from typing import Optional, Union

from harborapi.models.scanner import Severity

from ...colors import COLOR_BAD, COLOR_GOOD, get_color_cvss
from ...cve import most_severe
from ...format import format_decimal
from ...harbor.api import ArtifactInfo
from ...html.cve import severity_to_colorclass
from ..report import ArtifactCVSS, ArtifactReport
from ..text import Badge, Color, Hyperlink, Text
from .models import Table


# TODO: move these functions
def _get_artifact_url(artifact: ArtifactInfo) -> str:
    """Returns the URL for an artifact."""
    return f"/projects/{artifact.repository.project_name}/{artifact.repository.base_name}/{artifact.artifact.digest}"


def artifact_hyperlink(artifact: ArtifactInfo) -> Hyperlink:
    """Returns a hyperlink for an artifact."""
    return Hyperlink(
        artifact.repository.name or "-",
        url=_get_artifact_url(artifact),
    )


def image_info(report: ArtifactReport, digest_limit: Optional[int] = 8) -> Table:
    """Generates the table data used to display the info for an image.

    Parameters
    ----------
    report : ArtifactReport
        The reports to display image statistics for.
    digest_limit : int
        Maximum displayed sha256 digest length, by default 8

    Returns
    -------
    Table
        The generated table.
    """
    columns = [
        "Image",
        "Created",
        "Tags",
        "Digest",
    ]

    rows = []  # type: list[list[Text]]
    for a in report.artifacts:
        digest = "-"

        # Digest
        if a.artifact.digest is not None:
            digest = a.artifact.digest
            if ":" in a.artifact.digest:
                digest = digest.split(":")[1]
            if digest_limit and len(digest) > digest_limit:
                digest = digest[:digest_limit]  # + "..."

        # Move to ImageInfo.get_tags()?

        # Tags
        if a.artifact.tags is not None:
            tags = ", ".join(t.name for t in a.artifact.tags if t.name is not None)
        else:
            tags = "-"

        # Created (push) time
        if a.artifact.push_time is not None:
            created = a.artifact.push_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            created = "-"

        # Repo name
        if a.repository.name is not None:
            repo_name = a.repository.name
        else:
            repo_name = "-"

        # image hyperlink
        # NOTE: digest might be None (probably will never be?)
        image_link = Hyperlink(
            repo_name,
            url=f"/projects/{a.repository.project_name}/{a.repository.base_name}/{a.artifact.digest}",
        )

        rows.append(
            [
                artifact_hyperlink(a),
                Text(created),
                Text(tags),
                Text(digest),
            ]
        )

    title = "Image"
    if report.is_aggregate:
        title += "s"

    return Table(
        title=title,
        header=columns,
        rows=rows,
        caption="",
        description="",
    )


def cve_statistics(report: ArtifactReport) -> Table:
    """Generates the table data used to display the statistics of images
    in a report.

    Parameters
    ----------
    report : ArtifactInfo
        The report to display the statistics for.

    Returns
    -------
    Table
        The generated table.
    """
    columns = [
        "Image",
        "Median CVSS",
        "Mean CVSS",
        "CVSS Stdev",
        "Max CVSS",
        "L",
        "M",
        "H",
        "C",
        "# Vulns",
    ]

    rows = []
    for c in report.cvss:
        # Columns:
        dist = c.artifact.report.distribution

        # Total number of vulnerabilities
        low = dist.get(Severity.low, 0)
        medium = dist.get(Severity.medium, 0)
        high = dist.get(Severity.high, 0)
        critical = dist.get(Severity.critical, 0)
        total = low + medium + high + critical

        row = [
            artifact_hyperlink(c.artifact),
            # Color(format_decimal(c.cvss.median), color=get_color_cvss(c.cvss.median)),
            # Color(format_decimal(c.cvss.mean), color=get_color_cvss(c.cvss.mean)),
            # Color(format_decimal(c.cvss.stdev), color=get_color_cvss(c.cvss.stdev)),
            # Color(format_decimal(c.cvss.max), color=get_color_cvss(c.cvss.max)),
            Text(format_decimal(c.cvss.median)),
            Text(format_decimal(c.cvss.mean)),
            Text(format_decimal(c.cvss.stdev)),
            Text(format_decimal(c.cvss.max)),
            Text(low),
            Text(medium),
            Text(high),
            Text(critical),
            Text(total),
        ]
        rows.append(row)

    return Table(
        title="Statistics",
        header=columns,
        rows=rows,
        caption="",
        description=(
            "The statistics is based on the scanned image(s) and denotes the Median, Mean and Standard deviation (Stdev) score of all vulnerabilities found. "
            "Additionally it showcases the single highest score of a vulnerability for this scan. 'L', 'M', 'H' and 'C' denote the severity categories, with the corresponding number of vulnerabilities for each category. "
            "'#Vulns' denotes the total number of vulnerabilities found. "
            "\n\nWhere: L = Low (0.1 - 3.9), M = Medium, (4.0 - 6.9), H = High (7.0 - 8.9), C = Critical (9.0 - 10.0)"
        ),
    )


def top_vulns(report: ArtifactReport, fixable: bool = False, maxrows: int = 5) -> Table:
    """Generates the data used to display the top vulnerabilities in a report.

    Parameters
    ----------
    report : ArtifactReport
        An artifact report to display the top vulnerabilities for.
    fixable : bool
        Whether or not to only display fixable vulnerabilities.
    maxrows : int
        Maximum number of rows to return.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the top vulnerabilities.
    """
    header = [
        "Image",
        "Package",
        "Version",
        "Description",  # Description
        "CVSS ID",  # ID
        "CVSS Score",  # 0-10
        "Severity",
        "Fixed In",
    ]

    rows = []

    # Get list of vulnerabilities per image
    for a in report.artifacts:
        most_severe = a.report.top_vulns(maxrows, fixable=fixable)
        for vuln in most_severe:
            # Image name (repo)
            image_name = a.repository.name or "-"

            package = vuln.package or "-"

            # Vuln description
            description = vuln.description or "-"

            # Vuln URL
            # url = vuln.url or "-"
            vuln_id = vuln.id or ""
            url = Hyperlink(
                vuln_id,
                url="https://nvd.nist.gov/vuln/detail/{}".format(vuln_id),
            )

            # Vuln score
            score = vuln.get_cvss_score(a.report.scanner)
            score_color = get_color_cvss(score)

            # Severity
            # severity = vuln.get_severity(a.report.scanner).name.title()
            severity = vuln.get_severity_highest(a.report.scanner)
            severity_str = severity.name.title()

            affected_version = vuln.version or ""
            upgrade_version = vuln.fix_version or ""

            row = [
                artifact_hyperlink(a),
                Text(package),  # Package
                Text(affected_version),
                Text(description),  # Description
                url,
                Color(format_decimal(score), color=score_color),  # TODO: format
                Badge(severity_str, bg_color=severity_to_colorclass(severity)),
                Color(upgrade_version, color=COLOR_GOOD),
            ]
            rows.append(row)

    fx = " Fixable " if fixable else " "
    # ag = " by Image" if is_aggregate else ""
    title = f"Most Critical{fx}Vulnerabilities"
    description = (
        "Lists the found vulnerabilities with highest CVSS scores. "
        "The CVSS ID is a hyperlink to official documentation for that vulnerability. "
        "'Upgradeable' denotes whether the found vulnerability has a known fix ie. a new version of a package or library. "
    )
    if fixable:
        description += "Only vulnerabilities that are fixable are listed."

    return Table(
        title=title,
        header=header,
        rows=rows,
        description=description,
    )
