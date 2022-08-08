from typing import Union

from harborapi.models.scanner import Severity

from ..api import ArtifactInfo
from ..cve import most_severe
from ..report import ArtifactCVSS, ArtifactReporter
from .models import Table


def statistics_table(report: ArtifactReporter) -> Table:
    """Generates the table data used to display the statistics of a report.

    Parameters
    ----------
    artifact : ArtifactInfo
        The artifact to display the statistics for.

    Returns
    -------
    `Table`
        The generated table data.
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
    # Always add Image as 1st column if we have an aggregated report
    # if isinstance(report, AggregateReport):
    #     columns.insert(0, "Image")
    # report = report.report
    # dist = report.distribution

    # sev = most_severe(artifact.report.distribution)

    # # FIXME: we don't seem to use this value?
    # highest_severity = sev.name.title()

    rows = []
    for c in report.cvss:
        row = _get_report_statistics_row(c)
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


def _get_report_statistics_row(cvss: ArtifactCVSS) -> list[Union[str, int, float]]:
    # Alias for shorter variable names
    report = cvss.artifact.report

    # Columns:
    name = cvss.artifact.repository.name
    dist = report.distribution
    # Total number of vulnerabilities
    low = dist.get(Severity.low, 0)
    medium = dist.get(Severity.medium, 0)
    high = dist.get(Severity.high, 0)
    critical = dist.get(Severity.critical, 0)
    total = low + medium + high + critical

    row = [
        # format_decimal(report.cvss.median),
        # format_decimal(report.cvss.mean),
        # format_decimal(report.cvss.stdev),
        # format_decimal(report.cvss.max),
        name,
        cvss.cvss.median,
        cvss.cvss.mean,
        cvss.cvss.stdev,
        cvss.cvss.max,
        low,
        medium,
        high,
        critical,
        total,
    ]
    return row


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
        "Vulnerability",  # Name
        "CVSS ID",  # ID
        "CVSS Score",  # 0-10
        "Severity",
        "Upgradable",  # Yes/No
    ]

    rows = []
    reports = []

    # Get list of vulnerabilities per image
    for a in report.artifacts:
        most_severe = a.report.top_vulns(maxrows, fixable=fixable)
        for vuln in most_severe:
            # Vuln name (ID)
            name = vuln.description or "-"
            # Vuln URL
            # url = vuln.url or "-"
            vuln_id = vuln.id or ""
            url = Hyperlink(
                "https://nvd.nist.gov/vuln/detail/{}".format(vuln_id), vuln_id
            )

            # Vuln score
            score = vuln.get_cvss_score(a.report.scanner)

            # Severity
            severity = vuln.get_severity(a.report.scanner).name.title()

            # Upgradable
            upgradable = "Yes" if vuln.fixable else "No"

            row = [
                a.repository.name,
                name,
                url,
                format_decimal(score),  # TODO: format
                severity,
                upgradable,
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

    return Table(title, header, rows, description=description)
