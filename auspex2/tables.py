from harborapi.models.scanner import HarborVulnerabilityReport
from .models import Table
from .api import ArtifactInfo
from .cve import highest_severity


def statistics_table(artifact: ArtifactInfo) -> Table:
    """Generates the table data used to display the statistics of a report.

    Parameters
    ----------
    artifact : ArtifactInfo
        The artifact to display the statistics for.

    Returns
    -------
    `TableData`
        Contents and metadat for the constructed table.
    """
    columns = [
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

    dist = report.get_distribution_by_severity()
    prio = ["critical", "high", "medium", "low"]
    # This is flimsy and should be refactored and moved to
    # a separate function.
    # We rely on the order defined in the list `prio` above.
    # TODO: use CVESeverity to define the order
    highest_severity = "low"  # default to low
    for p in prio:
        if dist.get(p):
            highest_severity = p
            break

    sev = highest_severity(artifact.report.distribution)

    # FIXME: we don't seem to use this value?
    highest_severity = highest_severity.title()

    rows = []
    if isinstance(report, AggregateReport):
        for r in report.reports:
            row = _get_report_statistics_row(r)
            row.insert(0, r.image.image_name)
            rows.append(row)
    else:
        rows.append(_get_report_statistics_row(report))

    return TableData(
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


def _get_report_statistics_row(report: HarborVulnerabilityReport) -> list[Any]:
    dist = report.get_distribution_by_severity()
    row = [
        format_decimal(report.cvss.median),
        format_decimal(report.cvss.mean),
        format_decimal(report.cvss.stdev),
        format_decimal(report.cvss.max),
        dist["low"],
        dist["medium"],
        dist["high"],
        dist["critical"],
        dist["low"] + dist["medium"] + dist["high"] + dist["critical"],
    ]
    return row
