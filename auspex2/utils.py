from collections import Counter
from typing import Iterable, List, cast

from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    Severity,
    VulnerabilityItem,
)

from .colors import get_color_severity
from .cve import sort_distribution
from .npmath import mean, median, stdev
from .plots import PlotData
from .report import Vulnerability


def get_distribution(vulnerabilities: Iterable[Vulnerability]) -> Counter[Severity]:
    """Get a counter showing the distribution of severities from a list of vulnerabilities.

    Parameters
    ----------
    vulnerabilities : List[VulnerabilityItem]
        The vulnerabilities to count.

    Returns
    -------
    Counter[Severity] :
        The distribution of severities.
    """
    dist = Counter()  # type: Counter[Severity]
    for v in vulnerabilities:
        if v.vulnerability.severity:
            dist[v.vulnerability.severity] += 1
    return dist


def plotdata_from_dist(distribution: Counter[Severity]) -> PlotData[Severity, int]:
    """Create a PlotData object with severities as labels and counts as values
     from a Counter of severities.

    Example:
    >>> plotdata_from_dist(Counter({Severity.critical: 1, Severity.high: 2}))
    PlotData(
        labels=[Severity.critical, Severity.high],
        values=[1, 2],
        colors=["#d7191c", "#fdae61"]
    )


    Parameters
    ----------
    distribution : Counter[Severity]
        The distribution of severities to create plot data from.

    Returns
    -------
    PlotData[Severity, int]
        Plot data where `.labels` are the severities and `.values` are the counts.
        `.colors` are set to the severity colors, as defined by the `colors` module.
    """
    p = PlotData()
    # "dumb" iteration to ensure order is correct (not necessary?)
    distrib_sorted = sort_distribution(distribution)
    for severity, count in distrib_sorted:
        p.labels.append(severity)
        p.values.append(count)
    p.colors = [get_color_severity(severity) for severity in p.labels]
    return p
