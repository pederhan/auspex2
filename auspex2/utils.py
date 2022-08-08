from collections import Counter
from typing import Iterable, List, cast

from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    Severity,
    VulnerabilityItem,
)

from .npmath import mean, median, stdev
from .plots import PlotData
from .report import Vulnerability


def get_distribution(vulnerabilities: Iterable[Vulnerability]) -> Counter[Severity]:
    """Get a counter showing the distribution of severities from a list of vulnerabilities.

    Args:
        vulnerabilities (List[VulnerabilityItem]): The vulnerabilities to count.

    Returns:
        Counter[Severity]: The distribution of severities.
    """
    dist = Counter()  # type: Counter[Severity]
    for v in vulnerabilities:
        if v.vulnerability.severity:
            dist[v.vulnerability.severity] += 1
    return dist


def plotdata_from_dist(distribution: Counter[Severity]) -> PlotData[Severity, int]:
    """Create a PlotData object with severities as labels and counts as values
     from a Counter of severities.

    Args:
        distribution (Counter[Severity]): The distribution of severity values.

    Returns:
        PlotData[Severity, int]: The constructed PlotData object.
    """
    p = PlotData()
    # "dumb" iteration to ensure order is correct (not necessary?)
    for severity, count in distribution.items():
        p.labels.append(severity)
        p.values.append(count)
    return p
