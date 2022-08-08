from collections import Counter
from typing import List

from harborapi.models.scanner import Severity, VulnerabilityItem

from .plots import PlotData


def get_distribution(vulnerabilities: List[VulnerabilityItem]) -> Counter[Severity]:
    """Get a counter showing the distribution of severities from a list of vulnerabilities.

    Args:
        vulnerabilities (List[VulnerabilityItem]): The vulnerabilities to count.

    Returns:
        Counter[Severity]: The distribution of severities.
    """
    dist = Counter()  # type: Counter[Severity]
    for vulnerability in vulnerabilities:
        if vulnerability.severity:
            dist[vulnerability.severity] += 1
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
