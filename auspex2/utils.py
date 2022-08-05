from collections import Counter
from typing import List
from harborapi.models.scanner import VulnerabilityItem, Severity

from .models import PlotData


def get_distribution(vulnerabilities: List[VulnerabilityItem]) -> Counter[Severity]:
    dist = Counter()  # type: Counter[Severity]
    for vulnerability in vulnerabilities:
        if vulnerability.severity:
            dist[vulnerability.severity] += 1
    return dist


def plotdata_from_dist(distribution: Counter[Severity]) -> PlotData[Severity, int]:
    p = PlotData()
    # "dumb" iteration to ensure order is correct (not necessary?)
    for severity, count in distribution.items():
        p.labels.append(severity)
        p.values.append(count)
    return p
