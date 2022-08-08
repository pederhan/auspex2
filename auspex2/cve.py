from typing import Iterable

from harborapi.models.scanner import Severity
from pydantic import BaseModel


class CVSS(BaseModel):
    """Key CVSS metrics for a scanned container."""

    mean: float
    median: float
    stdev: float
    min: float
    max: float


def most_severe(severities: Iterable[Severity]) -> Severity:
    """Returns the highest severity in a list of severities."""
    prio = [  # low -> high
        Severity.unknown,
        Severity.negligible,
        Severity.low,
        Severity.medium,
        Severity.high,
        Severity.critical,
    ]
    # TODO: add test to ensure we test every possible Severity value
    highest_idx = 0
    for s in severities:
        i = prio.index(s)
        if i > highest_idx:
            highest_idx = i
    return prio[highest_idx]
