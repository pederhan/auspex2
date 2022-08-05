from typing import List
from harborapi.models.scanner import Severity


def highest_severity(severities: List[Severity]) -> Severity:
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
