import itertools
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List

from harborapi.models import Artifact
from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    Severity,
    VulnerabilityItem,
)

from . import npmath
from .api import ArtifactInfo
from .cve import CVSS


@dataclass
class Vulnerability:
    vulnerability: VulnerabilityItem
    artifact: ArtifactInfo


@dataclass
class ArtifactCVSS:
    cvss: CVSS
    artifact: ArtifactInfo


def remove_duplicate_artifacts(artifacts: List[ArtifactInfo]) -> Iterable[ArtifactInfo]:
    """Remove duplicate artifacts from the list of artifacts, based on SHA256 digest."""
    seen = set()
    for a in artifacts:
        if a.artifact.digest not in seen:
            seen.add(a.artifact.digest)
            yield a


# @dataclass
# TODO: rename to something more appropriate
class ArtifactReport:
    artifacts: List[ArtifactInfo]

    def __init__(
        self, artifacts: List[ArtifactInfo], remove_duplicates: bool = True
    ) -> None:
        if remove_duplicates:
            artifacts = list(remove_duplicate_artifacts(artifacts))
        self.artifacts = artifacts
        if len(artifacts) == 0:
            raise ValueError("List of artifacts must not be empty")

    @property
    def is_aggregate(self) -> bool:
        return len(self.artifacts) > 1

    @property
    def cvss(self) -> List[ArtifactCVSS]:
        cvss = []  # type: List[ArtifactCVSS]
        for a in self.artifacts:
            scores = a.report.cvss_scores
            c = CVSS(
                mean=npmath.median(scores),
                median=npmath.mean(scores),
                stdev=npmath.stdev(scores),
                min=npmath.min(scores),
                max=npmath.max(scores),
            )
            cvss.append(ArtifactCVSS(c, a))
        return cvss

    # NOTE: we could implement these methods with some dirty metaprogramming
    #       but let's keep it simple for now

    @property
    def fixable(self) -> Iterable[Vulnerability]:
        """Get all fixable vulnerabilities."""
        for a in self.artifacts:
            for v in a.report.fixable:
                yield Vulnerability(v, a)

    @property
    def unfixable(self) -> Iterable[Vulnerability]:
        """Get all fixable vulnerabilities."""
        for a in self.artifacts:
            for v in a.report.unfixable:
                yield Vulnerability(v, a)

    @property
    def critical(self) -> Iterable[Vulnerability]:
        yield from self.vulnerabilities_by_severity(Severity.critical)

    @property
    def high(self) -> Iterable[Vulnerability]:
        yield from self.vulnerabilities_by_severity(Severity.high)

    @property
    def medium(self) -> Iterable[Vulnerability]:
        yield from self.vulnerabilities_by_severity(Severity.medium)

    @property
    def low(self) -> Iterable[Vulnerability]:
        yield from self.vulnerabilities_by_severity(Severity.low)

    @property
    def distribution(self) -> Counter[Severity]:
        """Get the distribution of severities from the vulnerabilities of all artifacts."""
        dist = Counter()  # type: Counter[Severity]
        for artifact in self.artifacts:
            a_dist = artifact.report.distribution
            dist.update(a_dist)
        return dist

    def vulnerabilities_by_severity(
        self, severity: Severity
    ) -> Iterable[Vulnerability]:
        for a in self.artifacts:
            for v in a.report.vulnerabilities_by_severity(severity):
                yield Vulnerability(v, a)


# TODO: add test to ensure parity with HarborVulnerabilityReport
