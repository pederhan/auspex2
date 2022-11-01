from typing import Iterable

from harborapi.models import Artifact, Repository
from harborapi.models.scanner import HarborVulnerabilityReport, VulnerabilityItem
from pydantic import BaseModel


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport = HarborVulnerabilityReport()  # type: ignore # why complain?
    # NOTE: add Project?

    def has_cve(self, cve_id: str) -> bool:
        for vuln in self.report.vulnerabilities:
            if vuln.id == cve_id:
                return True
        return False

    def has_description(self, description: str, case_sensitive: bool = False) -> bool:
        for vuln in self.vulns_with_description(description, case_sensitive):
            return True
        return False

    def has_package(self, package: str, case_sensitive: bool = False) -> bool:
        for vuln in self.vulns_with_package(package, case_sensitive):
            return True
        return False

    def vulns_with_package(
        self, package: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.package is None:
                continue

            # Case insensitive comparison
            vuln_package = vuln.package
            if not case_sensitive:
                package = package.lower()
                vuln_package = vuln_package.lower()

            if vuln_package == package:
                yield vuln

    def vulns_with_description(
        self, description: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.description is None:
                continue

            # Case insensitive comparison
            vuln_description = vuln.description
            if not case_sensitive:
                description = description.lower()
                vuln_description = vuln_description.lower()

            if description in vuln_description:
                yield vuln
