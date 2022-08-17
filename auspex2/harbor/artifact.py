from harborapi.models import Artifact, Repository
from harborapi.models.scanner import HarborVulnerabilityReport
from pydantic import BaseModel


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport = HarborVulnerabilityReport()  # type: ignore # why complain?
    # NOTE: add Project?
