import asyncio
import itertools
from typing import Any, Coroutine, Dict, List, TYPE_CHECKING, Optional, Tuple


from harborapi.models import Artifact, Repository, Project
from harborapi.models.scanner import HarborVulnerabilityReport
from harborapi import HarborAsyncClient
from loguru import logger
from pydantic import BaseModel


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: Optional[HarborVulnerabilityReport] = None
    # NOTE: add Project?


async def get_artifacts(
    client: HarborAsyncClient,
    repos: Optional[List[Repository]] = None,
    tags: Optional[List[str]] = None,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifacts in all repositories.
    Optionally specify a list of repositories to fetch from.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    repos : Optional[List[Repository]]
        The list of repositories to fetch artifacts from.
        If not specified, all repositories will be used.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.
    """
    if not repos:
        repos = await client.get_repositories()
    coros = [_get_repo_artifacts(client, repo, tags=tags, **kwargs) for repo in repos]
    a = await asyncio.gather(*coros)
    return list(itertools.chain.from_iterable(a))


async def _get_repo_artifacts(
    client: HarborAsyncClient, repo: Repository, tags: Optional[List[str]], **kwargs
) -> List[ArtifactInfo]:
    s = repo.split_name()
    if not s:
        return []  # TODO: add warning or raise error
    project_name, repo_name = s
    artifacts = await client.get_artifacts(
        project_name,
        repo_name,
        query=(f"tags={','.join(tags)}" if tags else None),
        **kwargs,
    )
    return [ArtifactInfo(artifact=artifact, repository=repo) for artifact in artifacts]


async def get_artifact_vulnerabilities(
    client: HarborAsyncClient,
    tags: Optional[List[str]] = None,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifact vulnerability reports in all projects.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.
    """
    repos = await client.get_repositories()
    # We first retrieve all artifacts before we get the vulnerability reports
    # since the reports themselves lack information about the artifact.
    artifacts = await get_artifacts(client, repos=repos, tags=tags, **kwargs)

    # We must iterate through all artifacts to get vulnerability reports for each one
    coros = [_get_artifact_report(client, artifact) for artifact in artifacts]
    artifacts = await asyncio.gather(*coros)
    return artifacts  # type: ignore # why does pylance report this as tuple[()]?


async def _get_artifact_report(
    client: HarborAsyncClient, artifact: ArtifactInfo
) -> ArtifactInfo:
    """Get the vulnerability report for an artifact.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    artifact : Artifact
        The artifact to get the report for.
    project_name : str
        The name of the project the artifact belongs to.
    repo_name : str
        The name of the repository the artifact belongs to.
    """
    tag = artifact.artifact.tags[0].name if artifact.artifact.tags else None
    if not tag:
        tag = "latest"

    s = artifact.repository.split_name()
    if not s:
        # Should never happen at this point, since we already filtered out
        # the invalid names earlier
        return artifact

    project_name, repo_name = s
    report = await client.get_artifact_vulnerabilities(
        project_name,
        repo_name,
        tag,
    )
    if not report:
        logger.debug(
            "No vulnerabilities found for artifact '{}'".format(
                f"{project_name}/{repo_name}:{tag}"
            )
        )
    artifact.report = report
    return artifact