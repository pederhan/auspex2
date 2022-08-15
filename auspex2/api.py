import asyncio
import itertools
from typing import TYPE_CHECKING, Any, Coroutine, Dict, List, Optional, Tuple

from harborapi import HarborAsyncClient
from harborapi.models import Artifact, Project, Repository
from harborapi.models.scanner import HarborVulnerabilityReport
from loguru import logger
from pydantic import BaseModel


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport = HarborVulnerabilityReport()  # type: ignore # why complain?
    # NOTE: add Project?


async def get_image(
    client: HarborAsyncClient, repo: str, tag: Optional[str] = None
) -> Optional[ArtifactInfo]:
    artifacts = await get_artifacts(client)
    return await _filter_artifact(artifacts, repo, tag)


async def _filter_artifact(
    artifacts: List[ArtifactInfo], repo: str, tag: Optional[str]
) -> Optional[ArtifactInfo]:
    matches = [a for a in artifacts if a.repository.project_name == repo]
    if not matches:
        return None

    if not tag:
        has_date = [m for m in matches if m.artifact.push_time]
        return sorted(has_date, key=lambda m: m.artifact.push_time)[-1]  # type: ignore # guaranteed to have push_time

    for m in matches:
        if not m.artifact.tags:
            continue
        for t in m.artifact.tags:
            if t and t.name == tag:
                return m
    return None


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

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, without the .report field populated.
    """
    if not repos:
        repos = await client.get_repositories()
    # Fetch artifacts from each repository concurrently
    coros = [_get_repo_artifacts(client, repo, tags=tags, **kwargs) for repo in repos]
    a = await asyncio.gather(*coros)
    return list(itertools.chain.from_iterable(a))


async def _get_repo_artifacts(
    client: HarborAsyncClient, repo: Repository, tags: Optional[List[str]], **kwargs
) -> List[ArtifactInfo]:
    """Fetch all artifacts in a repository.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    repo : Repository
        The repository to get the artifacts from.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, combining each artifact with its
        repository.
    """
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


async def get_repositories(
    client: HarborAsyncClient, projects: List[str], exc_ok: bool = False
) -> List[Repository]:
    """Fetch all repositories in a list of projects.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    projects : List[str]
        The list of projects to fetch repositories from.
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed repository is skipped, and the exception
        is logged. If False, the exception is raised.

    Returns
    -------
    List[Repository]
        A list of Repository objects.
    """
    coros = [_get_project_repos(client, project) for project in projects]
    rtn = await asyncio.gather(*coros, return_exceptions=True)

    repos = []
    for repo_or_exc in rtn:
        if isinstance(repo_or_exc, Exception):
            if exc_ok:
                logger.error(repo_or_exc)
            else:
                raise repo_or_exc
        else:
            repos.extend(repo_or_exc)
    return repos


async def _get_project_repos(
    client: HarborAsyncClient, project: str
) -> List[Repository]:
    """Fetch all repositories in a project.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    project : str
        The project to fetch repositories from.

    Returns
    -------
    List[Repository]
        A list of Repository objects.
    """
    return await client.get_repositories(project_name=project)


async def get_artifact_vulnerabilities(
    client: HarborAsyncClient,
    tags: Optional[List[str]] = None,
    projects: Optional[List[str]] = None,
    exc_ok: bool = False,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifact vulnerability reports in all projects.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them
    into a single list of ArtifactInfo objects afterwards.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, where the .report field is populated with the
        vulnerability report.
    """
    projects = projects or []
    if projects:
        repos = await get_repositories(client, projects, exc_ok=exc_ok)
    else:
        repos = []
    # repos = []

    # # TODO: run concurrently

    # for project in projects:
    #     r = await client.get_repositories(project_name=project)
    #     repos.extend(r)

    # We first retrieve all artifacts before we get the vulnerability reports
    # since the reports themselves lack information about the artifact.
    artifacts = await get_artifacts(client, repos=repos, tags=tags, **kwargs)

    # We must fetch each report individually, since the API doesn't support
    # getting all reports in one call.
    # This is done concurrently to speed up the process.
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
    artifact : ArtifactInfo
        The artifact to get the vulnerability report for.

    Returns
    -------
    ArtifactInfo
        The `ArtifactInfo` object with the vulnerability report attached.
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
    if report is None:
        logger.debug(
            "No vulnerabilities found for artifact '{}'".format(
                f"{project_name}/{repo_name}:{tag}"
            )
        )
    else:
        artifact.report = report
    return artifact
