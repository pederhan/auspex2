import asyncio
import itertools
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

import backoff
from harborapi import HarborAsyncClient
from harborapi.exceptions import NotFound
from harborapi.models import Artifact, Project, Repository, UserResp
from httpx import TimeoutException
from loguru import logger

from .artifact import ArtifactInfo

T = TypeVar("T")


async def get_artifact(
    client: HarborAsyncClient,
    repo: str,
    tag: Optional[str] = None,
    digest: Optional[str] = None,
) -> Optional[ArtifactInfo]:
    artifacts = await get_artifacts(client)
    return await _filter_artifact(artifacts, repo, tag, digest)


async def get_artifact_by_digest(
    client: HarborAsyncClient,
    project: str,
    repository: str,
    tag: Optional[str] = None,
    digest: Optional[str] = None,
) -> Optional[ArtifactInfo]:
    reference = tag or digest
    if not reference:
        raise ValueError("Must specify either tag or digest")
    try:
        artifact = await client.get_artifact(
            project_name=project,
            repository_name=repository,
            reference=reference,
        )
    except NotFound:
        return None

    try:
        repo = await client.get_repository(
            project_id=project,  # type: ignore
            repository_name=repository,
        )
    except NotFound:
        return None

    def _no_report() -> None:
        delim = ":" if tag else "@"
        logger.error(
            f"No vulnerability report for {project}/{repository}{delim}{reference}"
        )
        return None

    try:
        report = await client.get_artifact_vulnerabilities(
            project_name=project, repository_name=repo.base_name, reference=reference
        )
    except NotFound:
        return _no_report()  # type: ignore
    if not report:
        return _no_report()  # type: ignore

    return ArtifactInfo(artifact=artifact, repository=repo, report=report)


async def _filter_artifact(
    artifacts: List[ArtifactInfo],
    repo: str,
    tag: Optional[str],
    digest: Optional[str],
) -> Optional[ArtifactInfo]:
    matches = [a for a in artifacts if a.repository.project_name == repo]
    if not matches:
        return None

    if digest:
        return next(a for a in matches if a.artifact.digest == digest)

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


async def filter_artifacts_latest(
    artifacts: List[ArtifactInfo],
    fallback: Optional[Callable[[ArtifactInfo, ArtifactInfo], ArtifactInfo]] = None,
) -> List[ArtifactInfo]:
    """Get the latest version of all artifacts from a list of artifacts.

    Parameters
    ----------
    artifacts : List[ArtifactInfo]
        The list of artifacts to filter.

    fallback : Optional[Callable[[ArtifactInfo, ArtifactInfo], ArtifactInfo]]
        Optional comparison function to use if one of the artifacts has no `push_time`.
        The function should take two ArtifactInfo objects `(latest_artifact, maybe_latest)`
        and return the one deemed to be the latest.
        If not specified, artifacts without `push_time` are ignored.

        Example:
        ```py
            def compare_artifacts(latest_artifact, maybe_latest):
                # we know they have no push_time, so we compare digests
                if latest_artifact.artifact.digest and maybe_latest.artifact.digest:
                    return latest_artifact if latest_artifact.artifact.digest > maybe_latest.artifact.digest else maybe_latest
                return latest_artifact # fallback if no digest
        ```

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, with the latest artifact for each repository.
    """

    art = {}  # type: Dict[str, ArtifactInfo]
    for a in artifacts:
        # should never happen, but spec says this can be None
        if not a.repository.name:
            continue

        newest = art.get(a.repository.name)

        # if no newest, set first as newest
        if not newest:
            art[a.repository.name] = a
            continue

        # if one of the artifacts does not have a push time, use fallback
        # comparison function or skip it
        #
        # FIXME: problematic if art[a.repository.name] has no push time
        if not a.artifact.push_time or not newest.artifact.push_time:
            # use fallback comparison function if provided, otherwise skip
            if fallback is not None:
                art[a.repository.name] = fallback(newest, a)
            continue

        # compare push times, pick most recent
        if a.artifact.push_time > newest.artifact.push_time:
            art[a.repository.name] = a
            continue

    return list(art.values())


async def get_artifacts(
    client: HarborAsyncClient,
    repos: Optional[List[Repository]] = None,
    tags: Optional[List[str]] = None,
    exc_ok: bool = True,
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
        # repos = await client.get_repositories()
        repos = await get_repositories(
            client, projects=[""]
        )  # bit of a hack for now to retrieve all repos
    # Fetch artifacts from each repository concurrently
    coros = [_get_repo_artifacts(client, repo, tags=tags, **kwargs) for repo in repos]
    a = await asyncio.gather(*coros, return_exceptions=True)
    return handle_gather(a, exc_ok=exc_ok)
    # return list(itertools.chain.from_iterable(a))


@backoff.on_exception(
    backoff.expo, (TimeoutException, asyncio.TimeoutError), max_tries=5
)
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
        with_scan_overview=True,
        **kwargs,
    )
    return [ArtifactInfo(artifact=artifact, repository=repo) for artifact in artifacts]


async def get_projects(client: HarborAsyncClient) -> List[Project]:
    """Get all projects."""
    projects = await client.get_projects()
    return projects


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
    return handle_gather(rtn, exc_ok=exc_ok)


async def _get_project_repos(
    client: HarborAsyncClient, project: Optional[str]
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
    repos = await client.get_repositories(project_name=project)
    return repos


async def get_artifact_vulnerabilities(
    client: HarborAsyncClient,
    tags: Optional[List[str]] = None,
    projects: Optional[List[str]] = None,
    exc_ok: bool = False,
    batch_size: Optional[int] = 5,
    sleep_duration: Optional[float] = 1.0,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifact vulnerability reports in all projects, optionally
    filtering by tag names and project names.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them
    into a single list of ArtifactInfo objects afterwards.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    projects : Optional[List[str]]
        The project(s) to fetch artifacts from.
        If not specified, all projects will be used.
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed artifact is skipped, and the exception
        is logged. If False, the exception is raised.
    batch_size : Optional[int]
        The number of requests to make in each batch.
        If None, all requests will be made in a single batch.
        WARNING: this will likely cause a DoS on the Harbor server.
    sleep_duration : Optional[float]
        The duration to sleep between batches of requests.
        If None, the next batch is sent immediately.
    kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, where the .report field is populated with the
        vulnerability report.
    """
    # Get all projects if not specified
    if not projects:
        p = await get_projects(client)
        projects = [project.name for project in p if project.name]

    repos = await get_repositories(client, projects, exc_ok=exc_ok)

    # We first retrieve all artifacts before we get the vulnerability reports
    # since the reports themselves lack information about the artifact.
    artifacts = await get_artifacts(client, repos=repos, tags=tags, **kwargs)

    # Filter out artifacts without a scan overview (no vulnerability report)
    artifacts = [a for a in artifacts if a.artifact.scan_overview is not None]

    # We must fetch each report individually, since the API doesn't support
    # getting all reports in one call.
    # This is done concurrently to speed up the process.
    coros = [_get_artifact_report(client, artifact) for artifact in artifacts]
    artifacts = await run_coros(
        coros, batch_size=batch_size, sleep_duration=sleep_duration
    )
    return handle_gather(artifacts, exc_ok=exc_ok)


async def run_coros(
    coros: List[Coroutine[Any, Any, Any]],
    batch_size: Optional[int],
    sleep_duration: Optional[float],
) -> List[Any]:
    """Splits up a list of coroutines into smaller batches and runs each batch sequentially."""
    results = []

    # Divide coros into batches
    if batch_size is not None:
        coros_to_run = [
            coros[i : i + batch_size] for i in range(0, len(coros), batch_size)
        ]
    else:
        coros_to_run = [coros]

    for coros in coros_to_run:
        res = await asyncio.gather(*coros, return_exceptions=True)
        results.extend(res)
        if sleep_duration is not None:
            await asyncio.sleep(sleep_duration)  # sleep between batches

    return results


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


# TODO: maybe move this to a separate module?
#       but putting it into utils leads to circular imports
#       Consider moving ArtifactInfo to a separate module to resolve this
def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]], exc_ok: bool
) -> List[T]:
    """Handles the returned values of an `asyncio.gather()` call, handling
    any exceptions and returning a list of the results with exceptions removed.
    Flattens lists of results. TODO: toggle this?

    Parameters
    ----------
    results : List[Union[T, List[T], Exception]]
        The results of an `asyncio.gather)` call.
    exc_ok : bool
        Whether to log and skip exceptions, or raise them.
        If True, exceptions are logged and skipped.
        If False, exceptions are raised.

    Returns
    -------
    List[T]
        The list of results with exceptions removed.
    """
    ok = []  # type: List[T]
    for res_or_exc in results:
        if isinstance(res_or_exc, Exception):
            if exc_ok:
                logger.error(res_or_exc)
            else:
                raise res_or_exc
        else:
            if isinstance(res_or_exc, Sequence):
                ok.extend(res_or_exc)
            else:
                ok.append(res_or_exc)
    return ok


async def get_artifact_owner(client: HarborAsyncClient, artifact: Artifact) -> UserResp:
    project_id = artifact.project_id
    if project_id is None:
        raise ValueError("Artifact has no project_id")
    project = await client.get_project(project_id)
    if project.owner_id is None:
        raise ValueError("Project has no owner_id")
    return await client.get_user(project.owner_id)
