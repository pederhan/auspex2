import asyncio
import os
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from harborapi import HarborAsyncClient
from loguru import logger
from redis import Redis

from .cache import get_cache, get_cached, set_cached
from .harbor.api import (
    ArtifactInfo,
    filter_artifacts_latest,
    get_artifact,
    get_artifact_by_digest,
    get_artifact_vulnerabilities,
    get_projects,
)
from .html import TEMPLATES, mount_static_dir
from .plots import PieChartStyle, piechart_severity
from .report import ArtifactReport
from .tables.tables import cve_statistics, image_info, top_vulns

# TODO: warn if these are not defined
client = HarborAsyncClient(
    url=os.getenv("HARBOR_URL", ""),
    credentials=os.getenv("HARBOR_CREDENTIALS", ""),
    logging=True,
)


app = FastAPI()
mount_static_dir(app)


@app.exception_handler(404)
async def not_found(request: Request, exc: Exception):
    return TEMPLATES.TemplateResponse(
        "error.html",
        {
            "request": request,
            "title": "Not Found",
            "status": 404,
            "description": f"{request.url.path} not found",
        },
    )


async def report_project(request: Request, project: str):
    artifacts = await get_cached(ArtifactInfo, project)
    if not artifacts:
        artifacts = await get_artifact_vulnerabilities(
            client,
            projects=[project],
            exc_ok=True,
        )
        await set_cached(ArtifactInfo, project, artifacts)

    artifacts = await filter_artifacts_latest(artifacts)
    return await report_page(request, artifacts)


async def report_artifact(
    request: Request,
    project: str,
    repo: str,
    tag: Optional[str] = None,
    digest: Optional[str] = None,
):
    artifact = await get_artifact_by_digest(client, project, repo, tag, digest)
    if not artifact:
        wtag = f" with tag {tag}" if tag else ""
        return HTMLResponse(f"No artifact in repo {repo}{wtag} found", status_code=404)
    return await report_page(request, [artifact])


async def report_page(request: Request, artifacts: List[ArtifactInfo]):
    if not artifacts:
        return TEMPLATES.TemplateResponse(
            "report.html",
            {
                "ttables": [],
                "pplots": [],
                "request": request,
            },
        )

    report = ArtifactReport(artifacts, remove_duplicates=False)

    directory = Path("_dev/plots")
    directory.mkdir(parents=True, exist_ok=True)

    styles = [PieChartStyle.DEFAULT, PieChartStyle.FIXABLE, PieChartStyle.UNFIXABLE]

    # for artifact in artifacts:
    plots = []  # type List[Plot]
    for style in styles:
        p = piechart_severity(
            report,
            directory=directory,
            style=style,
            as_html=True,
        )
        plots.append(p)

    stable = cve_statistics(report)
    itable = image_info(report)
    tvtable = top_vulns(report)
    tvtable_fix = top_vulns(report, fixable=True)

    # with open(public_dir / "report.html", "w") as f:
    #     f.write(html)
    return TEMPLATES.TemplateResponse(
        "report.html",
        {
            "ttables": [itable, stable, tvtable, tvtable_fix],
            "pplots": plots,
            "request": request,
        },
    )


@app.get("/projects")
async def projects_page(request: Request):
    import time

    start = time.time()
    projects = await get_projects(client)
    logger.info(f"Got {len(projects)} projects in {time.time() - start} seconds")
    return TEMPLATES.TemplateResponse(
        "projects.html", {"projects": projects, "request": request}
    )


@app.get("/projects/{project}", response_class=HTMLResponse)
async def get_project_report(request: Request, project: str):
    return await report_project(request, project=project)


@app.get("/projects/{project}/{repo}/{digest}", response_class=HTMLResponse)
async def get_artifact_report(
    request: Request,
    project: str,
    repo: str,
    digest: str,
    # cache: Cache = Depends(get_cache),
):
    return await report_artifact(request, project=project, repo=repo, digest=digest)


@app.get("/cache")
async def test_cache(request: Request, key: str = "foo", value: str = "bar"):
    cache = await get_cache()
    cached = await cache.get(key)
    if cached:
        logger.info("Fetched '{}' from cache for key '{}'", cached, key)
    else:
        await cache.set(key, value)
    return {"key": key, "value": value}


@app.get("/allproj")
async def all_projects_page(request: Request):
    import time

    start = time.time()
    projects = await get_artifact_vulnerabilities(
        client,
        exc_ok=True,
    )
    end = time.time()
    print(f"{len(projects)} artifacts in {end - start} seconds")
    return projects[0].dict()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        debug=True,
    )
