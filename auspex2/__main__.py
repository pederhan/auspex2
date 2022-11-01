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

from .harbor.api import (
    ArtifactInfo,
    filter_artifacts_latest,
    get_artifact,
    get_artifact_by_digest,
    get_artifact_vulnerabilities,
    get_projects,
)
from .html import TEMPLATES, mount_static_dir
from .report import ArtifactReport
from .report.layout import EmptyPage, ReportLayout
from .report.plots import PieChartStyle, piechart_severity
from .report.section import MultiSection
from .report.tables.tables import cve_statistics, image_info, top_vulns

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
    artifacts = await get_artifact_vulnerabilities(
        client,
        projects=[project],
        exc_ok=True,
    )
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
        # TODO: raise HTTPException?
        return HTMLResponse(f"No artifact in repo {repo}{wtag} found", status_code=404)
    return await report_page(request, [artifact])


async def report_page(request: Request, artifacts: List[ArtifactInfo]):
    if not artifacts:
        return TEMPLATES.TemplateResponse(
            "report.html",
            {
                "layout": EmptyPage(),
                "request": request,
            },
        )

    report = ArtifactReport(artifacts, remove_duplicates=False)

    directory = Path("_dev/plots")
    directory.mkdir(parents=True, exist_ok=True)

    styles = [PieChartStyle.DEFAULT, PieChartStyle.FIXABLE, PieChartStyle.UNFIXABLE]

    layout = ReportLayout(
        stats_t=cve_statistics(report),
        info_t=image_info(report),
        top_vulns_t=top_vulns(report),
        top_vulns_t_fix=top_vulns(report, fixable=True),
        vuln_p=[
            piechart_severity(
                report,
                directory=directory,
                style=style,
                as_html=True,
            )
            for style in styles
        ],
    )
    return TEMPLATES.TemplateResponse(
        "report.html",
        {
            "layout": layout,
            "request": request,
        },
    )


@app.get("/projects")
async def projects_page(request: Request):
    import time

    start = time.time()
    projects = await get_projects(client)
    logger.debug(f"Got {len(projects)} projects in {time.time() - start} seconds")
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
):
    return await report_artifact(request, project=project, repo=repo, digest=digest)


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
