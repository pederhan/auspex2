from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

HTML_DIR = Path(__file__).parent.resolve().absolute()
STATIC_DIR = HTML_DIR / "static"
TEMPLATES_DIR = HTML_DIR / "templates"


def mount_static_dir(app: FastAPI) -> None:
    """Mount static dir."""
    # Make sure we don't mount multiple times.
    mount_path = str(STATIC_DIR)

    if _route_is_added(app, mount_path):
        return

    app.mount(
        mount_path,  # arg MUST be str, not Path
        StaticFiles(directory=mount_path),
        name="static",
    )


def _route_is_added(app: FastAPI, route: str) -> bool:
    for r in app.routes:
        if r.path == route:
            return True
    return False


TEMPLATES = Jinja2Templates(directory=TEMPLATES_DIR)
