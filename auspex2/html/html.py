from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from jinja2.loaders import FileSystemLoader

loader = FileSystemLoader(Path(__file__).parent / "templates")

env = Environment(
    # loader=PackageLoader("auspex2"),
    loader=loader,
    autoescape=select_autoescape(),
)


tables_template = env.get_template("report.html")
