from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from jinja2.loaders import FileSystemLoader

loader = FileSystemLoader(str(Path(__file__).parent))

env = Environment(
    # loader=PackageLoader("auspex2"),
    loader=loader,
    autoescape=select_autoescape(),
)


tables_template = env.get_template("tables.html")
