from math import pi
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import numpy as np  # noqa?
import pandas as pd
from bokeh.embed import components
from bokeh.palettes import RdYlGn
from bokeh.plotting import figure, output_file, save, show
from bokeh.plotting.figure import Figure
from bokeh.transform import cumsum
from harborapi.models.scanner import Severity
from sanitize_filename import sanitize

from ..api import ArtifactInfo
from ..report import ArtifactReport
from ..text import Text
from ..utils import get_distribution, plotdata_from_dist
from .models import PieChartStyle, Plot, PlotType


def piechart_severity(
    report: ArtifactReport,
    # prefix: Optional[str] = "severity",
    directory: Optional[Union[str, Path]] = None,
    style: Union[PieChartStyle, str] = PieChartStyle.DEFAULT,
    as_html: bool = False,
    **kwargs: Any,
) -> Plot:
    """Generates a pie chart of the severity distribution of vulnerabilities.

    Parameters
    ----------
    artifact : ArtifactReport
        Artifact to generate the pie chart for.
    prefix : Optional[str]
        Prefix for the filename of the figure, by default `"severity"`.
    directory : Optional[Union[str, Path]], optional
        Directory to save the figure in, by default None
    style : Union[PieChartStyle, str]
        Which vulnerabilities to include in the pie chart.
        By default, all vulnerabilities are included.
        If `PieChartStyle.FIXABLE` or "fixable", only vulnerabilities that can be fixed are included.
        If `PieChartStyle.UNFIXABLE` or "unfixable", only vulnerabilities that cannot be fixed are included.
    **kwargs : Any
        Additional keyword arguments to pass to `save_fig`.

    Returns
    -------
    Plot
        Plot object with metadata for the generated figure.
    """
    style = PieChartStyle.get_style(style)

    if style != PieChartStyle.DEFAULT:
        extra = f"{style.value.title()} "
    else:
        extra = ""

    title = f"{extra}Vulnerabilities"
    plot = Plot(
        title=title,
        description="No vulnerabilities found.",
        caption=title,
        path=None,
        plot_type=PlotType.PIE,
    )

    size = 0.3

    if style == PieChartStyle.FIXABLE:
        distribution = get_distribution(report.fixable)
    elif style == PieChartStyle.UNFIXABLE:
        distribution = get_distribution(report.unfixable)
    else:
        distribution = report.distribution

    plotdata = plotdata_from_dist(distribution)
    if all(v == 0 for v in plotdata.values):
        return plot

    data = (
        pd.Series(plotdata.as_dict())
        .reset_index(name="value")
        .rename(columns={"index": "country"})
    )

    data["country"] = data["country"].map(lambda x: Severity(x).name)
    data["angle"] = data["value"] / data["value"].sum() * 2 * pi
    data["color"] = plotdata.colors

    p = figure(
        height=350,
        title="Pie Chart",
        toolbar_location=None,
        tools="hover",
        tooltips="@country: @value",
        x_range=(-0.5, 1.0),
    )

    p.wedge(
        x=0,
        y=1,
        radius=0.4,
        start_angle=cumsum("angle", include_zero=True),
        end_angle=cumsum("angle"),
        line_color="white",
        fill_color="color",
        legend_field="country",
        source=data,
    )

    p.axis.axis_label = None
    p.axis.visible = False
    p.grid.grid_line_color = None

    if report.is_aggregate:
        name = "All Repositories"  # FIXME: more specific than "All Repositories"
        artifact = None
        prefix = "agg"
    else:
        name = report.artifacts[0].repository.name
        artifact = report.artifacts[0]
        prefix = None

    if as_html:
        plot.script, plot.div = save_fig_components(p)
    else:
        plot.path = save_fig(p, artifact, directory, prefix, **kwargs)

    plot.description = (
        f"The pie chart shows the distribution of {extra}vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    # plt.show(block=True)
    return plot


def save_fig_components(fig: Figure) -> Tuple[str, str]:
    return components(fig)


def save_fig(
    fig: Figure,
    artifact: Optional[ArtifactInfo],
    directory: Optional[Union[str, Path]] = None,
    prefix: Optional[str] = None,
    suffix: Optional[str] = None,
) -> Path:
    fpath = get_figure_filepath(
        artifact=artifact, directory=directory, prefix=prefix, suffix=".html"
    )
    output_file(filename=fpath)
    save(fig)
    return fpath


def get_figure_filepath(
    artifact: Optional[ArtifactInfo] = None,
    directory: Optional[Union[str, Path]] = None,
    prefix: Optional[str] = None,
    suffix: Optional[str] = None,
) -> Path:
    """Generate a file path for a new figure.

    Parameters
    ----------
    artifact : ArtifactInfo
        The artifact used to generate the figure.
    directory : Optional[Union[str, Path]]
        The directory to save the figure to, by default None
        If omitted, uses current working directory.
    prefix : Optional[str]
        The prefix for the of the figure's filename.
    suffix : Optional[str]
        File suffix, by default None

    Returns
    -------
    Path
        The generated path.
    """
    if not directory:
        directory = Path(".")
    elif not isinstance(directory, Path):
        directory = Path(directory)

    fname = f"{prefix}_" or ""
    if artifact:
        if artifact.repository.name:
            fname += f"{artifact.repository.name}"
        if artifact.artifact.digest:
            digest = artifact.artifact.digest[:14]  # sha256 + 8 chars
            fname += f"_{digest}"

    fname = f"{sanitize(fname)}"

    path = directory / fname
    path = path.resolve()  # resolve symlinks # NOTE: can fail. See docs

    if suffix:
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        path = path.with_suffix(suffix)

    return path
