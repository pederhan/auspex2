import asyncio
from enum import Enum
from importlib.metadata import distribution
from pathlib import Path
from typing import Optional, Union

import matplotlib.pyplot as plt
import numpy as np  # noqa?
from harborapi.models.scanner import Severity
from matplotlib.figure import Figure
from sanitize_filename import sanitize

from ..api import ArtifactInfo
from ..colors import get_color
from ..report import ArtifactReport
from ..utils import get_distribution, plotdata_from_dist
from .models import PieChartStyle, Plot, PlotType


def piechart_severity(
    report: ArtifactReport,
    # prefix: Optional[str] = "severity",
    directory: Optional[Union[str, Path]] = None,
    style: Union[PieChartStyle, str] = PieChartStyle.DEFAULT,
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

    title = f"Distribution of {extra}Vulnerabilities by Severity"
    p = Plot(
        title=title,
        description="No vulnerabilities found.",
        caption=title,
        path=None,
        plot_type=PlotType.PIE,
    )

    fig, ax = plt.subplots()

    size = 0.3

    if style == PieChartStyle.FIXABLE:
        distribution = get_distribution(report.fixable)
    elif style == PieChartStyle.UNFIXABLE:
        distribution = get_distribution(report.unfixable)
    else:
        distribution = report.distribution

    plotdata = plotdata_from_dist(distribution)
    if all(v == 0 for v in plotdata.values):
        return p

    colors = [get_color(severity) for severity in plotdata.labels]

    def labelfunc(pct: float, allvals: list[int]) -> str:
        absolute = int(np.round(pct / 100.0 * np.sum(allvals)))
        return "{:.1f}%\n({:d})".format(pct, absolute)

    # Outer pie chart
    wedges, *_ = ax.pie(
        plotdata.values,
        radius=1,
        colors=colors,
        wedgeprops=dict(width=0.7, edgecolor="black", linewidth=0.5),
        startangle=90,
        counterclock=False,
        autopct=lambda pct: labelfunc(pct, plotdata.values),
    )

    if report.is_aggregate:
        name = "All Repositories"  # FIXME: more specific than "All Repositories"
        artifact = None
        filename = "aggregatereport"
    else:
        name = report.artifacts[0].repository.name
        artifact = report.artifacts[0]
        filename = None
    p.title = f"{name} - {title}"

    # Add legend
    ax.legend(
        wedges,
        [l.name for l in plotdata.labels],
        title="Severity",
        loc="upper left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )
    ax.set_title(p.title)

    # Save fig and store its filename
    # TODO: fix filename
    path = save_fig(
        fig=fig,
        filename=filename,
        artifact=artifact,
        # prefix=prefix,
        directory=directory,
        suffix=f"{style.name}_piechart_severity",
    )
    p.path = path
    p.description = (
        f"The pie chart shows the distribution of {extra}vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    # plt.show(block=True)
    return p


def save_fig(
    fig: Figure,
    filename: Optional[str] = None,
    artifact: Optional[ArtifactInfo] = None,
    prefix: Optional[str] = None,
    suffix: Optional[str] = None,
    directory: Optional[Union[str, Path]] = None,
    filetype: str = "png",
    close_after: bool = True,
) -> Path:
    """Saves a figure to a file.

    Parameters
    ----------
    fig : Figure
        The figure to save.
    artifact : ArtifactInfo
        Information about the artifact used to generate the figure.
    prefix : Optional[str]
        The prefix for the of the figure's filename.
        If omitted, uses the artifact's name and digest, by default None
    suffix : Optional[str]
        Suffix to append to filename
    directory : Optional[Union[str, Path]]
        The directory to save the file to, by default None
    filetype : str
        File suffix, by default "pdf"
    close_after : bool
        Close figure after saving, by default True

    Returns
    -------
    Path
        Path to the saved figure.
    """
    fname = filename or ""
    if artifact:
        if artifact.repository.name:
            fname = f"{artifact.repository.name}"
        if artifact.artifact.digest:
            digest = artifact.artifact.digest[:14]  # sha256 + 8 chars
            fname = f"{fname}_{digest}"

    if prefix:
        fname = f"{prefix}_{fname}"
    if suffix:
        fname = f"{fname}_{suffix}"
    if filetype:
        fname = f"{fname}.{filetype}"  # remove?

    dirpath = Path(directory) if directory else Path(".")

    fig_filename = sanitize(fname)
    path = (dirpath / Path(fig_filename)).absolute()

    fig.savefig(str(path), format=filetype)
    if close_after:
        plt.close(fig)

    return path