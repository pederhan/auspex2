import asyncio
from enum import Enum
from importlib.metadata import distribution
from pathlib import Path
from typing import Optional, Union

import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import numpy as np  # noqa?
from harborapi.models.scanner import Severity
from sanitize_filename import sanitize

from .api import ArtifactInfo
from .utils import get_distribution, plotdata_from_dist

from .colors import get_color
from .models import Plot, PlotType


class PieChartStyle(Enum):
    DEFAULT = "default"
    FIXABLE = "fixable"
    UNFIXABLE = "unfixable"

    @classmethod
    def get_style(cls, style: Union[str, "PieChartStyle"]) -> "PieChartStyle":
        if isinstance(style, str):
            try:
                return cls(style)
            except ValueError as e:
                raise ValueError(f"Unknown Pie Chart style {style}") from e
        return style


def piechart_severity(
    artifact: ArtifactInfo,
    basename: Optional[str] = None,
    directory: Optional[Union[str, Path]] = None,
    style: Union[PieChartStyle, str] = PieChartStyle.DEFAULT,
) -> Plot:
    """Generates a pie chart of the severity distribution of vulnerabilities.
    Parameters
    ----------
    artifact : ArtifactInfo
        An object containing the artifact and its vulnerabilities.
    basename : Optional[str]
        The basename of the output file.
    Returns
    -------
    `PlotData`
        A plot data object containing everything required to insert
        the plot into the report.
    """
    style = PieChartStyle.get_style(style)

    report = artifact.report
    assert report is not None  # ideally do away with this

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

    # Add legend
    ax.legend(
        wedges,
        [l.name for l in plotdata.labels],
        title=f"Severity Distribution for {report.artifact}",
        loc="upper left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )

    # Save fig and store its filename
    # TODO: fix filename
    path = save_fig(
        fig,
        artifact,
        basename=basename,
        directory=directory,
        suffix=f"{style.name}_piechart_severity",
    )
    p.path = path
    p.description = (
        f"The pie chart shows the distribution of vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    # plt.show(block=True)
    return p


def save_fig(
    fig: Figure,
    artifact: ArtifactInfo,
    basename: Optional[str] = None,
    suffix: Optional[str] = None,
    directory: Optional[Union[str, Path]] = None,
    filetype: str = "pdf",
    close_after: bool = True,
) -> Path:
    """Saves a figure to a file.
    Parameters
    ----------
    fig : plt.Figure
        The figure to save.
    basename : Optional[str]
        The basename of the output file.
    suffix : str
        The filename suffix to add to the basename.
    filetype : str
        The filetype to save the figure as.
    close_after : bool
        Whether to close the figure after saving.
    Returns
    -------
    `Path`
        Path to the generated figure.
    """
    if not basename:
        basename = f"{artifact.repository.name}"
        if artifact.artifact.digest:
            digest = artifact.artifact.digest[:14]  # sha256 + 8 chars
            basename += f"_{digest}"

    fig_filename = f"{basename}_{suffix}"
    if filetype:
        fig_filename = f"{fig_filename}.{filetype}"

    dirpath = Path(directory) if directory else Path(".")

    fig_filename = sanitize(fig_filename)
    path = (dirpath / Path(fig_filename)).absolute()

    fig.savefig(str(path))
    if close_after:
        plt.close(fig)

    return path
