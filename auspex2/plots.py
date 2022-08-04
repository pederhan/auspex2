import asyncio
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np  # noqa?
from harborapi import HarborAsyncClient, HarborClient
from harborapi.models.scanner import HarborVulnerabilityReport, Severity
from sanitize_filename import sanitize

from auspex2.api import ArtifactInfo

from .colors import get_color
from .models import PlotData, PlotType


def piechart_severity(
    artifact: ArtifactInfo, basename: Optional[str] = None
) -> PlotData:
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
    report = artifact.report
    assert report is not None  # ideally do away with this

    title = f"Distribution of Vulnerabilities by Severity"
    p = PlotData(
        title=title,
        description="No vulnerabilities found.",
        caption=title,
        path=None,
        plot_type=PlotType.PIE,
    )

    fig, ax = plt.subplots()

    size = 0.3

    labels = []  # type: list[Severity]
    values = []  # type: list[int]
    # "dumb" iteration to ensure order is correct (not necessary?)
    for label, value in report.distribution.items():
        labels.append(label)
        values.append(value)

    if all(v == 0 for v in values):
        return p
    colors = []  # type: list[tuple[float, float, float, float]]
    for severity in report.distribution.keys():
        colors.append(get_color(severity))
    colors = [get_color(severity) for severity in report.distribution.keys()]

    def labelfunc(pct: float, allvals: list[int]) -> str:
        absolute = int(np.round(pct / 100.0 * np.sum(allvals)))
        return "{:.1f}%\n({:d})".format(pct, absolute)

    # Outer pie chart
    wedges, *_ = ax.pie(
        values,
        radius=1,
        colors=colors,
        wedgeprops=dict(width=0.7, edgecolor="black", linewidth=0.5),
        startangle=90,
        counterclock=False,
        autopct=lambda pct: labelfunc(pct, values),
    )
    #
    ax.legend(
        wedges,
        labels,
        title=f"Severity Distribution for {report.artifact}",
        loc="upper left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )

    # Save fig and store its filename
    # TODO: fix filename
    path = save_fig(fig, artifact, basename, "piechart_severity")
    p.path = path
    p.description = (
        f"The pie chart shows the distribution of vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    # plt.show(block=True)
    return p


def save_fig(
    fig: plt.Figure,
    artifact: ArtifactInfo,
    basename: Optional[str],
    suffix: str,
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
            basename += f"_{artifact.artifact.digest}"
    fig_filename = f"{basename}_{suffix}"
    if filetype:
        fig_filename = f"{fig_filename}.{filetype}"
    fig_filename = sanitize(fig_filename)
    path = Path(fig_filename).absolute()
    fig.savefig(str(path))
    if close_after:
        plt.close(fig)
    return path