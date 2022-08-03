import asyncio
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np  # noqa?
from harborapi import HarborAsyncClient
from harborapi.models.scanner import HarborVulnerabilityReport, Severity

from .colors import get_color
from .models import PlotData, PlotType

client = HarborAsyncClient(
    url="https://harbor-test.uio.no/api/v2.0",
    credentials_file="robot.json",
    logging=True,
)


def piechart_severity(
    report: HarborVulnerabilityReport, basename: Optional[str] = None
) -> PlotData:
    """Generates a pie chart of the severity distribution of vulnerabilities.
    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    basename : `Optional[str]`
        The basename of the output file.
    Returns
    -------
    `PlotData`
        A plot data object containing everything required to insert
        the plot into the report.
    """

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

    labels = set()  # type: set[Severity]
    values = []  # type: list[int]
    # "dumb" iteration to ensure order is correct (not necessary?)
    for label, value in report.distribution.items():
        labels.add(label)
        values.append(value)

    if all(v == 0 for v in values):
        return p
    colors = []  # type: list[tuple[float, float, float, float]]
    for label in labels:
        colors.append(get_color(label))

    # def get_colors(cmapname: str) -> tuple[int, ...]:
    #     return plt.colormaps[cmapname]([150, 125, 100])
    #     # plt.colormaps()

    # low = get_colors("Greens")
    # medium = get_colors("Yellows")  # assert this is init
    # high = get_colors("Oranges")
    # critical = get_colors("Reds")
    # colors = [low, medium, high, critical]

    # colors = [low[0], medium[0], high[0], critical[0]]

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
    # path = save_fig(fig, report, basename, "piechart_severity")
    # p.path = path
    p.description = (
        f"The pie chart shows the distribution of vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    plt.show(block=True)
    return p


async def main() -> None:
    # artifacts = await client.get_artifacts(
    #     "library", "vulntest", query="tags=latest", with_scan_overview=True
    # )
    # print(artifacts)
    report = await client.get_artifact_vulnerabilities("library", "vulntest", "latest")
    if report:
        piechart_severity(report)


if __name__ == "__main__":
    asyncio.run(main())
