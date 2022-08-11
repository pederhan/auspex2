from functools import lru_cache
from typing import List, Sequence, Tuple, Union

from bokeh.palettes import Greys3, RdYlGn5
from harborapi.models.scanner import Severity

# set default palette and copy it, so we can modify its contents
DEFAULT_PALETTE = list(RdYlGn5)  # type: list[str]
DEFAULT_PALETTE[2] = "#fadd02"

SEVERITY_COLORS = {
    Severity.critical: RdYlGn5[4],
    Severity.high: RdYlGn5[3],
    Severity.medium: RdYlGn5[2],
    Severity.low: RdYlGn5[1],
    Severity.negligible: RdYlGn5[0],
    Severity.unknown: Greys3[0],
}

COLOR_GOOD = DEFAULT_PALETTE[0]
COLOR_BAD = DEFAULT_PALETTE[-1]


def get_color_severity(severity: Union[str, Severity]) -> str:
    # return mpl.colors.to_rgb(mpl.cm.get_cmap(colors[severity])(0.5))
    if isinstance(severity, str):
        try:
            severity = Severity(severity)
        except ValueError as e:
            raise ValueError(f"Unknown severity {severity}") from e
    return SEVERITY_COLORS.get(severity, SEVERITY_COLORS[Severity.unknown])


@lru_cache(maxsize=256)  # or bigger?
def get_color_cvss(cvss: float, palette: Sequence[str] = DEFAULT_PALETTE) -> str:
    """Returns a hex color code given a palette and a CVSS score.

    Parameters
    ----------
    cvss : float
        CVSS score.
    palette : Sequence[str]
        Palette of hex color codes.

    Returns
    -------
    str
        Hex color code.
    """
    max_idx = len(palette) - 1
    idx = round(max_idx * cvss / 10)
    if idx > max_idx:
        idx = max_idx
    return palette[idx]
