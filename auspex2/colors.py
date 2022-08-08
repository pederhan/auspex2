from typing import Union

import matplotlib as mpl
import numpy as np
from harborapi.models.scanner import Severity
from matplotlib.cm import get_cmap, register_cmap
from matplotlib.colors import ListedColormap

SEVERITY_COLORS = {
    Severity.critical: "Reds",
    Severity.high: "Oranges",
    Severity.medium: "Yellows",
    Severity.low: "Greens",
    Severity.negligible: "Purples",
    Severity.unknown: "Greys",
}

# We use the RdYlGn CMAP but reverse it so it goes from Green to Red
DEFAULT_CMAP = get_cmap("RdYlGn")
DEFAULT_CMAP = DEFAULT_CMAP.reversed()
DEFAULT_CMAP._init()  # type: ignore # call _init() so we can access the _lut attribute

# Add "yellows" as a new colormap to the list of colormaps
try:
    N = 256
    yellow = np.ones((N, 4))
    yellow[:, 0] = np.linspace(255 / 256, 1, N)[::-1]  # R = 255
    yellow[:, 1] = np.linspace(232 / 256, 1, N)[::-1]  # G = 232
    yellow[:, 2] = np.linspace(11 / 256, 1, N)[::-1]  # B = 11
    register_cmap("Yellows", ListedColormap(yellow))
except ValueError as e:
    if "already registered" in str(e):
        pass
    else:
        raise


def get_color(severity: Union[str, Severity]) -> tuple[float, float, float, float]:
    # return mpl.colors.to_rgb(mpl.cm.get_cmap(colors[severity])(0.5))
    if isinstance(severity, str):
        try:
            severity = Severity(severity)
        except ValueError as e:
            raise ValueError(f"Unknown severity {severity}") from e
    return get_cmap(SEVERITY_COLORS.get(severity))(0.5)  # type: ignore
