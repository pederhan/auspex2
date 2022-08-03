from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class PlotType(Enum):
    PIE = auto()
    BAR = auto()
    LINE = auto()
    SCATTER = auto()
    HISTOGRAM = auto()


@dataclass
class PlotData:
    title: str
    plot_type: PlotType
    description: str = ""
    caption: str = ""
    path: Optional[Path] = None