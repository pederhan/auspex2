from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Generic, List, Optional, TypeVar

T = TypeVar("T")
S = TypeVar("S")


class PlotType(Enum):
    PIE = auto()
    BAR = auto()
    LINE = auto()
    SCATTER = auto()
    HISTOGRAM = auto()


@dataclass
class PlotData(Generic[T, S]):
    labels: List[T] = field(default_factory=list)
    values: List[S] = field(default_factory=list)

    def __post_init__(self):
        if len(self.labels) != len(self.values):
            raise ValueError("labels and values must be the same length")


@dataclass
class Plot:
    title: str
    plot_type: PlotType
    description: str = ""
    caption: str = ""
    path: Optional[Path] = None
