from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union

from pydantic import BaseModel

from ..text import Text, text_validator

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

    def as_dict(self) -> Dict[T, S]:
        return {label: value for label, value in zip(self.labels, self.values)}


class Plot(BaseModel):
    title: Union[Text, str]
    plot_type: PlotType
    description: Union[Text, str] = Text()
    caption: Union[Text, str] = Text()
    path: Optional[Path] = None
    script: Optional[str] = None
    div: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True

    _title_validator = text_validator("title")
    _description_validator = text_validator("description")
    _caption_validator = text_validator("caption")

    @property
    def embeddable(self) -> bool:
        return self.script is not None and self.div is not None


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
