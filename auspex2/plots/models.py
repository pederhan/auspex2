from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Generic, List, Optional, TypeVar, Union

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


class Plot(BaseModel):
    title: str  # TODO: use Text?
    plot_type: PlotType
    description: Union[Text, str] = Text()
    caption: Union[Text, str] = Text()
    path: Optional[Path] = None

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True

    # @validator("description")
    # def coerce_description(cls, v: Any) -> Union[Text, str]:
    #     if isinstance(v, str):
    #         return Text(v)
    #     return v

    _description_validator = text_validator("description")

    def __post_init__(self) -> None:
        if isinstance(self.description, str):
            self.description = Text(self.description)
        if isinstance(self.caption, str):
            self.caption = Text(self.caption)


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
