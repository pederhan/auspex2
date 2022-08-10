from dataclasses import dataclass, field
from typing import Any

from ..text import Text, text_validator


@dataclass
class Table:
    # TODO: make use of Text
    title: str
    header: list[str] = field(default_factory=list)  # column names
    rows: list[list[Text]] = field(
        default_factory=list
    )  # each row is a list of len(header)
    caption: Text = Text()
    description: Text = Text()
    # TODO: add rich description class

    _header_validator = text_validator("header")
    _caption_validator = text_validator("caption")
    _description_validator = text_validator("description")

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True

    def __post_init__(self):
        if self.rows and len(self.header) != len(self.rows[0]):
            raise ValueError("header and rows must be the same length")

    @property
    def empty(self) -> bool:
        return len(self.rows) == 0
