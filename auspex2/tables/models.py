from dataclasses import dataclass, field
from typing import Any


@dataclass
class Table:
    title: str
    header: list[str] = field(default_factory=list)  # column names
    rows: list[list[Any]] = field(
        default_factory=list
    )  # each row is a list of len(header)
    caption: str = ""
    description: str = ""
    # TODO: add rich description class

    def __post_init__(self):
        if self.rows and len(self.header) != len(self.rows[0]):
            raise ValueError("header and rows must be the same length")

    @property
    def empty(self) -> bool:
        return len(self.rows) == 0
