from typing import Any, Dict, Union

from pydantic import BaseModel, Field, root_validator

from ..section import Section, SectionType
from ..text import Text, text_validator


class Table(Section):
    header: list[Text] = Field(default_factory=list)  # column names
    rows: list[list[Text]] = Field(
        default_factory=list
    )  # each row is a list of len(header)
    section_type: SectionType = Field(default=SectionType.TABLE, allow_mutation=False)

    _header_validator = text_validator("header", each_item=True)

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True

    @root_validator
    def validate_header_length(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        rows = values.get("rows", [])
        header = values.get("header", [])
        if rows and len(header) != len(rows[0]):
            # NOTE: check all rows?
            raise ValueError("header and rows must be the same length")
        return values

    @property
    def empty(self) -> bool:
        return len(self.rows) == 0
