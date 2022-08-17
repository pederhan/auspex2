from typing import Any, Dict, Union

from pydantic import BaseModel, Field, root_validator

from ..text import Text, text_validator


class Table(BaseModel):
    # TODO: make use of Text
    title: Union[str, Text]
    header: list[Text] = Field(default_factory=list)  # column names
    rows: list[list[Text]] = Field(
        default_factory=list
    )  # each row is a list of len(header)
    caption: Union[str, Text] = Text()
    description: Union[str, Text] = Text()
    # TODO: add rich description class

    _title_validator = text_validator("title")
    _header_validator = text_validator("header", each_item=True)
    _caption_validator = text_validator("caption")
    _description_validator = text_validator("description")

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
