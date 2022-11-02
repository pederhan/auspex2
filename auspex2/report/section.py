from enum import Enum
from typing import Iterator, List, Union

from pydantic import BaseModel, Field

from .text import Text, text_validator


class SectionType(Enum):
    TABLE = "table"
    PLOT = "plot"
    TEXT = "text"
    MULTI = "multi"


class Section(BaseModel):
    section_type: SectionType
    title: Union[Text, str]
    description: Union[Text, str] = Text()
    caption: Union[Text, str] = Text()

    _title_validator = text_validator("title")
    _description_validator = text_validator("description")
    _caption_validator = text_validator("caption")

    class Config:
        schema_extra = {
            "example": {
                "section_type": "text",
                "title": "Text",
                "description": "This is a text section",
                "caption": "This is a caption",
            }
        }
        arbitrary_types_allowed = True


class MultiSection(Section):
    subsections: List[Section] = Field(default_factory=list)
    html_wrapper: str = Field(default='<div class=col-3">{}</div>')
    row: bool = True  # all sections in same row
    section_type: SectionType = Field(default=SectionType.MULTI)

    @property
    def empty(self) -> bool:
        return len(self.subsections) == 0

    def __len__(self) -> int:
        return len(self.subsections)

    def __iter__(self) -> Iterator[Section]:  # type: ignore
        return iter(self.subsections)

    @property
    def wrap_start(self) -> str:
        return self.html_wrapper.split("{}")[0]

    @property
    def wrap_end(self) -> str:
        return self.html_wrapper.split("{}")[1]
