from enum import Enum
from typing import Union

from pydantic import BaseModel

from .text import Text, text_validator


class SectionType(Enum):
    TABLE = "table"
    PLOT = "plot"
    TEXT = "text"


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
