"""This module defines tokens used to render text in output (tables, etc.)."""

# TODO Future optimization:
#       * use normal classes with __slots__
#           Currently uses dataclasses for rapid iteration
#       * be able to combine tokens (e.g. bold + italic)


from dataclasses import dataclass
from typing import Any, NamedTuple


@dataclass
class Text:
    text: Any  # define type for str, int, etc.

    def render(self) -> str:
        """Renders the text as a string."""
        return str(self.text)

    def render_html(self) -> str:
        """Renders the text as HTML."""
        return str(self.text)


@dataclass
class Hyperlink(Text):
    """Class that encapsulates a text with a corresponding URL.
    Used to render hyperlinks in the text."""

    url: str
    # text: Text # this way we can combine tokens?

    def render_html(self) -> str:
        return f"<a href='{self.url}'>{self.text}</a>"


@dataclass
class Italic(Text):
    def render_html(self) -> str:
        return f"<i>{self.text}</i>"


@dataclass
class Bold(Text):
    def render_html(self) -> str:
        return f"<b>{self.text}</b>"
