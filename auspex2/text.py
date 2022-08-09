"""This module defines tokens used to render text in output (tables, etc.)."""

from typing import Any, Protocol, Union, runtime_checkable


@runtime_checkable
class TextLike(Protocol):
    """Protocol for objects that can be rendered as text."""

    def render(self) -> str:
        ...

    def render_html(self) -> str:
        ...

    # can be expanded
    # e.g. def render_latex(self) -> str: ...


class _TextToken:
    """The lowest level of text token. Represents a single string."""

    text: Any

    __slots__ = ("text",)

    def __init__(self, text: Any):
        self.text = text

    def render(self) -> str:
        return str(self.text)

    def render_html(self) -> str:
        return str(self.text)


class Text:
    """The base class for all text tokens"""

    text: TextLike  # define type for str, int, etc.

    __slots__ = ("text",)

    def __init__(self, text: Union[TextLike, str]) -> None:
        if isinstance(text, TextLike):
            self.text = text
        else:
            self.text = _TextToken(text=text)

    def render(self) -> str:
        """Renders the text as a string."""
        return str(self.text.render())

    def render_html(self) -> str:
        """Renders the text as HTML."""
        return str(self.text.render_html())


class Hyperlink(Text):
    """Class that encapsulates a text with a corresponding URL.
    Used to render hyperlinks in the text."""

    url: str

    __slots__ = ("text", "url")

    def __init__(self, text: Union[TextLike, str], url: str) -> None:
        super().__init__(text=text)
        self.url = url

    def render_html(self) -> str:
        return f"<a href='{self.url}'>{self.text.render_html()}</a>"


class Italic(Text):
    """Italics text token."""

    def render_html(self) -> str:
        return f"<i>{self.text.render_html()}</i>"


class Bold(Text):
    """Bold text token."""

    def render_html(self) -> str:
        return f"<b>{self.text.render_html()}</b>"
