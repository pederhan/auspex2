"""This module defines tokens used to render text in output (tables, etc.)."""


# FIXME: this module is a mess! I am VERY bad at parsing/tokenizing!

from typing import Any, List, Protocol, TypeVar, Union, runtime_checkable

from pydantic import validator

__all__ = [
    "Text",
    "Hyperlink",
    "Italics",
    "Bold",
    "Color",
]


@runtime_checkable
class TextLike(Protocol):
    """Protocol for objects that can be rendered as text."""

    @property
    def text(self) -> Any:
        ...

    def __bool__(self) -> bool:
        ...

    def render(self) -> str:
        ...

    def render_html(self) -> str:
        ...

    # can be expanded
    # e.g. def render_latex(self) -> str: ...


# NOTE: can we remove this?
class _TextToken:
    """The lowest level of text token. Represents a single string."""

    text: Any

    # __slots__ = ("text",)

    def __init__(self, text: Any):
        self.text = text

    def __bool__(self) -> bool:
        return bool(self.text)

    def render(self) -> str:
        return str(self.text)

    def render_html(self) -> str:
        return str(self.text)


class Stringable(Protocol):
    """Protocol for objects that can be rendered as string."""

    def __str__(self) -> str:
        ...


def token_to_text(text: Union[TextLike, str, Stringable]) -> TextLike:
    if isinstance(text, TextLike):
        return text
    return _TextToken(text=text)


class Text:
    """A plain text token (???)"""

    text: TextLike  # define type for str, int, etc.
    _tokens: List[TextLike] = []

    # __slots__ = ("text",)

    def __init__(self, text: Union[TextLike, str, Stringable] = "", *args) -> None:
        self.text = token_to_text(text)
        self._tokens = [self.text]
        for arg in args:
            self._tokens.append(token_to_text(arg))

    def __bool__(self) -> bool:
        return any(bool(token) for token in self._tokens)

    def __str__(self) -> str:
        return self.render()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.render()}>"

    def __add__(self, other: Union[str, TextLike]) -> TextLike:
        if isinstance(other, TextLike):
            t = other
        else:
            t = self.__class__(text=other)
        self._tokens.append(t)  # FIXME: VERY BAD! REMOVE
        # TODO: return new instance with modified ._tokens
        return self

    def render(self) -> str:
        """Renders the text as a string."""
        return "".join(t.render() for t in self._tokens)

    def render_html(self) -> str:
        """Renders the text as HTML."""
        return "".join(t.render_html() for t in self._tokens)


class Hyperlink(Text):
    """Class that encapsulates a text with a corresponding URL.
    Used to render hyperlinks in the text."""

    url: str

    # __slots__ = ("text", "url")

    def __init__(self, text: Union[TextLike, str] = "", url: str = "") -> None:
        super().__init__(text=text)
        self.url = url

    def __add__(self, other: Union[str, TextLike]) -> "Hyperlink":
        """Adds a string or another Hyperlink to the current Hyperlink.
        If current hyperlink URL is empty, it is replaced by the other Hyperlink URL."""
        super().__add__(other)
        if not self.url and isinstance(other, Hyperlink):
            self.url = other.url
        return self

    def render_html(self) -> str:
        return f"<a href='{self.url}'>{super().render()}</a>"


class Italics(Text):
    """Italics text token."""

    def render_html(self) -> str:
        return f"<i>{super().render_html()}</i>"  # should be render_html?


class Bold(Text):
    """Bold text token."""

    def render_html(self) -> str:
        return f"<b>{super().render_html()}</b>"


class Color(Text):
    """Color text token."""

    color: str = "black"

    def __init__(
        self, text: Union[TextLike, str] = "", color: str = "black", *args
    ) -> None:
        super().__init__(text=text, *args)
        self.color = color

    def render_html(self) -> str:
        return f"<div style='color: {self.color};'>{super().render_html()}</div>"


def _text_validator(cls, value: Any) -> Text:
    if isinstance(value, str):
        return Text(value)
    elif isinstance(value, Text):
        return value
    else:
        raise TypeError(f"{value} is not a valid string or Text")


def text_validator(field: str, each_item: bool = False) -> Any:
    return validator(field, allow_reuse=True, pre=True, each_item=each_item)(
        _text_validator
    )
