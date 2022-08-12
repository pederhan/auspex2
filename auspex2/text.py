"""This module defines tokens used to render text in output (tables, etc.)."""


# FIXME: this module is a mess! I am VERY bad at parsing/tokenizing!

from typing import Any, List, Optional, Protocol, TypeVar, Union, runtime_checkable

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

    @property
    def plain(self) -> str:
        ...

    @property
    def html(self) -> str:
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

    @property
    def plain(self) -> str:
        return str(self.text)

    @property
    def html(self) -> str:
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
        return self.plain

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.plain}>"

    def __add__(self, other: Union[str, TextLike]) -> TextLike:
        if isinstance(other, TextLike):
            t = other
        else:
            t = self.__class__(text=other)
        self._tokens.append(t)  # FIXME: VERY BAD! REMOVE
        # TODO: return new instance with modified ._tokens
        return self

    @property
    def plain(self) -> str:
        """Renders the text as a string."""
        return "".join(t.plain for t in self._tokens)

    @property
    def html(self) -> str:
        """Renders the text as HTML."""
        return "".join(t.html for t in self._tokens)


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

    @property
    def html(self) -> str:
        return f"<a href='{self.url}'>{super().plain}</a>"


class Italics(Text):
    """Italics text token."""

    @property
    def html(self) -> str:
        return f"<i>{super().html}</i>"  # should be html?


class Bold(Text):
    """Bold text token."""

    @property
    def html(self) -> str:
        return f"<b>{super().html}</b>"


class Color(Text):
    """Color text token."""

    color: str = "black"

    def __init__(
        self, text: Union[TextLike, str] = "", color: str = "black", *args
    ) -> None:
        super().__init__(text=text, *args)
        self.color = color

    @property
    def html(self) -> str:
        return f"<div style='color: {self.color};'>{super().html}</div>"


class Badge(Text):
    """Badge token

    Rendered as a Bootstrap badge in HTML, plaintext otherwise.
    """

    style: Optional[str]  # TODO: make this an enum
    bg_color: str  # bootstrap styles: primary, secondary, etc.

    def __init__(
        self,
        text: Union[TextLike, str] = "",
        *args,
        style: Optional[str] = None,
        bg_color: str = "primary",
    ) -> None:
        super().__init__(text=text, *args)
        self.style = style
        self.bg_color = bg_color

    @property
    def html(self) -> str:
        if self.style:
            s = f" {self.style}"
        else:
            s = ""
        return f"<span class='badge{s} bg-{self.bg_color}'>{super().html}</span>"


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
