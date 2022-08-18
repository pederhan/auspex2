"""This module defines tokens used to render text in output (tables, etc.)."""


# FIXME: this module is a mess! I am VERY bad at parsing/tokenizing!

from sys import version_info
from typing import (
    Any,
    List,
    Optional,
    Protocol,
    TypeVar,
    Union,
    cast,
    runtime_checkable,
)

from pydantic import validator

if version_info >= (3, 11):
    from typing import Self  # type: ignore
else:
    from typing_extensions import Self

__all__ = [
    "Text",
    "Hyperlink",
    "Italics",
    "Bold",
    "Color",
    "Badge",
]


@runtime_checkable
class TextLike(Protocol):
    """Protocol for objects that can be rendered as text."""

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
    return _TextToken(text)


class Text:
    """A plain text token (???)"""

    _tokens: List[TextLike]

    def __init__(self, *text: Union[TextLike, str, Stringable]) -> None:
        self._tokens = []
        for t in text:
            self._tokens.append(token_to_text(t))

    def __bool__(self) -> bool:
        return any(bool(token) for token in self._tokens)

    def __str__(self) -> str:
        return self.plain

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.plain}>"

    def __add__(self, other: Union[str, TextLike]) -> Self:  # type: ignore # https://github.com/python/mypy/pull/11666
        if isinstance(other, TextLike):
            t = other
        else:
            t = self.__class__(other)
        return self.__class__(*(self._tokens), t)

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

    def __init__(
        self,
        *text: Union[str, TextLike],
        url: str = "",
    ) -> None:
        super().__init__(*text)
        self.url = url

    def __add__(self, other: Union[str, TextLike]) -> "Hyperlink":
        """Adds a string or another Hyperlink to the current Hyperlink.
        If current hyperlink URL is empty, it is replaced by the other Hyperlink URL."""
        new_obj = super().__add__(other)
        new_obj = cast(Hyperlink, new_obj)  # satisfy mypy (bug [i think])
        if not self.url and isinstance(other, Hyperlink):
            new_obj.url = other.url
        else:
            new_obj.url = self.url
        return new_obj

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

    def __init__(self, *text: Union[TextLike, str], color: str = "black") -> None:
        super().__init__(*text)
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
        *text: Union[TextLike, str],
        style: Optional[str] = None,
        bg_color: str = "primary",
    ) -> None:
        super().__init__(*text)
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
