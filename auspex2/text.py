from typing import NamedTuple


class Hyperlink(NamedTuple):
    """Class that encapsulates a text with a corresponding URL.
    Used to render hyperlinks in the text."""

    url: str
    text: str
