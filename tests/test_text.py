from auspex2.text import (
    Badge,
    Bold,
    Color,
    Hyperlink,
    Italics,
    Text,
    TextLike,
    _TextToken,
)


def test_text():
    text = Text("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "Hello, world!"

    text = Text()
    assert not text


def test_hyperlink():
    text = Hyperlink("Hello, world!", url="https://google.com")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "<a href='https://google.com'>Hello, world!</a>"

    text = Hyperlink()
    assert not text


def test_italics():
    text = Italics("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "<i>Hello, world!</i>"

    text = Italics()
    assert not text


def test_bold():
    text = Bold("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "<b>Hello, world!</b>"

    text = Bold()
    assert not text


def test_text_compose():
    text = Text("Hello, ") + Text("world!")
    assert text.plain == "Hello, world!"


def test_hyperlink_add():
    text = Hyperlink("Hello, ", url="https://google.com") + Hyperlink(
        "world!", url="https://yahoo.com"
    )
    assert text.plain == "Hello, world!"
    assert text.html == "<a href='https://google.com'>Hello, world!</a>"
    assert text.url == "https://google.com"

    text2 = Hyperlink("Hello, ", url="https://google.com") + "world!"


def test_color():
    text = Color("Hello, world!", color="red")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "<div style='color: red;'>Hello, world!</div>"

    text = Color()
    assert not text


def test_badge():
    text = Badge("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.plain == "Hello, world!"
    assert text.html == "<span class='badge bg-primary'>Hello, world!</span>"

    text = Badge()
    assert not text

    text = Badge("Hello, world!", bg_color="secondary")
    assert text.html == "<span class='badge bg-secondary'>Hello, world!</span>"


def test_textlike():
    """Tests that all expected TextLike methods are implemented and
    they pass isinstance checks."""
    classes = [
        Text,
        Hyperlink,
        Italics,
        Bold,
        Color,
        Badge,
    ]
    for cls in classes:
        text = cls("Hello, world!")
        assert text
        assert isinstance(text, TextLike)
        assert text.plain == "Hello, world!"

        text = cls()
        assert not text
