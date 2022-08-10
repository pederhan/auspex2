from auspex2.text import Bold, Hyperlink, Italics, Text, TextLike, _TextToken


def test_text():
    text = Text("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.render() == "Hello, world!"
    assert text.render_html() == "Hello, world!"

    text = Text()
    assert not text


def test_hyperlink():
    text = Hyperlink("Hello, world!", url="https://google.com")
    assert text
    assert isinstance(text, TextLike)
    assert text.render() == "Hello, world!"
    assert text.render_html() == "<a href='https://google.com'>Hello, world!</a>"

    text = Hyperlink()
    assert not text


def test_italics():
    text = Italics("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.render() == "Hello, world!"
    assert text.render_html() == "<i>Hello, world!</i>"

    text = Italics()
    assert not text


def test_bold():
    text = Bold("Hello, world!")
    assert text
    assert isinstance(text, TextLike)
    assert text.render() == "Hello, world!"
    assert text.render_html() == "<b>Hello, world!</b>"

    text = Bold()
    assert not text


def test_text_compose():
    text = Text("Hello, ") + Text("world!")
    assert text.render() == "Hello, world!"


def test_hyperlink_add():
    text = Hyperlink("Hello, ", url="https://google.com") + Hyperlink(
        "world!", url="https://yahoo.com"
    )
    assert text.render() == "Hello, world!"
    assert text.render_html() == "<a href='https://google.com'>Hello, world!</a>"
    assert text.url == "https://google.com"

    text2 = Hyperlink("Hello, ", url="https://google.com") + "world!"
