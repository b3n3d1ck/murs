"""HTML parsing: links, forms, and file-upload inputs (stdlib only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class FormField:
    name: str
    type: str = "text"


@dataclass
class Form:
    action: str
    method: str = "get"
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)

    @property
    def file_fields(self) -> list[FormField]:
        return [f for f in self.fields if f.type == "file"]

    @property
    def is_upload(self) -> bool:
        return bool(self.file_fields) or "multipart/form-data" in self.enctype.lower()


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.title: str | None = None
        self._in_title = False
        self._cur: Form | None = None
        self.generators: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            if a.get("name", "").lower() == "generator" and a.get("content"):
                self.generators.append(a["content"])
        elif tag == "form":
            self._cur = Form(
                action=a.get("action", ""),
                method=(a.get("method") or "get").lower(),
                enctype=(a.get("enctype") or "application/x-www-form-urlencoded").lower(),
            )
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur.fields.append(
                FormField(name=a.get("name", ""), type=(a.get("type") or "text").lower())
            )

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def handle_data(self, data):
        if self._in_title and self.title is None:
            t = data.strip()
            if t:
                self.title = t


@dataclass
class ParsedPage:
    title: str | None
    links: list[str]
    forms: list[Form]
    generators: list[str]


def parse_html(html: str) -> ParsedPage:
    p = _Parser()
    try:
        p.feed(html)
    except Exception:  # malformed HTML must never crash a scan
        pass
    return ParsedPage(title=p.title, links=p.links, forms=p.forms, generators=p.generators)
