"""Text extraction for uploaded architecture documents.

Supported: PDF (pypdf), Word/PowerPoint/Visio OOXML (zip + XML), draw.io, SVG, HTML, plain text,
Markdown, JSON/YAML/CSV. Images (and PDFs, for richer diagrams) are additionally passed to
vision-capable AI providers as attachments.
"""
from __future__ import annotations

import base64
import html
import io
import re
import zipfile
import zlib
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree as ET

IMAGE_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
             ".webp": "image/webp", ".bmp": "image/bmp"}
DOC_EXT = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
           ".vsdx": "application/vnd.ms-visio.drawing", ".drawio": "application/xml", ".svg": "image/svg+xml",
           ".txt": "text/plain", ".md": "text/markdown", ".markdown": "text/markdown", ".json": "application/json",
           ".yaml": "text/yaml", ".yml": "text/yaml", ".csv": "text/csv", ".html": "text/html", ".htm": "text/html",
           ".xml": "application/xml", ".puml": "text/plain", ".mmd": "text/plain", ".rtf": "text/rtf"}
CODE_ARCHIVE_EXT = {".zip"}
MAX_TEXT = 400_000  # chars kept per document


def classify_upload(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in IMAGE_EXT:
        return "image"
    if ext in DOC_EXT:
        return "document"
    return "unknown"


def mime_for(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return IMAGE_EXT.get(ext) or DOC_EXT.get(ext) or "application/octet-stream"


def _clean(text: str) -> str:
    text = text.replace("\r", "")
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()[:MAX_TEXT]


def _xml_text(data: bytes, para_tags: tuple[str, ...] = ("p",)) -> str:
    """Concatenate text nodes, inserting newlines at paragraph-like elements."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return ""
    out: list[str] = []

    def walk(el: ET.Element) -> None:
        tag = el.tag.rsplit("}", 1)[-1]
        if el.text and tag not in ("style", "script"):
            out.append(el.text)
        for child in el:
            walk(child)
        if tag in para_tags:
            out.append("\n")
        if el.tail and el.tail.strip():
            out.append(el.tail)
    walk(root)
    return "".join(out)


def _pdf(data: bytes) -> tuple[str, dict]:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    pages = []
    for i, page in enumerate(reader.pages):
        try:
            pages.append(f"--- page {i + 1} ---\n" + (page.extract_text() or ""))
        except Exception:  # noqa: BLE001 - malformed page, keep going
            pages.append(f"--- page {i + 1} --- (unreadable)")
    return "\n".join(pages), {"pages": len(reader.pages)}


def _docx(data: bytes) -> tuple[str, dict]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        parts = ["word/document.xml"] + sorted(n for n in z.namelist()
                                               if re.match(r"word/(header|footer|footnotes|comments)\d*\.xml", n))
        text = "\n".join(_xml_text(z.read(p), ("p", "tr")) for p in parts if p in z.namelist())
        images = [n for n in z.namelist() if n.startswith("word/media/")]
    return text, {"embedded_images": len(images)}


def _pptx(data: bytes) -> tuple[str, dict]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        slides = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                        key=lambda n: int(re.findall(r"\d+", n)[-1]))
        notes = {int(re.findall(r"\d+", n)[-1]): n for n in z.namelist()
                 if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n)}
        out = []
        for i, s in enumerate(slides, 1):
            out.append(f"--- slide {i} ---\n" + _xml_text(z.read(s)))
            if i in notes:
                out.append("Notes: " + _xml_text(z.read(notes[i])))
    return "\n".join(out), {"slides": len(slides)}


def _vsdx(data: bytes) -> tuple[str, dict]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        pages = sorted(n for n in z.namelist() if re.match(r"visio/pages/page\d+\.xml$", n))
        out = [f"--- page {i} ---\n" + _xml_text(z.read(p), ("Shape", "p")) for i, p in enumerate(pages, 1)]
    return "\n".join(out), {"pages": len(pages)}


def _drawio(data: bytes) -> tuple[str, dict]:
    """draw.io / diagrams.net: labels live in mxCell@value; diagrams may be deflate+base64 compressed."""
    text = data.decode("utf-8", "replace")
    xmls = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return text, {}
    for d in root.iter("diagram"):
        if len(d):
            xmls.append(ET.tostring(d, encoding="unicode"))
        elif (d.text or "").strip():
            try:
                raw = zlib.decompress(base64.b64decode(d.text.strip()), -15).decode("utf-8")
                xmls.append(unquote(raw))
            except Exception:  # noqa: BLE001
                pass
    if not xmls:
        xmls = [text]
    labels, edges = [], 0
    for x in xmls:
        try:
            r = ET.fromstring(x)
        except ET.ParseError:
            continue
        for cell in r.iter("mxCell"):
            v = cell.get("value") or ""
            v = re.sub(r"<br\s*/?>", " ", v)
            v = html.unescape(re.sub(r"<[^>]+>", " ", v)).strip()
            if cell.get("edge") == "1":
                edges += 1
                if v:
                    labels.append(f"[flow] {v}")
            elif v:
                labels.append(v)
        for obj in r.iter("object"):
            if obj.get("label"):
                labels.append(html.unescape(re.sub(r"<[^>]+>", " ", obj.get("label"))).strip())
    return "\n".join(dict.fromkeys(labels)), {"shapes": len(labels), "flows": edges}


def _html(data: bytes) -> str:
    t = data.decode("utf-8", "replace")
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", t)
    t = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h\d>", "\n", t)
    return html.unescape(re.sub(r"<[^>]+>", " ", t))


def _rtf(data: bytes) -> str:
    t = data.decode("latin-1", "replace")
    t = re.sub(r"\\par[d]?", "\n", t)
    t = re.sub(r"\\'[0-9a-f]{2}", "", t)
    t = re.sub(r"\\[a-z]+-?\d* ?|[{}]", "", t)
    return t


def extract_text(filename: str, data: bytes) -> tuple[str, dict]:
    """Return (text, meta). Never raises - failures are reported in meta['error']."""
    ext = Path(filename).suffix.lower()
    meta: dict = {}
    try:
        if ext in IMAGE_EXT:
            return "", {"needs_vision": True}
        if ext == ".pdf":
            text, meta = _pdf(data)
            if len(text.strip()) < 40 * max(1, meta.get("pages", 1)) // 4:
                meta["needs_vision"] = True  # scanned / diagram-only PDF
        elif ext == ".docx":
            text, meta = _docx(data)
        elif ext == ".pptx":
            text, meta = _pptx(data)
        elif ext == ".vsdx":
            text, meta = _vsdx(data)
        elif ext == ".drawio" or (ext == ".xml" and b"mxfile" in data[:2000]):
            text, meta = _drawio(data)
        elif ext == ".svg":
            text = _xml_text(data, ("text", "g"))
        elif ext in (".html", ".htm"):
            text = _html(data)
        elif ext == ".rtf":
            text = _rtf(data)
        else:
            text = data.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - surface to the user rather than failing the upload
        return "", {"error": f"Could not read {ext or 'file'}: {e}"}
    text = _clean(text)
    meta["chars"] = len(text)
    meta["words"] = len(text.split())
    return text, meta
