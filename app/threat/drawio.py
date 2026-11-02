"""draw.io / diagrams.net XML -> data flow diagram (nodes, edges, trust boundaries).

Handles bare <mxGraphModel>, <mxfile><diagram> wrappers, <object> cells with custom properties and
compressed (deflate + base64) pages. The XML is untrusted: DTD / entity declarations are refused before
parsing, defusedxml is used when installed, and compressed pages are inflated with a size cap.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import zlib
from urllib.parse import unquote
from xml.etree.ElementTree import Element, ParseError

from .mermaid import safe_id

try:
    from defusedxml.common import DefusedXmlException
    from defusedxml.ElementTree import fromstring as _fromstring
except ImportError:  # stdlib fallback: DOCTYPE/ENTITY are rejected up front, so no entity expansion can occur
    from xml.etree.ElementTree import fromstring as _fromstring

    class DefusedXmlException(ValueError):
        pass

MAX_INFLATED = 5_000_000
STORE_STYLE = re.compile(r"cylinder|datastore|database|datastorage|shape=(?:[\w.]+\.)?(?:storage|disk|database)")
STORE_LABEL = re.compile(r"\b(db|database|data ?store|store|cache|queue|bucket|s3|blob|redis|postgres\w*|mysql|"
                         r"dynamo\w*|mongo\w*|table|warehouse|lake|index|vector|kafka|topic)\b", re.I)
ACTOR_STYLE = re.compile(r"umlactor|shape=actor|person|user")
ACTOR_LABEL = re.compile(r"\b(user|users|customer|client|browser|actor|admin|operator|partner|third[- ]party|"
                         r"external|attacker|public|internet|end user)\b", re.I)
PROTOCOL = re.compile(r"\b(HTTPS|HTTP|gRPC|mTLS|TLS|SQL|JDBC|ODBC|AMQP|MQTT|SMTP|SFTP|FTP|SSH|WebSockets?|WSS|"
                      r"REST|GraphQL|TCP|UDP|LDAPS?|Kafka|SOAP|OIDC|SAML)\b", re.I)


class DiagramError(ValueError):
    pass


def _parse(text: str) -> Element:
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise DiagramError("XML with DOCTYPE or entity declarations is not accepted")
    try:
        return _fromstring(text)
    except (ParseError, DefusedXmlException) as e:
        raise DiagramError(f"Not a valid draw.io XML file: {e}") from e


def _inflate(payload: str) -> str:
    d = zlib.decompressobj(-15)
    raw = d.decompress(base64.b64decode(payload), MAX_INFLATED)
    if d.unconsumed_tail:
        raise DiagramError("Compressed diagram is too large")
    return unquote(raw.decode("utf-8"))


def _graph_model(root: Element) -> Element | None:
    if root.tag == "mxGraphModel":
        return root
    for d in root.iter("diagram"):
        model = d.find(".//mxGraphModel")
        if model is None and (d.text or "").strip():
            try:
                sub = _parse(_inflate(d.text.strip()))
            except (binascii.Error, zlib.error, UnicodeDecodeError, ValueError):
                continue
            model = sub if sub.tag == "mxGraphModel" else sub.find(".//mxGraphModel")
        if model is not None:
            return model
    return root.find(".//mxGraphModel")


def _text(value: str | None) -> str:
    v = re.sub(r"<br\s*/?>", " ", value or "", flags=re.I)
    v = html.unescape(re.sub(r"<[^>]+>", " ", v))
    return re.sub(r"\s+", " ", v).strip()


def _geom(cell: Element) -> tuple[float, float, float, float] | None:
    g = cell.find("mxGeometry")
    if g is None:
        return None
    try:
        return (float(g.get("x", 0)), float(g.get("y", 0)), float(g.get("width", 0)), float(g.get("height", 0)))
    except ValueError:
        return None


def parse_drawio(xml: str) -> dict:
    """Return {"nodes", "edges", "trust_boundaries"} in the data flow diagram shape. Raises DiagramError."""
    model = _graph_model(_parse(xml.strip()))
    if model is None:
        raise DiagramError("No draw.io diagram (mxGraphModel) found in the file")
    cells = []
    for el in model.iter():
        if el.tag in ("object", "UserObject") and el.find("mxCell") is not None:
            cells.append((el.get("id") or "", _text(el.get("label") or el.get("value")), el.find("mxCell")))
        elif el.tag == "mxCell" and el.get("id"):
            cells.append((el.get("id"), _text(el.get("value")), el))
    vertices = {cid: (lbl, c) for cid, lbl, c in cells if c.get("vertex") == "1" and cid not in ("0", "1")}
    child_count: dict[str, int] = {}
    for _, (_, c) in vertices.items():
        child_count[c.get("parent", "")] = child_count.get(c.get("parent", ""), 0) + 1
    groups = {cid for cid, (_, c) in vertices.items()
              if cid in child_count or re.search(r"swimlane|container=1|^group", (c.get("style") or "").lower())}
    # Dashed rectangles drawn around nodes (without being their parent) are trust boundaries too.
    contained: dict[str, list[str]] = {}
    for gid, (_, gc) in vertices.items():
        if "dashed=1" not in (gc.get("style") or "").lower() or gid in groups:
            continue
        box = _geom(gc)
        if not box or not box[2] or not box[3]:
            continue
        inside = []
        for vid, (_, vc) in vertices.items():
            vb = _geom(vc)
            if vid == gid or not vb or vc.get("parent") != gc.get("parent"):
                continue
            cx, cy = vb[0] + vb[2] / 2, vb[1] + vb[3] / 2
            if box[0] <= cx <= box[0] + box[2] and box[1] <= cy <= box[1] + box[3]:
                inside.append(vid)
        if inside:
            contained[gid] = inside
    ids: dict[str, str] = {}
    nodes = []
    for cid, (lbl, c) in vertices.items():
        if cid in groups or cid in contained or not lbl:
            continue
        style = (c.get("style") or "").lower()
        typ = ("data_store" if STORE_STYLE.search(style) or STORE_LABEL.search(lbl) else
               "external_entity" if ACTOR_STYLE.search(style) or ACTOR_LABEL.search(lbl) else "process")
        nid = safe_id(cid, f"n{len(nodes) + 1}")
        while nid in ids.values():
            nid = f"{nid}_{len(nodes) + 1}"
        ids[cid] = nid
        nodes.append({"id": nid, "label": lbl, "type": typ})
    edges = []
    for cid, lbl, c in cells:
        if c.get("edge") != "1":
            continue
        src, dst = ids.get(c.get("source", "")), ids.get(c.get("target", ""))
        if src and dst:
            m = PROTOCOL.search(lbl)
            edges.append({"from": src, "to": dst, "label": lbl, "protocol": m.group(1) if m else ""})
    boundaries = []
    for gid in list(groups) + list(contained):
        name = vertices[gid][0]
        members = contained.get(gid) or [cid for cid, (_, c) in vertices.items() if c.get("parent") == gid]
        node_ids = [ids[m] for m in members if m in ids]
        if name and node_ids:
            boundaries.append({"id": safe_id(gid, f"tb{len(boundaries) + 1}"), "name": name, "node_ids": node_ids})
    if not nodes:
        raise DiagramError("The diagram has no labelled shapes")
    return {"nodes": nodes, "edges": edges, "trust_boundaries": boundaries}
