"""The structured synthetic document schema.

Deliberately not a document format. There is no parser for anything here:
a :class:`SyntheticDocument` is plain, server-owned structured data -- a
title, a kind, and an ordered list of blocks -- that the workstation's
document viewer renders with safe DOM construction (``textContent``, never
``innerHTML``) and nothing else. See Architecture Spec v1.1 (Batch 4) S48-S53.

Every block is one of a small closed vocabulary:

``paragraph``      {"text": str}
``heading``         {"text": str, "level": 1|2|3}
``key_value``       {"pairs": [[label, value], ...]}
``table``           {"headers": [str, ...], "rows": [[str, ...], ...]}
``list``            {"items": [str, ...]}

No block type carries HTML, a URL to fetch, a script, or a macro. A value
that looks like markup is still just a string a renderer must display as
literal text -- see :mod:`rewindsec.content.sanitize` for what is rejected
before it ever reaches this schema.
"""

from rewindsec.content.sanitize import SanitizationError, sanitize_text

__all__ = ["SyntheticDocument", "DocumentSchemaError", "BLOCK_TYPES",
           "paragraph", "heading", "key_value", "table", "doc_list"]

BLOCK_TYPES = frozenset({"paragraph", "heading", "key_value", "table", "list"})

_MAX_BLOCKS = 64
_MAX_TITLE = 160
_MAX_TEXT = 2000
_MAX_ROWS = 64
_MAX_COLUMNS = 12
_MAX_ITEMS = 64
_DOCUMENT_KINDS = frozenset({
    "memo", "invoice", "report", "spreadsheet", "pdf_page", "plain_text",
})


class DocumentSchemaError(ValueError):
    """A document or one of its blocks does not satisfy the schema."""


def _text(value, max_length=_MAX_TEXT):
    try:
        return sanitize_text(value, max_length=max_length)
    except SanitizationError as exc:
        raise DocumentSchemaError(str(exc)) from exc


def paragraph(text):
    return {"type": "paragraph", "text": _text(text)}


def heading(text, level=2):
    if level not in (1, 2, 3):
        raise DocumentSchemaError("heading level must be 1, 2 or 3")
    return {"type": "heading", "text": _text(text, max_length=200), "level": level}


def key_value(pairs):
    out = []
    for label, value in pairs:
        out.append([_text(label, max_length=120), _text(str(value), max_length=300)])
    return {"type": "key_value", "pairs": out}


def table(headers, rows):
    if len(headers) > _MAX_COLUMNS:
        raise DocumentSchemaError("table has too many columns")
    if len(rows) > _MAX_ROWS:
        raise DocumentSchemaError("table has too many rows")
    safe_headers = [_text(h, max_length=80) for h in headers]
    safe_rows = []
    for row in rows:
        if len(row) != len(headers):
            raise DocumentSchemaError("table row length does not match headers")
        safe_rows.append([_text(str(cell), max_length=200) for cell in row])
    return {"type": "table", "headers": safe_headers, "rows": safe_rows}


def doc_list(items):
    if len(items) > _MAX_ITEMS:
        raise DocumentSchemaError("list has too many items")
    return {"type": "list", "items": [_text(item, max_length=300) for item in items]}


class SyntheticDocument(object):
    """One complete, server-owned structured document.

    ``document_id`` is stable and content-derived (see
    :mod:`rewindsec.content.generate`), never a random or a host-filesystem
    path. ``kind`` is presentation context only -- it never triggers a real
    parser or application.
    """

    __slots__ = ("document_id", "title", "kind", "blocks", "provenance_id")

    def __init__(self, document_id, title, kind, blocks, provenance_id):
        if not document_id or not isinstance(document_id, str):
            raise DocumentSchemaError("document_id must be a non-empty string")
        if kind not in _DOCUMENT_KINDS:
            raise DocumentSchemaError("unknown document kind %r" % (kind,))
        if len(blocks) > _MAX_BLOCKS:
            raise DocumentSchemaError("document has too many blocks")
        for block in blocks:
            if not isinstance(block, dict) or block.get("type") not in BLOCK_TYPES:
                raise DocumentSchemaError("unrecognised document block: %r" % (block,))
        self.document_id = document_id
        self.title = _text(title, max_length=_MAX_TITLE)
        self.kind = kind
        self.blocks = list(blocks)
        self.provenance_id = provenance_id

    def to_projection(self):
        """The safe, complete learner-facing projection.

        No hidden metadata of any kind: no provenance id, no archetype id, no
        threat classification. Everything here is legitimate visible document
        content -- exactly what Architecture Spec v1.1 S51 permits.
        """
        return {
            "document_id": self.document_id,
            "title": self.title,
            "kind": self.kind,
            "blocks": [dict(block) for block in self.blocks],
        }
