"""Binds the runtime content pipeline's document catalogue to concrete files.

This is a *workstation* adapter, not part of the pipeline itself: it is the
one place that knows "the file the learner sees as ``f-invoice`` is the
synthetic document the content pipeline generated as ``doc-invoice...``".
:mod:`rewindsec.content` never imports this module and knows nothing about
file ids, mail ids or download mechanics -- see that package's own module
docstrings for why the two are kept apart (Architecture Spec v1.1 S37).

Three ways a file ends up bound to a document
----------------------------------------------
* A file that already exists in :data:`rewindsec.workstation.content.world
  .FILE_TREE` (:data:`_STATIC_FILE_DOCUMENTS`).
* A mail attachment, downloaded via ``mail.download_attachment`` -- the file
  id is deterministic (``f-dl-<mail_id>-<index>``), so the binding is keyed
  the same way (:data:`_MAIL_ATTACHMENT_DOCUMENTS`).
* A browser resource, downloaded via ``browser.download`` -- keyed by
  ``(url, resource_id)``, resolved to the deterministic ``f-web-...`` file id
  the same way :mod:`rewindsec.workstation.service` derives it
  (:data:`_WEB_RESOURCE_DOCUMENTS`).

A file with no entry here simply has no document -- opening it falls back to
the plain "no preview available" behaviour that predates the viewer. That is
deliberate: not every file in the world needs a structured document, and one
is never invented merely to fill this table in.
"""

from rewindsec.content.catalog import DOCUMENT_BY_ID, _STATIC_BINDINGS
from rewindsec.workstation.content import index as ix

__all__ = ["document_for_file"]

_STATIC_FILE_DOCUMENTS = {
    key: value for key, value in _STATIC_BINDINGS.items()
    if not key.startswith("_")
}

#: ``mail_id`` -> document id, for the one mail attachment presently bound to
#: a structured document: the original, legitimate invoice. The rate-card
#: attachment (``m-rate-card``) is deliberately unbound -- it is the
#: ransomware lure, and opening it triggers the authored consequential
#: decision; the viewer never renders content for it (Architecture Spec v1.1
#: S54 permits the file to be *opened* as a consequential action without any
#: macro running, but does not require -- or want -- a fabricated document
#: body standing in for it).
_MAIL_ATTACHMENT_DOCUMENTS = {
    ("m-vendor-invoice", 0): _STATIC_BINDINGS["f-invoice"],
    ("m-facilities-followup", 0): _STATIC_BINDINGS["_facilities_update_memo"],
}

#: ``(url, resource_id)`` -> document id.
_WEB_RESOURCE_DOCUMENTS = {
    ("intranet.northbridge.example/it/maintenance", "res-access-guide"):
        _STATIC_BINDINGS["_access_guide"],
}


def _mail_download_file_id(mail_id, index):
    return "f-dl-%s-%d" % (mail_id, index)


def _web_download_file_id(url, resource_id):
    return "f-web-%s-%s" % (ix.url_slug(url), resource_id)


def _dynamic_bindings():
    """Resolve the deterministic download file ids once, at import time."""
    out = {}
    for (mail_id, index), document_id in _MAIL_ATTACHMENT_DOCUMENTS.items():
        out[_mail_download_file_id(mail_id, index)] = document_id
    for (url, resource_id), document_id in _WEB_RESOURCE_DOCUMENTS.items():
        out[_web_download_file_id(url, resource_id)] = document_id
    return out


_ALL_BINDINGS = dict(_STATIC_FILE_DOCUMENTS)
_ALL_BINDINGS.update(_dynamic_bindings())


def document_for_file(file_id):
    """The bound :class:`~rewindsec.content.schema.SyntheticDocument`, or ``None``."""
    document_id = _ALL_BINDINGS.get(file_id)
    if document_id is None:
        return None
    return DOCUMENT_BY_ID.get(document_id)
