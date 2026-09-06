"""Convert a reviewed, sanitized source reference into the stable internal
feature schema the archetype/generation stages consume.

Architecture Spec v1.1 (Batch 4) S41: normalized features, not raw source
text. This module fails closed exactly like :mod:`rewindsec.content.sanitize`
-- an unreviewed or unsanitized provenance record is refused outright, never
"normalized anyway and flagged".
"""

from rewindsec.content.provenance import get as get_provenance
from rewindsec.content.sanitize import SanitizationError, sanitize_record

__all__ = ["NormalizationError", "NormalizedFeatures", "normalize_mail_feature",
           "normalize_mfa_feature", "normalize_document_feature"]

_MAIL_FIELDS = frozenset({
    "communication_purpose", "sender_role", "urgency", "requested_action_type",
    "link_present", "attachment_present", "identity_mismatch_archetype",
    "financial_change_archetype",
})
_MFA_FIELDS = frozenset({"app_context", "expected", "device_class", "location_class"})
_DOCUMENT_FIELDS = frozenset({
    "document_kind", "operational_context", "sensitivity",
})


class NormalizationError(ValueError):
    """A source could not be normalized -- unreviewed, unsanitized, or malformed."""


class NormalizedFeatures(object):
    """A stable, JSON-safe bag of normalized features tied to its provenance."""

    __slots__ = ("provenance_id", "feature_kind", "fields")

    def __init__(self, provenance_id, feature_kind, fields):
        self.provenance_id = provenance_id
        self.feature_kind = feature_kind
        self.fields = dict(fields)

    def to_state(self):
        return {"provenance_id": self.provenance_id,
                "feature_kind": self.feature_kind, "fields": dict(self.fields)}


def _require_generatable(provenance_id):
    record = get_provenance(provenance_id)
    if record is None:
        raise NormalizationError("unknown provenance id %r" % (provenance_id,))
    if not record.may_generate:
        raise NormalizationError(
            "source %r is not reviewed/sanitized for generation" % (provenance_id,))
    return record


def _normalize(provenance_id, feature_kind, allowed_fields, fields):
    _require_generatable(provenance_id)
    try:
        clean = sanitize_record(fields, allowed_fields)
    except SanitizationError as exc:
        raise NormalizationError(str(exc)) from exc
    return NormalizedFeatures(provenance_id, feature_kind, clean)


def normalize_mail_feature(provenance_id, **fields):
    return _normalize(provenance_id, "mail", _MAIL_FIELDS, fields)


def normalize_mfa_feature(provenance_id, **fields):
    return _normalize(provenance_id, "mfa", _MFA_FIELDS, fields)


def normalize_document_feature(provenance_id, **fields):
    return _normalize(provenance_id, "document", _DOCUMENT_FIELDS, fields)
