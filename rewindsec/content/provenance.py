"""Machine-readable provenance for everything that enters the content pipeline.

Architecture Spec v1.1 (Batch 4) S38-S39: no raw external row may feed
runtime content directly, and every source/reference needs explicit,
machine-readable provenance metadata -- origin, license/review status,
limitations. This module is that record.

No external dataset is used
----------------------------
RewindSec 2.0's runtime content does not currently draw on any external
phishing/security corpus. Every :class:`ProvenanceRecord` below is marked
``origin="internally_authored_synthetic"`` and ``review_status="reviewed"``:
these are references this project wrote for itself, in the same register as
the rest of the authored workplace content in
:mod:`rewindsec.workstation.content.world`, not material recovered from a
public research dataset and relabelled. That is a deliberate, documented
choice (S38): importing an unreviewed real corpus merely to say the pipeline
exists would be worse than not having one.
"""

__all__ = ["ProvenanceRecord", "SOURCES", "get", "all_sources",
           "REVIEW_REVIEWED", "REVIEW_UNREVIEWED", "SANITIZED", "UNSANITIZED"]

REVIEW_REVIEWED = "reviewed"
REVIEW_UNREVIEWED = "unreviewed"
SANITIZED = "sanitized"
UNSANITIZED = "unsanitized"

_ORIGIN_INTERNAL = "internally_authored_synthetic"

_ALLOWED_USES = frozenset({"generation", "reference_only"})


class ProvenanceRecord(object):
    """One machine-readable provenance entry.

    ``checksum`` is only meaningful for a concrete local artifact (a file);
    every source here is an inline, internally authored text record, so it is
    ``None`` -- there is no separate file whose integrity needs pinning.
    """

    __slots__ = ("source_id", "title", "source_type", "origin", "version",
                 "license_status", "allowed_use", "checksum", "review_status",
                 "sanitization_status", "limitations")

    def __init__(self, source_id, title, source_type, version, allowed_use,
                 limitations, license_status="not_applicable_internal_authorship",
                 origin=_ORIGIN_INTERNAL, checksum=None,
                 review_status=REVIEW_REVIEWED, sanitization_status=SANITIZED):
        if allowed_use not in _ALLOWED_USES:
            raise ValueError("allowed_use must be one of %s" % sorted(_ALLOWED_USES))
        self.source_id = source_id
        self.title = title
        self.source_type = source_type
        self.origin = origin
        self.version = version
        self.license_status = license_status
        self.allowed_use = allowed_use
        self.checksum = checksum
        self.review_status = review_status
        self.sanitization_status = sanitization_status
        self.limitations = tuple(limitations)

    @property
    def is_reviewed(self):
        return self.review_status == REVIEW_REVIEWED

    @property
    def is_sanitized(self):
        return self.sanitization_status == SANITIZED

    @property
    def may_generate(self):
        """Whether generation may draw on this source at all.

        Both gates are required: an unreviewed *or* unsanitized source can
        never reach :mod:`rewindsec.content.generate`, no matter how it is
        marked otherwise -- S75 asserts this directly.
        """
        return self.is_reviewed and self.is_sanitized and self.allowed_use == "generation"

    def to_state(self):
        return {
            "source_id": self.source_id, "title": self.title,
            "source_type": self.source_type, "origin": self.origin,
            "version": self.version, "license_status": self.license_status,
            "allowed_use": self.allowed_use, "checksum": self.checksum,
            "review_status": self.review_status,
            "sanitization_status": self.sanitization_status,
            "limitations": list(self.limitations),
        }


#: Every source/reference the content pipeline is allowed to generate from.
#: All internally authored synthetic references -- see the module docstring.
SOURCES = {
    "src-mail-archetypes-v1": ProvenanceRecord(
        source_id="src-mail-archetypes-v1",
        title="Internally authored workplace-mail archetype set",
        source_type="archetype_reference", version="2026-09",
        allowed_use="generation",
        limitations=("Covers phishing, BEC, and ordinary workplace-mail "
                    "archetypes only; not derived from any real message.",)),
    "src-mfa-archetypes-v1": ProvenanceRecord(
        source_id="src-mfa-archetypes-v1",
        title="Internally authored MFA-prompt archetype set",
        source_type="archetype_reference", version="2026-09",
        allowed_use="generation",
        limitations=("Covers unsolicited-approval and legitimate-reauthentication "
                    "archetypes only.",)),
    "src-ransomware-lure-archetypes-v1": ProvenanceRecord(
        source_id="src-ransomware-lure-archetypes-v1",
        title="Internally authored attachment/download lure archetype set",
        source_type="archetype_reference", version="2026-09",
        allowed_use="generation",
        limitations=("Describes lure *shape* (attachment/download context) "
                    "only; carries no executable content of any kind.",)),
    "src-document-archetypes-v1": ProvenanceRecord(
        source_id="src-document-archetypes-v1",
        title="Internally authored synthetic workplace-document archetype set",
        source_type="archetype_reference", version="2026-09",
        allowed_use="generation",
        limitations=("Structured document shapes (memo, invoice, report, "
                    "spreadsheet-like table) only; no real organisation's "
                    "documents were consulted.",)),
}


def get(source_id):
    return SOURCES.get(source_id)


def all_sources():
    return tuple(SOURCES[key] for key in sorted(SOURCES))
