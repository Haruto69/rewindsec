"""Deterministic synthetic generation from archetypes.

Architecture Spec v1.1 (Batch 4) S43, S45: generation must be deterministic
from a session's own named RNG stream (``content_variation``), must not use
an LLM or any external/network call at runtime, and generated content needs
a stable id derived from session identity, archetype and occurrence number --
never Python's ``hash()``.

This module is pure and offline: it takes a
:class:`~rewindsec.core.rng.RandomStream` the caller already owns (this
package never constructs its own randomness or reaches into a session
itself, so it cannot perturb any other stream) and a small set of authored
variant templates, and returns a deterministically chosen variant plus a
stable id.

Two callers use this
---------------------
:mod:`rewindsec.content.catalog` calls it with a fixed, non-session
"catalogue" stream to build the small set of static synthetic documents the
document viewer serves (these are part of the shared authored world, exactly
like the rest of :mod:`rewindsec.workstation.content`, and so are
deliberately *not* re-randomized per session -- see the Batch 4 completion
report). The functions here are nonetheless genuinely session-stream-shaped
and independently tested for determinism, so a future batch that wants
per-session mail/message variety can call them with a real session's
``content_variation`` stream with no redesign.
"""

import hashlib

__all__ = ["derive_content_id", "choose_variant", "GenerationError"]

_CONTENT_ID_LABEL = "rewindsec2/content-generation-id/v1"


class GenerationError(ValueError):
    """Generation was asked to do something it cannot do deterministically."""


def derive_content_id(session_identity, archetype_id, occurrence, version=1):
    """A stable id for one piece of generated content.

    Derived from ``(session_identity, archetype_id, occurrence, version)`` by
    SHA-256, exactly the scheme the domain layer already uses for action and
    event ids (see ``rewindsec.domain.identifiers.derive_id``) -- never
    ``hash()``, which CPython salts per process and would make two runs of
    the same session disagree about a generated item's identity.
    """
    if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 0:
        raise GenerationError("occurrence must be a non-negative int")
    material = "%s|%s|%s|%d|%d" % (
        _CONTENT_ID_LABEL, session_identity, archetype_id, occurrence, version)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def choose_variant(stream, variants):
    """Deterministically choose one of *variants* using *stream*.

    ``variants`` must be a non-empty, already-sorted sequence (callers own
    ordering -- this function never sorts, so it can never silently reorder
    a caller's authored list based on incidental dict iteration order).
    Exactly one draw from *stream*, so calling this once per generated item
    keeps the number of draws proportional to the number of items generated,
    not to the size of the variant pool.
    """
    if not variants:
        raise GenerationError("no variants to choose from")
    index = stream.randrange(len(variants))
    return variants[index]
