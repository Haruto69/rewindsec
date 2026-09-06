"""Version identifiers for the scoring subsystem.

Architecture Spec v1.1 (Batch 4) requires that a completed run always be able
to say which rubric version scored it, which evidence-model version produced
its evidence, and which result schema the stored artifact follows -- and that
changing scoring semantics in the future must never silently change a
historical completed session's score.

Three identifiers, each bumped independently and only when its own semantics
actually change:

``EVIDENCE_MODEL_VERSION``
    The shape and derivation of :class:`~rewindsec.scoring.evidence.Evidence`
    items -- what counts as an evidence item, how its id is derived, what
    fields it carries. Bump this if the evidence schema itself changes.

``RUBRIC_VERSION``
    The authored policy in :mod:`~rewindsec.scoring.rubric` -- dimension
    weights, valence rules, applicability rules. Bump this if scoring
    *outcomes* could change for an identical evidence graph.

``SCORING_VERSION``
    The overall scoring engine: how evidence and the rubric are combined into
    a :class:`~rewindsec.scoring.result.ScoringResult`. Bump this if the
    aggregation or result shape changes independently of the rubric.

A session is stamped with all three at creation (see
:mod:`rewindsec.scoring.state`). A session created before this module existed
carries none of them, which is exactly how legacy detection works: no stamp,
no real score, ever -- regardless of when the session happens to complete.
"""

__all__ = ["EVIDENCE_MODEL_VERSION", "RUBRIC_VERSION", "SCORING_VERSION",
           "RESULT_SCHEMA_VERSION"]

EVIDENCE_MODEL_VERSION = "rewindsec-evidence-model/v1"
RUBRIC_VERSION = "rewindsec-rubric/v1"
SCORING_VERSION = "rewindsec-scoring/v1"

#: The shape of :meth:`~rewindsec.scoring.result.ScoringResult.to_state`.
#: Independent of the three semantic versions above: this one governs only
#: whether old *persisted JSON* can still be parsed by the current code.
RESULT_SCHEMA_VERSION = 1
