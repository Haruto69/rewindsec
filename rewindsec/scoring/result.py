"""The reproducible, JSON-safe scoring result artifact.

This is authored system logic, not a claim about human competence. The
rubric it comes from does not measure real cybersecurity competence, does not
predict workplace behaviour, does not prove learning, does not measure
retention or transfer, and has not been psychometrically validated. It may
be reported as "RewindSec scoring rubric v1 produced this result" and never
as "the learner is objectively N% competent". Any claim about human learning,
retention or transfer requires human research data this system does not
collect.
"""

from rewindsec.scoring.dimensions import (DIMENSION_DESCRIPTIONS,
                                          DIMENSION_IDS, DIMENSION_LABELS)
from rewindsec.scoring.versions import (EVIDENCE_MODEL_VERSION, RESULT_SCHEMA_VERSION,
                                        RUBRIC_VERSION, SCORING_VERSION)

__all__ = ["DimensionResult", "ScoringResult", "COMPETENCE_DISCLAIMER"]

COMPETENCE_DISCLAIMER = (
    "RewindSec scoring rubric v1 produced this result from this session's "
    "own recorded decisions and evidence. It is an authored implementation "
    "policy, not a validated measure of security competence, and it does "
    "not predict workplace behaviour, prove learning, or measure retention "
    "or transfer.")


class DimensionResult(object):
    """One dimension's outcome: a score, or an explicit reason it is N/A."""

    __slots__ = ("dimension_id", "applicable", "score", "na_reason",
                 "evidence_ids", "explanations")

    def __init__(self, dimension_id, applicable, score, na_reason,
                 evidence_ids, explanations):
        self.dimension_id = dimension_id
        self.applicable = applicable
        #: ``None`` unless ``applicable``. Never ``0``/``100`` as a stand-in
        #: for N/A -- callers must check ``applicable`` first.
        self.score = score
        self.na_reason = na_reason
        self.evidence_ids = tuple(evidence_ids)
        #: ``[(explanation_code, explanation_text, valence)]``, ordered by
        #: simulation time then evidence id -- deterministic, never by
        #: dict/set iteration order.
        self.explanations = tuple(explanations)

    def to_state(self):
        return {
            "dimension_id": self.dimension_id,
            "label": DIMENSION_LABELS[self.dimension_id],
            "description": DIMENSION_DESCRIPTIONS[self.dimension_id],
            "applicable": self.applicable,
            "score": self.score,
            "na_reason": self.na_reason,
            "evidence_ids": list(self.evidence_ids),
            "explanations": [
                {"code": code, "text": text, "valence": valence}
                for code, text, valence in self.explanations],
        }

    def to_learner_view(self):
        """The permitted learner-facing projection: no internal ids, no weights."""
        return {
            "id": self.dimension_id,
            "label": DIMENSION_LABELS[self.dimension_id],
            "description": DIMENSION_DESCRIPTIONS[self.dimension_id],
            "applicable": self.applicable,
            "score": self.score,
            "na_reason": self.na_reason,
            "evidence": [{"text": text, "direction": valence}
                        for _, text, valence in self.explanations],
        }


class ScoringResult(object):
    """The immutable, reproducible result of scoring one completed session."""

    __slots__ = ("session_id", "focus", "mode", "overall", "dimensions",
                 "evidence_count", "opportunity_count")

    def __init__(self, session_id, focus, mode, overall, dimensions,
                 evidence_count, opportunity_count):
        self.session_id = session_id
        self.focus = focus
        self.mode = mode
        #: ``None`` only when every dimension is N/A.
        self.overall = overall
        #: ``{dimension_id: DimensionResult}``.
        self.dimensions = dict(dimensions)
        self.evidence_count = evidence_count
        self.opportunity_count = opportunity_count

    def to_state(self):
        """The full internal artifact. May carry more provenance than the
        learner ever sees -- see :meth:`to_learner_view` for that boundary."""
        return {
            "result_schema_version": RESULT_SCHEMA_VERSION,
            "scoring_version": SCORING_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "evidence_model_version": EVIDENCE_MODEL_VERSION,
            "session_id": self.session_id,
            "focus": self.focus,
            "mode": self.mode,
            "overall": self.overall,
            "dimensions": {dim: self.dimensions[dim].to_state()
                          for dim in DIMENSION_IDS if dim in self.dimensions},
            "evidence_count": self.evidence_count,
            "opportunity_count": self.opportunity_count,
        }

    @classmethod
    def from_state(cls, state):
        dims = {}
        for dim_id, payload in (state.get("dimensions") or {}).items():
            dims[dim_id] = DimensionResult(
                dimension_id=dim_id, applicable=payload["applicable"],
                score=payload["score"], na_reason=payload["na_reason"],
                evidence_ids=payload["evidence_ids"],
                explanations=[(e["code"], e["text"], e["valence"])
                             for e in payload["explanations"]])
        return cls(session_id=state.get("session_id"), focus=state.get("focus"),
                   mode=state.get("mode"), overall=state.get("overall"),
                   dimensions=dims, evidence_count=state.get("evidence_count", 0),
                   opportunity_count=state.get("opportunity_count", 0))

    def to_learner_view(self):
        """The permitted learner/debrief projection.

        No evidence ids, no weights, no opportunity classes, no hidden
        candidate metadata -- only what Architecture Spec v1.1 S31 and S62
        allow a results page to show: the overall figure, the six dimensions,
        their N/A state, and a short factual explanation per dimension.
        """
        return {
            "available": True,
            "legacy": False,
            "scoring_version": SCORING_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "evidence_model_version": EVIDENCE_MODEL_VERSION,
            "overall": self.overall,
            "dimensions": [self.dimensions[dim].to_learner_view()
                          for dim in DIMENSION_IDS if dim in self.dimensions],
            "note": COMPETENCE_DISCLAIMER,
        }


def legacy_view():
    """The learner/debrief projection for a session predating Batch 4 scoring.

    Explicit and honest rather than a silently-empty result: the session
    genuinely was never stamped with a rubric or evidence-model version, and
    its historical demo numbers -- if the old prototype presentation is still
    reachable at all -- are not RewindSec 2.0 scoring and must never be
    retroactively treated as if they were.
    """
    return {
        "available": False,
        "legacy": True,
        "scoring_version": None,
        "rubric_version": None,
        "evidence_model_version": None,
        "overall": None,
        "dimensions": [],
        "note": "Scoring unavailable for this legacy run. It was created "
                "before RewindSec 2.0's real scoring rubric existed and is "
                "not eligible for retroactive scoring.",
    }
