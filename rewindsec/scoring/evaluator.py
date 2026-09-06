"""Turns one session's Evidence Graph into a deterministic six-dimension result.

Pure Python: no Flask, no SQLAlchemy, no UI imports, no randomness and no
wall clock. The only inputs are the session's own factual history (via
:mod:`rewindsec.scoring.evidence`) and the authored policy in
:mod:`rewindsec.scoring.rubric`.
"""

from rewindsec.scoring import rubric
from rewindsec.scoring.dimensions import DIMENSION_IDS
from rewindsec.scoring.evidence import build_evidence
from rewindsec.scoring.result import DimensionResult, ScoringResult

__all__ = ["evaluate"]


def _round_half_away_from_zero(numerator, denominator):
    """Deterministic integer rounding of ``numerator / denominator``.

    Ordinary Python integer floor division rounds toward negative infinity,
    which is not what "round to nearest" means for a negative numerator; this
    rounds to the nearest integer, ties away from zero, using only integer
    arithmetic so the result is identical on every machine and Python build.
    """
    if denominator == 0:
        return 0
    sign = 1 if numerator >= 0 else -1
    numerator = abs(numerator)
    return sign * ((2 * numerator + denominator) // (2 * denominator))


def _score_dimension(items):
    """``0..100`` from a nonempty list of same-dimension evidence items.

    A neutral 50 sits at the centre; the weighted sum of valence*weight,
    normalized by the total weight, moves the score toward 0 (every item
    negative) or 100 (every item positive). No evidence at all for an
    otherwise-applicable dimension is scored 50: an authored, documented
    policy decision that "nothing happened here" is neutral, not a failure --
    see the Batch 4 completion report for the rationale.
    """
    if not items:
        return 50
    weighted_sum = sum(item.valence * item.weight for item in items)
    total_weight = sum(item.weight for item in items)
    if total_weight <= 0:
        return 50
    delta = _round_half_away_from_zero(50 * weighted_sum, total_weight)
    return max(0, min(100, 50 + delta))


def evaluate(session):
    """Score one session. Deterministic: same session state, same result.

    Does not persist anything -- see :mod:`rewindsec.scoring.state` for the
    finalize-once, immutable-after persistence contract. Safe to call on an
    active session for internal/dev inspection, but the product only ever
    calls it once, at session completion.
    """
    evidence = build_evidence(session)
    by_dimension = {dim: [] for dim in DIMENSION_IDS}
    for item in evidence:
        by_dimension.setdefault(item.dimension, []).append(item)

    applicability = rubric.applicability(session)

    dimensions = {}
    for dim in DIMENSION_IDS:
        applicable, na_reason = applicability[dim]
        items = by_dimension.get(dim, [])
        if not applicable:
            dimensions[dim] = DimensionResult(
                dimension_id=dim, applicable=False, score=None,
                na_reason=na_reason, evidence_ids=(), explanations=())
            continue
        score = _score_dimension(items)
        explanations = [
            (item.explanation_code, item.explanation_text,
             "positive" if item.valence > 0 else
             "negative" if item.valence < 0 else "neutral")
            for item in sorted(items, key=lambda i: (i.sim_time_ms, i.evidence_id))]
        dimensions[dim] = DimensionResult(
            dimension_id=dim, applicable=True, score=score, na_reason=None,
            evidence_ids=tuple(sorted(i.evidence_id for i in items)),
            explanations=explanations)

    applicable_scores = [dimensions[d].score for d in DIMENSION_IDS
                         if dimensions[d].applicable]
    overall = (None if not applicable_scores else
              max(0, min(100, _round_half_away_from_zero(
                  sum(applicable_scores), len(applicable_scores)))))

    return ScoringResult(
        session_id=session.session_id, focus=session.focus.value,
        mode=session.mode.value, overall=overall, dimensions=dimensions,
        evidence_count=len(evidence),
        opportunity_count=sum(1 for d in DIMENSION_IDS if dimensions[d].applicable))
