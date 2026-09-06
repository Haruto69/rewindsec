"""The Evidence Graph: stable, machine-readable evidence items.

Each :class:`Evidence` item traces to a factual, already-persisted session
artifact -- a decision recorded in the world, a Context Ledger fact, an
:class:`~rewindsec.scoring.opportunities.Opportunity` -- never to prose or to
UI state. Its id is derived deterministically from that provenance (the same
scheme :mod:`rewindsec.domain.identifiers` already uses: SHA-256 over a
domain-separated, delimiter-joined string), so the same session evaluated
twice produces byte-identical evidence ids, and two different facts can never
collide into the same id.

The central correction this module makes over its first cut: evidence is now
driven by :mod:`rewindsec.scoring.opportunities`, not by the decisions the
learner happened to record. Every :class:`~rewindsec.scoring.opportunities
.Opportunity` this session ever presented is walked; if a decision that
resolves it was recorded, that decision's own authored valence produces Tier
1 evidence exactly as before. If none was -- the opportunity was *ignored* --
this module now records explicit negative evidence for **every** dimension
that opportunity was relevant to, not only ``security_judgment``. That is
what keeps a hostile MFA prompt nobody touched, a contained incident nobody
went further with, or a recovery step nobody took from silently vanishing
into "no evidence, so this dimension is a neutral 50" or "no evidence, so
this dimension is N/A".

This module only *collects* evidence; it does not decide what an item is
worth. That is :mod:`rewindsec.scoring.rubric`'s job -- kept separate so the
provenance/dedup machinery here does not get tangled up with the weights.
"""

import hashlib

from rewindsec.scoring import opportunities as opp
from rewindsec.scoring import rubric
from rewindsec.scoring.versions import EVIDENCE_MODEL_VERSION
from rewindsec.management import session_link
from rewindsec.workstation.bootstrap import NS_DECISIONS
from rewindsec.workstation.content import index as ix

_evidence_fact_id = ix.evidence_fact_id
_evidence_source = ix.evidence_source

__all__ = ["Evidence", "build_evidence", "decision_records",
           "OpportunityResolution", "resolve_opportunities"]

_EVIDENCE_ID_LABEL = "rewindsec2/scoring-evidence-id/v1"


class Evidence(object):
    """One deterministic, provenance-carrying evidence item.

    Immutable and JSON-safe. ``valence`` is ``+1`` (supports the dimension),
    ``-1`` (counts against it) or ``0`` (recorded for provenance but
    contributes nothing -- unused today, reserved so a future rubric change
    can add neutral evidence without a schema change). ``weight`` is a small
    positive integer authored in :mod:`rewindsec.scoring.rubric`.
    """

    __slots__ = ("evidence_id", "dimension", "evidence_type", "opportunity_id",
                 "valence", "weight", "sim_time_ms", "source", "explanation_code",
                 "explanation_text", "dedup_key")

    def __init__(self, evidence_id, dimension, evidence_type, opportunity_id,
                 valence, weight, sim_time_ms, source, explanation_code,
                 explanation_text, dedup_key):
        self.evidence_id = evidence_id
        self.dimension = dimension
        self.evidence_type = evidence_type
        self.opportunity_id = opportunity_id
        self.valence = valence
        self.weight = weight
        self.sim_time_ms = sim_time_ms
        #: ``{"decision_id": ..., "action_id": ..., "fact_id": ..., ...}`` --
        #: whichever factual references produced this item. Never a mail id
        #: alone with no session artifact behind it.
        self.source = dict(source)
        self.explanation_code = explanation_code
        self.explanation_text = explanation_text
        self.dedup_key = dedup_key

    def to_state(self):
        return {
            "evidence_id": self.evidence_id,
            "evidence_model_version": EVIDENCE_MODEL_VERSION,
            "dimension": self.dimension,
            "evidence_type": self.evidence_type,
            "opportunity_id": self.opportunity_id,
            "valence": self.valence,
            "weight": self.weight,
            "sim_time_ms": self.sim_time_ms,
            "source": dict(self.source),
            "explanation_code": self.explanation_code,
            "explanation_text": self.explanation_text,
        }


def _make_id(*parts):
    """A stable, lowercase-hex evidence id derived from its own provenance.

    Mirrors ``rewindsec.domain.actions.derive_action_id``'s scheme (SHA-256
    over a domain-separated, delimiter-joined string) rather than
    ``rewindsec.domain.identifiers.derive_id``, because the parts here --
    decision ids, mail ids, dimension names -- are not themselves required to
    satisfy the domain's narrow *identity* charset, only to be stable strings.
    """
    material = "|".join([_EVIDENCE_ID_LABEL] + [str(part) for part in parts])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


#: Fallback explanation text for an ignored opportunity, by opportunity type.
#: Used only when no more specific text is warranted -- these are already the
#: generic case, since the specific mail/prompt/incident is named in
#: ``source``, not in the sentence.
_IGNORED_EXPLANATIONS = {
    "mail": "A message that called for a decision was delivered and none "
           "was ever recorded about it.",
    "prompt": "An approval request was raised and left unresolved.",
    "containment": "An incident occurred and no containment or response "
                   "decision was ever recorded before the session ended.",
    "recovery": "A recovery opportunity became available after containment "
               "and was never used.",
}


def _decision_records(session):
    """``{(decision_id, occurrence_key): (decision_id, record_id, state,
    definition)}`` for decisions actually recorded this session.

    Keyed by the *semantic* decision class plus whichever occurrence it was
    recorded against (``None`` for a decision this architecture has always
    treated as one-shot for the whole session) -- not by the row's own
    storage key in :data:`NS_DECISIONS`, which is an occurrence-scoped
    composite for exactly the decisions that can recur (see
    :mod:`rewindsec.workstation.consequences`). The storage key is still
    carried through as ``record_id``, though: :func:`_decision_evidence`
    needs it to keep two occurrences' evidence from colliding into the same
    id. Authored decisions with no matching definition (should not happen;
    defensive) are skipped.
    """
    rows = {}
    for record_id, state in session.world.get_component(NS_DECISIONS).items():
        decision_id = state.get("decision_class", record_id)
        definition = ix.DECISION_BY_ID.get(decision_id)
        if definition is None:
            continue
        occurrence_key = state.get("occurrence_key")
        rows[(decision_id, occurrence_key)] = (decision_id, record_id, state,
                                               definition)
    return rows


def _evidence_fraction_observed(session, kind, ref):
    items = ix.evidence_model(kind, ref)
    if not items:
        return None
    observed = 0
    for item in items:
        fact_id = _evidence_fact_id(item.get("action"))
        if fact_id and session.ledger.has(fact_id) and session.ledger.get(fact_id).observed:
            observed += 1
    return observed, len(items)


def _decision_evidence(session, decision_id, state, definition, record_id=None):
    """Tier 1 (the decision itself) and Tier 2 (evidence-use enrichment) for
    one *recorded* decision, whether or not it resolves a tracked opportunity.

    ``record_id`` is the occurrence-scoped storage key the decision was
    actually recorded under (``consequences._record_id``) -- ``decision_id``
    itself for every decision this architecture has always treated as
    one-shot, but distinct per occurrence for the handful that can now recur
    (an MFA approval, a shared-portal credential submission). Evidence ids,
    ``opportunity_id`` and ``dedup_key`` are derived from *this*, not the bare
    semantic class: two occurrences recording the same decision class would
    otherwise produce evidence that collided into the same id and the same
    ``opportunity_id`` bucket, silently merging two independent occurrences'
    evidence back together downstream of the resolution check this module
    already gets right. ``explanation_code`` still names the semantic class --
    it is prose, not an identity -- so "what kind of decision was this" stays
    readable even though "which occurrence" now lives in the id.
    """
    if record_id is None:
        record_id = decision_id
    items = []
    klass = definition.get("class")
    valence = rubric.CLASS_VALENCE.get(klass)
    dims = tuple(definition.get("dimensions") or ())
    source = {"decision_id": decision_id, "action_id": state.get("action_id"),
              "family": definition.get("family")}
    if state.get("occurrence_key") is not None:
        source["occurrence_key"] = state.get("occurrence_key")
    if valence:
        for dimension in dims:
            items.append(Evidence(
                evidence_id=_make_id("decision", record_id, dimension),
                dimension=dimension, evidence_type="decision",
                opportunity_id="decision:%s" % record_id,
                valence=valence, weight=rubric.DECISION_WEIGHT,
                sim_time_ms=state.get("at_ms", 0), source=source,
                explanation_code="decision:%s:%s" % (klass, decision_id),
                explanation_text=definition.get("label", decision_id),
                dedup_key=("decision", record_id, dimension)))

    evidence_source = _evidence_source(decision_id)
    if evidence_source is not None:
        fraction = _evidence_fraction_observed(session, *evidence_source)
        if fraction is not None:
            observed, total = fraction
            if observed * 2 >= total:
                items.append(Evidence(
                    evidence_id=_make_id("evidence_use", record_id, "observed"),
                    dimension="evidence_use", evidence_type="observation",
                    opportunity_id="decision:%s" % record_id,
                    valence=1, weight=rubric.EVIDENCE_USE_WEIGHT,
                    sim_time_ms=state.get("at_ms", 0), source=source,
                    explanation_code="evidence_observed:%s" % decision_id,
                    explanation_text="Inspected the available evidence "
                                     "before deciding.",
                    dedup_key=("evidence_use", record_id)))
            elif observed == 0:
                items.append(Evidence(
                    evidence_id=_make_id("evidence_use", record_id, "unobserved"),
                    dimension="evidence_use", evidence_type="observation",
                    opportunity_id="decision:%s" % record_id,
                    valence=-1, weight=rubric.EVIDENCE_USE_WEIGHT,
                    sim_time_ms=state.get("at_ms", 0), source=source,
                    explanation_code="evidence_unobserved:%s" % decision_id,
                    explanation_text="Decided without inspecting the "
                                     "evidence that was available.",
                    dedup_key=("evidence_use", record_id)))
    return items


def decision_records(session):
    """Public alias of :func:`_decision_records`.

    Batch 5 needs the same ``(decision_id, occurrence_key) -> record`` map
    this module already builds in order to count *scored interactions* for an
    assessment attempt, and it must be the same map -- a second, parallel
    reading of :data:`NS_DECISIONS` is exactly how two subsystems come to
    disagree about what a learner decided. Nothing about the mapping changes;
    this only gives it a name outside this module.
    """
    return _decision_records(session)


class OpportunityResolution(object):
    """One :class:`~rewindsec.scoring.opportunities.Opportunity` and whether a
    decision that resolves it was actually recorded.

    ``resolved_pair`` is the exact ``(decision_id, occurrence_key)`` pair that
    matched, or ``None`` when the opportunity was ignored. ``record_id`` is
    the occurrence-scoped storage key that decision was recorded under.
    """

    __slots__ = ("opportunity", "resolved_pair", "decision_id", "record_id",
                 "state", "definition")

    def __init__(self, opportunity, resolved_pair=None, decision_id=None,
                 record_id=None, state=None, definition=None):
        self.opportunity = opportunity
        self.resolved_pair = resolved_pair
        self.decision_id = decision_id
        self.record_id = record_id
        self.state = state
        self.definition = definition

    @property
    def resolved(self):
        return self.resolved_pair is not None


def resolve_opportunities(session):
    """Match every presented Opportunity against the decisions recorded.

    Extracted verbatim from :func:`build_evidence`, which now calls it, so
    there is exactly one implementation of "did a decision that resolves this
    occurrence actually get recorded" in the system. Batch 5's assessment
    progress reads the same answer rather than re-deriving it.

    Returns ``(resolutions, tracked_pairs, decisions)``:

    ``resolutions``
        One :class:`OpportunityResolution` per presented opportunity, in the
        opportunity model's own deterministic order. An ignored opportunity is
        present and unresolved -- it never disappears.
    ``tracked_pairs``
        Every ``(decision_id, occurrence_key)`` pair consulted, whether or not
        it matched. :func:`build_evidence` uses it to tell an ordinary
        operational decision apart from one that belongs to an opportunity.
    ``decisions``
        The :func:`decision_records` map the matching ran against.

    Pure: reads the session's world, consumes no randomness, advances no
    clock and persists nothing.

    For an Assessment carrying an exact v2 completion boundary, only the
    boundary's N admitted ``(opportunity_id, decision_record_id)`` pairs may
    resolve. A decision recorded later against an already-visible opportunity
    remains in factual history but cannot become N+1. Non-Assessment and
    pre-boundary sessions retain the ordinary Batch 4 behaviour. The final
    evidence-set filter is applied by :func:`build_evidence`, because an
    unadmitted opportunity must contribute neither decision evidence nor
    ``ignored`` evidence to the bounded result.
    """
    decisions = _decision_records(session)
    opportunities = opp.build_opportunities(session)
    admitted = session_link.admitted_scored_resolutions(session)

    tracked_pairs = set()
    # A fallback (unscoped) match is consumed the first time it resolves an
    # opportunity -- otherwise one unscoped record could "resolve" every
    # occurrence that shares its decision class, which is exactly the
    # double-counting occurrence scoping exists to prevent. An exact scoped
    # match never needs this: two occurrences never share a
    # ``(decision_id, occurrence_key)`` pair in the first place.
    consumed = set()
    resolutions = []
    for opportunity in opportunities:
        candidates = [(d, opportunity.occurrence_key)
                     for d in opportunity.resolving_decisions]
        if opportunity.occurrence_key is not None:
            # A decision recorded before occurrence scoping existed for its
            # class (or one whose class never needed it, e.g. a report/reply
            # decision that already carries its own occurrence in its id) is
            # still stored unscoped -- fall back to the bare class so those
            # keep resolving exactly the one opportunity they always did.
            candidates.extend((d, None) for d in opportunity.resolving_decisions)
        tracked_pairs.update(candidates)

        if admitted is None:
            resolved = next((pair for pair in candidates
                             if pair in decisions and pair not in consumed),
                            None)
        else:
            admitted_record_id = admitted.get(opportunity.opportunity_id)
            resolved = next((pair for pair in candidates
                             if pair in decisions and pair not in consumed
                             and decisions[pair][1] == admitted_record_id),
                            None)
        if resolved is None:
            resolutions.append(OpportunityResolution(opportunity))
            continue
        consumed.add(resolved)
        decision_id, record_id, state, definition = decisions[resolved]
        resolutions.append(OpportunityResolution(
            opportunity, resolved_pair=resolved, decision_id=decision_id,
            record_id=record_id, state=state, definition=definition))

    return tuple(resolutions), tracked_pairs, decisions


def build_evidence(session):
    """Derive the whole Evidence Graph for one (usually completed) session.

    Walks every :class:`~rewindsec.scoring.opportunities.Opportunity` this
    session ever presented, read from the world's own immutable mutation
    history (see :mod:`rewindsec.scoring.opportunities`) -- never live
    component state, so an opportunity a later action deleted, resolved or
    recovered still counts exactly as it did the moment it was presented. A
    resolved opportunity (a decision that answers it was recorded)
    contributes that decision's own Tier 1/2 evidence, exactly as authored.
    An *ignored* opportunity -- no
    such decision was ever recorded, whether because nothing was clicked or
    because the learner did something else entirely -- contributes explicit
    Tier 3 negative evidence for every dimension the opportunity was relevant
    to. This is what makes "the learner never touched it" and "there was
    nothing to touch" two different, distinguishable outcomes, instead of
    both quietly producing no evidence at all.

    Decisions that do not belong to any tracked opportunity (ordinary
    operational decisions such as answering a headcount request, or
    containment's own operational-cost twin ``d-isolate-no-incident``) still
    contribute their authored evidence unconditionally -- opportunity
    tracking narrows how *ignoring something* is scored, it does not narrow
    what counts as evidence when something *was* decided.

    Pure: reads the session's world and ledger and returns a tuple of
    :class:`Evidence`. Consumes no randomness, advances no clock, and calling
    it twice on the same session state returns identical items in identical
    order.
    """
    items = []
    resolutions, tracked_pairs, decisions = resolve_opportunities(session)
    admitted = session_link.admitted_scored_resolutions(session)

    for resolution in resolutions:
        opportunity = resolution.opportunity
        # The v2 boundary is the attempt's complete scoreable set, not merely
        # an allow-list of positive decisions. An already-visible unrelated
        # opportunity therefore contributes neither a late decision nor an
        # ``ignored opportunity`` penalty. Its delivery and any later action
        # remain in the immutable session history; they are simply outside
        # the N interactions this Assessment definition asked to score.
        if (admitted is not None
                and opportunity.opportunity_id not in admitted):
            continue
        if resolution.resolved:
            items.extend(_decision_evidence(
                session, resolution.decision_id, resolution.state,
                resolution.definition, record_id=resolution.record_id))
            continue

        for dimension in opportunity.dimensions:
            items.append(Evidence(
                evidence_id=_make_id("ignored", opportunity.opportunity_id, dimension),
                dimension=dimension, evidence_type="inaction",
                opportunity_id=opportunity.opportunity_id, valence=-1,
                weight=rubric.IGNORED_WEIGHT, sim_time_ms=opportunity.sim_time_ms,
                source=dict(opportunity.source),
                explanation_code="opportunity_ignored:%s:%s" % (
                    opportunity.opportunity_type, dimension),
                explanation_text=_IGNORED_EXPLANATIONS[opportunity.opportunity_type],
                dedup_key=("ignored_opportunity", opportunity.opportunity_id,
                          dimension)))

    # Decisions with no tracked opportunity behind them (ordinary operational
    # choices) still count, unconditionally, exactly as before this module's
    # opportunity-model correction.
    for pair, (decision_id, record_id, state, definition) in decisions.items():
        if pair in tracked_pairs:
            continue
        items.extend(_decision_evidence(session, decision_id, state,
                                        definition, record_id=record_id))

    items.sort(key=lambda item: (item.sim_time_ms, item.evidence_id))
    return tuple(items)
