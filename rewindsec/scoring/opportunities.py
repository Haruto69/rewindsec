"""The Opportunity model: what a session offered, independent of what a
learner did about it -- and independent of what later happened to the world.

This is the correction Architecture Spec v1.1 (Batch 4) review found missing
from the first cut of scoring: an :class:`Opportunity` is materialized from
factual, already-recorded history -- a delivered message, a raised approval
request, an incident reaching containment -- and exists whether or not any
decision was ever recorded about it.

Immutable provenance, not live state (review correction)
----------------------------------------------------------
The first cut of this module read *current* :class:`~rewindsec.domain.world
.WorldState` component snapshots (``get_component``). That is provably
insufficient as a scoring record on its own: nothing stops a caller from
reading it after the fact a mail was deleted, a prompt resolved, or an
incident recovered, and if the detection logic ever depended on a field that
changes (or is removed) later, a genuinely-presented opportunity could
silently disappear from what scoring sees.

This module instead walks :meth:`~rewindsec.domain.world.WorldState.mutations`
-- the world's own append-only, immutable audit log, already persisted and
already restored on every resume, with each entry's ``sim_time_ms`` stamped
at the moment it *actually happened*, not read back later. An opportunity is
recorded, once, at the first mutation that establishes it (mail actually
delivered, an approval request actually raised, the incident actually
opened/actually contained); every later mutation to that same row -- the
mail moved to Deleted, the request approved or denied, the incident later
recovered -- is simply never consulted again for that opportunity. There is
no separate log to keep in sync and nothing new to persist: the history this
reads has been the authoritative, immutable record all along.

:mod:`rewindsec.scoring.evidence` is the only caller. For each opportunity it
checks whether a decision that resolves it was actually recorded; if not, the
opportunity was *ignored*, and evidence.py records explicit negative evidence
for every dimension that opportunity was relevant to -- not just
``security_judgment``. A hostile MFA prompt the learner never touched, a
contained incident nobody ever isolated further into, a recovery opportunity
nobody used: all three now produce an opportunity record, so none of them can
quietly vanish into "no evidence, so the dimension scores a neutral 50" or
"no evidence, so the dimension is N/A".

Which authored decisions *resolve* an opportunity is a fixed, hand-authored
map here (the same style :mod:`rewindsec.workstation.content.index` already
uses for ``evidence_source``), not a generic inference -- there are few enough
opportunities in this scenario that guessing would only add risk. Which
dimensions an opportunity is relevant to is *derived* from those same
resolving decisions' authored ``dimensions`` (except containment/recovery,
kept deliberately narrow -- see the two hard-coded tuples below), so the
opportunity model can never claim a dimension the decision authoring does not
also claim.
"""

from rewindsec.domain.json_safe import thaw
from rewindsec.scoring.dimensions import DIMENSION_IDS
from rewindsec.workstation.bootstrap import NS_AUTH_REQUESTS, NS_INCIDENTS, NS_MAIL
from rewindsec.workstation.content import index as ix

__all__ = ["Opportunity", "build_opportunities"]

#: Bumped only if this record's own persisted shape changes incompatibly --
#: distinct from the evidence/rubric/scoring versions, since a change here
#: could in principle affect what opportunities a re-evaluation would find
#: without changing the rubric that scores them.
OPPORTUNITY_MODEL_VERSION = "rewindsec-opportunity-model/v1"

#: mail_id -> the decisions that resolve the opportunity it presents.
_MAIL_RESOLUTIONS = {
    "m-payroll-restructure": ("d-phish-credentials", "d-phish-report",
                              "d-phish-verify", "d-phish-delete"),
    "m-benefits-verify": ("d-phish2-credentials", "d-phish2-report",
                          "d-phish2-verify", "d-phish2-delete"),
    # Batch 4 correction (content pipeline wiring): each recurring
    # candidate's second, generated occurrence is its own opportunity, with
    # its own (smaller) decision set -- ignoring it is scored independently
    # of whatever happened with the first occurrence's message. See
    # rewindsec.training.recurrence.
    # The second occurrence shares the first occurrence's look-alike portal,
    # so a credential submission through *either* occurrence still records
    # the same semantic class, ``d-phish2-credentials`` -- but occurrence-
    # scoped now (see rewindsec.workstation.consequences), so a submission
    # made while this occurrence's message was the one in front of the
    # learner is tracked as resolving *this* opportunity, never the first
    # occurrence's.
    "m-benefits-verify-o2": ("d-phish3-report", "d-phish3-delete",
                             "d-phish2-credentials"),
    "m-rate-card": ("d-ransom-open", "d-ransom-report"),
    "m-audit-checklist": ("d-ransom2-open", "d-ransom2-report"),
    "m-audit-checklist-o2": ("d-ransom3-open", "d-ransom3-report"),
    "m-invoice-amend": ("d-bec-authorize", "d-bec-reply", "d-bec-verify",
                        "d-bec-report"),
    "m-meridian-amend": ("d-bec2-authorize", "d-bec2-reply", "d-bec2-verify",
                         "d-bec2-report"),
    # Batch 4 review correction (BEC occurrence-scoped authorization): the
    # second Meridian occurrence raises its own release-queue entry on the
    # shared payments page, so authorizing a changed account *while resolving
    # this occurrence* is one of the things that resolves this opportunity.
    # The semantic class is the same one the first occurrence uses --
    # releasing a supplier payment to an account that arrived by mail is the
    # same mistake the second time -- and it is the occurrence key, not the
    # class, that keeps the two apart: ``d-bec2-authorize@m-meridian-amend``
    # resolves the first occurrence and can never resolve this one, and vice
    # versa. See ``rewindsec.workstation.service._browser_release_payment``.
    "m-meridian-amend-o2": ("d-bec3-reply", "d-bec3-report",
                            "d-bec2-authorize"),
}

#: prompt_id -> the decisions that resolve the opportunity it presents.
_PROMPT_RESOLUTIONS = {
    "mfa-unexpected": ("d-mfa-approve-hostile", "d-mfa-deny-hostile"),
    "mfa-vpn": ("d-mfa-approve-legit", "d-mfa-deny-legit"),
}

#: Containment is a response to an incident existing at all -- available the
#: moment the incident opens, whether or not the learner ever acts. Kept to
#: exactly ``incident_response``: recovery is a separate, later opportunity
#: (below), and folding it in here would blur the distinction Architecture
#: Spec v1.1 S24 requires between the two.
_CONTAINMENT_RESOLUTIONS = ("d-ransom-isolate", "d-ransom-continue")
_CONTAINMENT_DIMENSIONS = ("incident_response",)

#: Recovery only ever becomes a real opportunity once containment has
#: happened -- see ``service._restore``'s gate. An incident that is never
#: contained never produces this opportunity at all, which is what makes
#: "no recovery opportunity ever existed" (legitimately N/A) distinguishable
#: from "a recovery opportunity existed and was ignored" (not N/A).
_RECOVERY_RESOLUTIONS = ("d-ransom-recover",)
_RECOVERY_DIMENSIONS = ("recovery_quality",)


class Opportunity(object):
    """One chance to demonstrate something, whether or not it was taken."""

    __slots__ = ("opportunity_id", "opportunity_type", "dimensions",
                 "sim_time_ms", "source", "resolving_decisions",
                 "occurrence_key")

    def __init__(self, opportunity_id, opportunity_type, dimensions,
                 sim_time_ms, source, resolving_decisions,
                 occurrence_key=None):
        self.opportunity_id = opportunity_id
        self.opportunity_type = opportunity_type
        self.dimensions = tuple(dimensions)
        self.sim_time_ms = sim_time_ms
        #: ``{"mail_id": ...}`` / ``{"request_id": ..., "prompt_id": ...}`` /
        #: ``{"incident_key": ...}`` -- whichever factual world row this
        #: opportunity was materialized from.
        self.source = dict(source)
        #: Decision ids that would resolve this opportunity if recorded. Not
        #: exposed to learners; used only by evidence.py to check whether one
        #: of them actually was.
        self.resolving_decisions = tuple(resolving_decisions)
        #: The occurrence identity a resolving decision must have been
        #: recorded against for it to count as resolving *this* opportunity
        #: rather than some other occurrence of the same recurring surface --
        #: the mail id for a mail opportunity, the request id for a prompt.
        #: ``None`` for the two opportunity types that never recur within a
        #: session (containment, recovery): those still match a decision
        #: recorded with no occurrence key at all, exactly as before this
        #: field existed.
        self.occurrence_key = occurrence_key

    def to_state(self):
        """Internal, provenance-carrying projection. Never sent to a learner.

        Includes ``resolving_decisions`` -- answer-key-shaped, needed by
        :mod:`rewindsec.scoring.evidence` to resolve this opportunity later,
        and must never reach a learner-facing projection; the leakage suite
        asserts that.
        """
        return {
            "opportunity_model_version": OPPORTUNITY_MODEL_VERSION,
            "opportunity_id": self.opportunity_id,
            "opportunity_type": self.opportunity_type,
            "dimensions": list(self.dimensions),
            "sim_time_ms": self.sim_time_ms,
            "source": dict(self.source),
            "resolving_decisions": list(self.resolving_decisions),
            "occurrence_key": self.occurrence_key,
        }


def _dims_for(decision_ids):
    """The union of dimensions the given decisions are authored against.

    Sorted into the canonical dimension order so two opportunities with the
    same underlying decisions always report dimensions identically, never by
    set/dict iteration order.
    """
    dims = set()
    for decision_id in decision_ids:
        definition = ix.DECISION_BY_ID.get(decision_id) or {}
        dims.update(definition.get("dimensions") or ())
    return tuple(dim for dim in DIMENSION_IDS if dim in dims)


def build_opportunities(session):
    """Every opportunity this session ever presented, from immutable history.

    Walks ``session.world.mutations()`` -- the append-only mutation log,
    already persisted, already restored byte-for-byte on every resume -- once,
    in order. Each opportunity is captured at the *first* mutation that
    establishes it, using that mutation's own ``sim_time_ms`` (stamped when it
    actually happened, not read back from current state); every later
    mutation to the same mail/request/incident row is consulted only to check
    for a *later* transition this function itself cares about (an incident
    becoming contained), never to re-derive or revoke an opportunity already
    captured. Deleting a mail, resolving a prompt, or recovering an incident
    afterward cannot make an opportunity that genuinely existed disappear --
    those later mutations to the same row are simply never visited again for
    this purpose.

    Pure and side-effect-free: consumes no randomness, advances no clock,
    persists nothing new (there is nothing new to persist -- the history this
    reads was already the authoritative record), and returns identical
    opportunities in identical order for the same mutation history every
    time it is called, on an active session or a completed one alike. Unlike
    evidence and scoring, nothing here is secret by itself; it is what
    :mod:`rewindsec.scoring.evidence` does with it that is gated to session
    completion.
    """
    out = []
    seen_mail, seen_requests = set(), set()
    incident_opened_at, incident_contained_at = None, None

    for mutation in session.world.mutations():
        if mutation.namespace == NS_MAIL:
            mail_id = mutation.key
            if mail_id in seen_mail:
                continue
            new_value = thaw(mutation.new_value)
            if not isinstance(new_value, dict) or not new_value.get("delivered"):
                continue
            resolutions = _MAIL_RESOLUTIONS.get(mail_id)
            if resolutions is None:
                continue
            seen_mail.add(mail_id)
            out.append(Opportunity(
                opportunity_id="mail:%s" % mail_id, opportunity_type="mail",
                dimensions=_dims_for(resolutions), sim_time_ms=mutation.sim_time_ms,
                source={"mail_id": mail_id}, resolving_decisions=resolutions,
                occurrence_key=mail_id))

        elif mutation.namespace == NS_AUTH_REQUESTS:
            request_id = mutation.key
            if request_id in seen_requests:
                continue
            new_value = thaw(mutation.new_value)
            if not isinstance(new_value, dict):
                continue
            prompt_id = new_value.get("prompt_id")
            resolutions = _PROMPT_RESOLUTIONS.get(prompt_id)
            if resolutions is None:
                continue
            seen_requests.add(request_id)
            out.append(Opportunity(
                opportunity_id="prompt:%s" % request_id, opportunity_type="prompt",
                dimensions=_dims_for(resolutions), sim_time_ms=mutation.sim_time_ms,
                source={"request_id": request_id, "prompt_id": prompt_id},
                resolving_decisions=resolutions, occurrence_key=request_id))

        elif mutation.namespace == NS_INCIDENTS and mutation.key == "inc-files":
            new_value = thaw(mutation.new_value)
            if not isinstance(new_value, dict):
                continue
            if incident_opened_at is None:
                incident_opened_at = mutation.sim_time_ms
            if incident_contained_at is None and new_value.get("contained"):
                incident_contained_at = mutation.sim_time_ms

    if incident_opened_at is not None:
        out.append(Opportunity(
            opportunity_id="incident:inc-files:containment",
            opportunity_type="containment", dimensions=_CONTAINMENT_DIMENSIONS,
            sim_time_ms=incident_opened_at, source={"incident_key": "inc-files"},
            resolving_decisions=_CONTAINMENT_RESOLUTIONS))
        if incident_contained_at is not None:
            out.append(Opportunity(
                opportunity_id="incident:inc-files:recovery",
                opportunity_type="recovery", dimensions=_RECOVERY_DIMENSIONS,
                sim_time_ms=incident_contained_at,
                source={"incident_key": "inc-files"},
                resolving_decisions=_RECOVERY_RESOLUTIONS))

    out.sort(key=lambda op: (op.sim_time_ms, op.opportunity_id))
    return tuple(out)
