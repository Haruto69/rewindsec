"""The authored scoring policy: weights, valence, and per-dimension applicability.

Everything a caller might want to tune about *how* evidence turns into a
score lives here, centrally, rather than scattered across evidence
collection and aggregation. This is deliberately a simple, transparent,
normalized weighted-evidence model -- no machine learning, no opaque
formula -- because Architecture Spec v1.1 (Batch 4) asks for an authored
policy a reviewer can read end to end, not a black box.

This is authored system logic, not a claim about human competence. See the
module docstring of :mod:`rewindsec.scoring.result` for the disclaimer that
travels with every result this rubric produces.
"""

from rewindsec.scoring.dimensions import DIMENSION_IDS
from rewindsec.workstation.bootstrap import (NS_AUTH_REQUESTS, NS_INCIDENTS,
                                             NS_MAIL, NS_TASKS)
from rewindsec.workstation.content import index as ix

__all__ = ["CLASS_VALENCE", "DECISION_WEIGHT", "EVIDENCE_USE_WEIGHT",
           "IGNORED_WEIGHT", "applicability"]

#: Authored decision class -> sign of its contribution to every dimension it
#: is tagged with. ``0`` means the decision is recorded (for the debrief and
#: for provenance) but produces no scoring evidence at all -- a "neutral"
#: decision such as downloading, but not opening, an attachment.
CLASS_VALENCE = {
    "safe": 1,
    "recovery_good": 1,
    "unsafe": -1,
    "over_suspicious": -1,
    "recovery_poor": -1,
    "neutral": 0,
    "incomplete": -1,
}

#: A resolved consequential decision is the strongest signal this rubric has:
#: an authored, ground-truth-classified choice the learner actually made.
DECISION_WEIGHT = 3

#: Whether decision-relevant, available evidence was inspected beforehand.
#: Weighted below a decision itself: using evidence well is good, but it is
#: not a substitute for the decision it informs.
EVIDENCE_USE_WEIGHT = 1

#: A hostile opportunity, or an open recovery opportunity, that produced no
#: decision at all -- pure inaction. Weighted between the two above: worse
#: than failing to inspect evidence you did act on, not as severe as an
#: affirmatively unsafe choice.
IGNORED_WEIGHT = 2


def _any_mail_delivered(session):
    return any(state.get("delivered")
              for state in session.world.get_component(NS_MAIL).values())


def _any_hostile_mail_delivered(session):
    return any(state.get("delivered") and ix.is_hostile_mail(mail_id)
              for mail_id, state in session.world.get_component(NS_MAIL).items())


def _any_hostile_prompt(session):
    return any(ix.is_hostile_prompt(state.get("prompt_id"))
              for state in session.world.get_component(NS_AUTH_REQUESTS).values())


def _any_verification_reachable(session):
    """Whether a family with an authored known-channel verification path
    (phishing, BEC) actually delivered hostile mail this session."""
    for mail_id, state in session.world.get_component(NS_MAIL).items():
        if not state.get("delivered") or not ix.is_hostile_mail(mail_id):
            continue
        record = ix.MAIL_BY_ID.get(mail_id) or {}
        family = (record.get("analysis") or {}).get("family")
        if family in ("phishing", "bec"):
            return True
    return False


def _any_incident(session):
    return bool(session.world.get_component(NS_INCIDENTS))


def _recovery_opportunity_ever_existed(session):
    """Whether a *recovery* opportunity ever materialized -- distinct from an
    incident merely having occurred.

    Recovery only ever becomes available once containment has already
    happened (see ``service._restore``'s gate and
    :mod:`rewindsec.scoring.opportunities`'s ``recovery`` opportunity type).
    An incident that occurred but was never contained never produced a
    recovery opportunity at all, which is the distinction Architecture Spec
    v1.1 S15 draws between "recovery ignored" (not N/A) and "recovery never
    offered" (legitimately N/A).
    """
    incident = session.world.get(NS_INCIDENTS, "inc-files")
    return bool(incident and incident.get("contained"))


def _any_operational_surface(session):
    if _any_mail_delivered(session):
        return True
    if session.world.get_component(NS_AUTH_REQUESTS):
        return True
    if session.world.get_component(NS_TASKS):
        return True
    return False


#: One predicate per dimension: whether *this session* presented a real
#: opportunity to demonstrate it, and the reason to record when it did not.
#: A dimension is N/A only when its predicate is false -- never because the
#: learner happened not to act, which is exactly the distinction Architecture
#: Spec v1.1 S15 draws (recovery ignored is not N/A; recovery never offered
#: is).
_APPLICABILITY = {
    "security_judgment": (
        lambda s: _any_hostile_mail_delivered(s) or _any_hostile_prompt(s),
        "No hostile message or approval request was delivered this session."),
    "evidence_use": (
        lambda s: _any_hostile_mail_delivered(s) or _any_hostile_prompt(s),
        "Nothing carrying inspectable decision-relevant evidence was "
        "delivered this session."),
    "verification_discipline": (
        _any_verification_reachable,
        "No message with an independent verification path (phishing or "
        "a payment/account-change request) was delivered this session."),
    "incident_response": (
        lambda s: _any_hostile_mail_delivered(s) or _any_hostile_prompt(s)
                  or _any_incident(s),
        "No hostile activity or incident occurred this session."),
    "operational_accuracy": (
        _any_operational_surface,
        "No legitimate workplace activity was delivered this session."),
    "recovery_quality": (
        _recovery_opportunity_ever_existed,
        "No incident was ever contained this session, so no recovery "
        "opportunity ever existed."),
}


def applicability(session):
    """``{dimension: (applicable, na_reason_or_None)}`` for every dimension."""
    out = {}
    for dimension in DIMENSION_IDS:
        predicate, reason = _APPLICABILITY[dimension]
        applicable = bool(predicate(session))
        out[dimension] = (applicable, None if applicable else reason)
    return out
