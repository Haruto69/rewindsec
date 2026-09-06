"""Eligibility, evaluated before any random value is drawn.

Architecture S9.2 makes this a rule rather than a preference: a candidate is
either LOCKED or ELIGIBLE, and only ELIGIBLE candidates take part in
selection. The reason it matters is fairness. A context-sensitive phishing
message that depends on the learner having somewhere to compare it against is
not *hard* if it arrives before that comparison exists -- it is arbitrary. And
probability is not a substitute for a prerequisite: making an unfair event
rare does not make it fair when it happens.

The second reason is reproducibility. If a LOCKED candidate consumed a
selection draw merely for existing in the catalogue, then adding one authored
message would shift every later draw in the stream and no stored session would
replay. Nothing here touches the RNG at all.

Available versus observed
-------------------------
The Context Ledger keeps two distinct states (architecture S7), and a
prerequisite has to say which one it needs, because both are legitimate and
neither is a safe default:

* :data:`FACT_AVAILABLE` -- the workplace has surfaced this. Used when the
  event only needs the *world* to make sense. The look-alike payroll message
  needs the real payroll domain to have been in the mailbox; it does not need
  the learner to have noticed it, and requiring that would let an inattentive
  learner opt out of the hard events.
* :data:`FACT_OBSERVED` -- the learner actually inspected this. Used when the
  event is a *follow-up to the learner's own attention*: a reply inside a
  thread the learner has read is plausible; the same reply to a thread they
  have never opened is a message from nowhere.

Reason codes
------------
Every LOCKED verdict carries machine-readable reason codes. They exist for
tests, debugging and later reproducibility work, they are recorded only in the
engine's internal trace, and they never reach a learner: "cooldown" and
"prerequisite_missing" are, between them, a map of what the simulation is
about to do.
"""

from rewindsec.workstation.bootstrap import NS_INCIDENTS, NS_MAIL, NS_SESSION

__all__ = [
    "Prereq", "EligibilityResult", "evaluate", "FACT_AVAILABLE",
    "FACT_OBSERVED", "WORLD_FLAG", "WORLD_FLAG_ABSENT", "DECISION_MADE",
    "DECISION_NOT_MADE", "MAIL_LIVE", "INCIDENT_OPEN", "INCIDENT_ABSENT",
    "REASON_CODES",
]

# -- prerequisite kinds ------------------------------------------------------

FACT_AVAILABLE = "fact_available"
FACT_OBSERVED = "fact_observed"
WORLD_FLAG = "world_flag"
WORLD_FLAG_ABSENT = "world_flag_absent"
DECISION_MADE = "decision_made"
DECISION_NOT_MADE = "decision_not_made"
MAIL_LIVE = "mail_live"
INCIDENT_OPEN = "incident_open"
INCIDENT_ABSENT = "incident_absent"

# -- reason codes ------------------------------------------------------------

REASON_CODES = frozenset({
    "missing_fact",
    "fact_not_observed",
    "cooldown",
    "max_occurrences",
    "wrong_focus_policy",
    "network_unavailable",
    "prerequisite_missing",
    "already_active",
    "already_delivered",
    "session_ended",
    "blocked_by_comparison",
})


class Prereq(object):
    """One declared precondition. Immutable, comparable, cheap to read."""

    __slots__ = ("kind", "ref")

    def __init__(self, kind, ref):
        self.kind = kind
        self.ref = ref

    def __repr__(self):
        return "Prereq(%r, %r)" % (self.kind, self.ref)

    def __eq__(self, other):
        return (isinstance(other, Prereq) and other.kind == self.kind
                and other.ref == self.ref)

    #: Deliberately unhashable. Defining ``__eq__`` without ``__hash__`` makes
    #: it so, and that is the intent: a prerequisite must never end up in a set
    #: or a dict key, because iterating one has no defined order and the order
    #: in which prerequisites are checked is part of what makes a trace
    #: reproducible. Prerequisites live in tuples, and are compared by value.
    __hash__ = None


class EligibilityResult(object):
    """The verdict on one candidate, with the reasons behind it."""

    __slots__ = ("candidate_id", "eligible", "reasons")

    def __init__(self, candidate_id, eligible, reasons=()):
        self.candidate_id = candidate_id
        self.eligible = bool(eligible)
        #: Sorted and de-duplicated so two evaluations of the same state
        #: produce byte-identical trace records.
        self.reasons = tuple(sorted(set(reasons)))

    def __repr__(self):
        return "EligibilityResult(%r, eligible=%r, reasons=%r)" % (
            self.candidate_id, self.eligible, self.reasons)

    def as_record(self):
        return {"candidate": self.candidate_id, "eligible": self.eligible,
                "reasons": list(self.reasons)}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(session, candidate, family_state, now_ms, focus_id,
             active_primary, gate_on_active_primary):
    """Resolve one candidate to ELIGIBLE or LOCKED. Draws no random value.

    Every failing condition is collected rather than short-circuited: a
    candidate blocked by three different things says so, which is what makes
    the trace useful when a family unexpectedly never appears.
    """
    reasons = []

    state = _candidate_state(session, candidate.candidate_id)
    if candidate.max_occurrences is not None \
            and state["occurrences"] >= candidate.max_occurrences:
        reasons.append("max_occurrences")

    if candidate.cooldown_ms and state["last_fired_ms"] is not None \
            and now_ms < state["last_fired_ms"] + candidate.cooldown_ms:
        reasons.append("cooldown")

    if now_ms < int(family_state.get("cooldown_until_ms") or 0):
        reasons.append("cooldown")

    if candidate.focus_only and focus_id not in candidate.focus_only:
        reasons.append("wrong_focus_policy")

    if candidate.requires_network and _offline(session):
        reasons.append("network_unavailable")

    if gate_on_active_primary and active_primary and candidate.is_primary:
        reasons.append("already_active")

    if candidate.delivers_mail and _mail_already_delivered(
            session, candidate.delivers_mail):
        reasons.append("already_delivered")

    for prereq in candidate.prerequisites:
        code = _check(session, prereq)
        if code is not None:
            reasons.append(code)

    return EligibilityResult(candidate.candidate_id, not reasons, reasons)


def _check(session, prereq):
    """The reason *prereq* fails, or ``None`` when it holds."""
    kind, ref = prereq.kind, prereq.ref

    if kind == FACT_AVAILABLE:
        if not session.ledger.has(ref) or not session.ledger.get(ref).available:
            return "missing_fact"
        return None

    if kind == FACT_OBSERVED:
        if not session.ledger.has(ref):
            return "missing_fact"
        fact = session.ledger.get(ref)
        if not fact.available:
            return "missing_fact"
        if not fact.observed:
            return "fact_not_observed"
        return None

    if kind == WORLD_FLAG:
        return None if session.world.get(NS_SESSION, ref) else "prerequisite_missing"

    if kind == WORLD_FLAG_ABSENT:
        return "prerequisite_missing" if session.world.get(NS_SESSION, ref) else None

    if kind == DECISION_MADE:
        from rewindsec.workstation.bootstrap import NS_DECISIONS
        return None if session.world.has(NS_DECISIONS, ref) \
            else "prerequisite_missing"

    if kind == DECISION_NOT_MADE:
        from rewindsec.workstation.bootstrap import NS_DECISIONS
        return "prerequisite_missing" if session.world.has(NS_DECISIONS, ref) \
            else None

    if kind == MAIL_LIVE:
        state = session.world.get(NS_MAIL, ref) or {}
        live = (state.get("delivered") and not state.get("reported")
                and state.get("folder") != "deleted")
        return None if live else "prerequisite_missing"

    if kind == INCIDENT_OPEN:
        return None if session.world.has(NS_INCIDENTS, ref) \
            else "prerequisite_missing"

    if kind == INCIDENT_ABSENT:
        return "prerequisite_missing" if session.world.has(NS_INCIDENTS, ref) \
            else None

    # An unrecognised prerequisite kind locks the candidate rather than being
    # ignored. Silently treating a typo as "no condition" would let an unfair
    # event through, which is precisely what this module exists to stop.
    return "prerequisite_missing"


def _offline(session):
    return bool(session.world.get(NS_SESSION, "network_disconnected", False))


def _mail_already_delivered(session, mail_id):
    state = session.world.get(NS_MAIL, mail_id) or {}
    return bool(state.get("delivered"))


def _candidate_state(session, candidate_id):
    from rewindsec.training import state as engine_state
    return engine_state.candidate_state(session, candidate_id)
