"""Trainer analytics, derived from persisted RewindSec 2.0 session facts.

Every number this module produces is computed from stored 2.0 sessions: their
world mutations, their recorded decisions, their Context Ledger observations
and their finalized scoring results. Nothing is authored, nothing is
illustrative, and nothing is carried over from the fixture console this batch
replaces. If the stored data cannot support a metric, the metric says so --
:attr:`Metric.available` is ``False``, its value is ``None``, and the console
renders an honest empty state. **A fabricated percentage is worse than an
empty card**, because a trainer cannot tell the two apart by looking.

What these numbers are, and are not
-----------------------------------
They are *technical telemetry about a simulation*. They describe what
happened inside authored scenarios under an authored rubric. They are not
measures of human competence, they do not demonstrate learning, retention or
transfer, and a change in any of them between two sessions is not evidence
that a person improved. Establishing any of that requires human research data
this system does not collect. Every metric carries that constraint in its
``interpretation`` field so it travels with the number rather than living
only in a document.

Two metrics, not one blended number
-----------------------------------
A metric's *label* and its *numerator* must be the same statement. Version 1
published one figure called a false-positive rate whose numerator was
"reported something genuine **or** disconnected with nothing to contain",
over a denominator of every session analysed. Those are two different
operational behaviours -- a judgement about one message, and a containment
action against the whole machine -- and no reading of the resulting
percentage was true. It is now two metrics, each with its own denominator:
``false_positive_reports`` over sessions that actually delivered something
genuine to over-report, and ``unnecessary_isolation`` over sessions
analysed. Neither is inferred from the other, and neither is a measure of
learning: see the interpretation limit above.

Extensibility (why this is not a pile of columns)
--------------------------------------------------
The architecture requires trainer analytics to be extensible. Adding a metric
here is adding an entry to :data:`METRIC_DEFINITIONS` and a small function --
never a migration, never a new column on ``rewindsec2_students`` or
``rewindsec2_sessions``. Every emitted metric carries
:data:`METRIC_SET_VERSION` plus its own ``definition`` and explicit
``denominator``, so a stored or exported figure always says what it counted
and under which version of the definition it counted it.
"""

from rewindsec.scoring import state as scoring_state
from rewindsec.scoring.evidence import decision_records, resolve_opportunities
from rewindsec.workstation.bootstrap import NS_MAIL
from rewindsec.workstation.content import index as ix

__all__ = ["METRIC_SET_VERSION", "METRIC_DEFINITIONS", "Metric",
           "session_facts", "aggregate", "INTERPRETATION_LIMIT"]

#: Bumped whenever any metric's definition or denominator changes. Emitted
#: with every metric row, so a figure recorded under an older definition can
#: never be silently compared with one recorded under a newer.
METRIC_SET_VERSION = "rewindsec-trainer-metrics/v2"

INTERPRETATION_LIMIT = (
    "Technical telemetry from authored simulations under an authored rubric. "
    "Not a measure of competence, learning, retention or transfer.")

# ---------------------------------------------------------------------------
# Authored decision groupings
# ---------------------------------------------------------------------------
#
# Hand-authored, in the same style ``scoring/opportunities.py`` authors its
# resolution map, rather than inferred from an id suffix. There are few enough
# decisions in this scenario that pattern-matching on names would only add a
# way to be silently wrong when a decision is renamed.

#: Submitting credentials on a look-alike destination.
_CREDENTIAL_DECISIONS = frozenset({"d-phish-credentials", "d-phish2-credentials"})

#: Checking a request on a channel the request itself did not supply.
_VERIFY_DECISIONS = frozenset({"d-phish-verify", "d-phish2-verify",
                               "d-bec-verify", "d-bec2-verify"})

#: Opening an attachment that carries an active payload.
_UNSAFE_OPEN_DECISIONS = frozenset({"d-ransom-open", "d-ransom2-open",
                                    "d-ransom3-open"})

#: Denying an approval request the learner did not start.
_MFA_HOSTILE_DENY = frozenset({"d-mfa-deny-hostile"})
_MFA_HOSTILE_PROMPTS = frozenset({"mfa-unexpected"})

#: Reporting a genuine work request as suspicious.
#:
#: These two used to share one metric and one numerator, published as a
#: "false positive report" rate. They are not the same behaviour and they do
#: not share a denominator: one is a *report*, made about a specific message
#: that was actually delivered, and the other is an *operational containment
#: action* taken against the whole workstation with no incident open. A
#: percentage whose numerator mixes them answers no question a trainer has,
#: and its label answered a question it was not counting. They are now two
#: metrics with two denominators -- see :data:`METRIC_DEFINITIONS`.
_FALSE_POSITIVE_REPORT_DECISIONS = frozenset({"d-report-legitimate"})

#: Taking the workstation off the network with nothing to contain.
_UNNECESSARY_ISOLATION_DECISIONS = frozenset({"d-isolate-no-incident"})

_CONTAINMENT_DECISION = "d-ransom-isolate"
_RECOVERY_DECISION = "d-ransom-recover"


class Metric(object):
    """One aggregate figure, with everything needed to read it honestly."""

    __slots__ = ("metric_id", "label", "definition", "denominator_label",
                 "numerator", "denominator", "unit", "available",
                 "unavailable_reason")

    def __init__(self, metric_id, label, definition, denominator_label,
                 numerator=0, denominator=0, unit="percent", available=True,
                 unavailable_reason=None):
        self.metric_id = metric_id
        self.label = label
        self.definition = definition
        self.denominator_label = denominator_label
        self.numerator = numerator
        self.denominator = denominator
        #: ``"percent"`` or ``"count"``.
        self.unit = unit
        self.available = available and denominator > 0
        self.unavailable_reason = unavailable_reason or (
            None if self.available else
            "No session yet presented an opportunity this metric counts.")

    @property
    def value(self):
        """The figure, or ``None`` when there is nothing to divide by.

        Integer percentage, rounded half away from zero with integer
        arithmetic only -- the same rule
        :mod:`rewindsec.scoring.evaluator` uses, so no figure anywhere in the
        product depends on floating-point rounding behaviour.
        """
        if not self.available:
            return None
        if self.unit == "count":
            return self.numerator
        return (2 * 100 * self.numerator + self.denominator) \
            // (2 * self.denominator)

    def to_state(self):
        return {
            "id": self.metric_id,
            "label": self.label,
            "definition": self.definition,
            "denominator_label": self.denominator_label,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "unit": self.unit,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "value": self.value,
            "display": (
                "—" if not self.available else
                ("%d" % self.value) if self.unit == "count"
                else ("%d%%" % self.value)),
            "metric_version": METRIC_SET_VERSION,
            "interpretation": INTERPRETATION_LIMIT,
        }


#: Every metric this version emits: its label, what it counts, and -- the part
#: that makes a percentage readable rather than merely present -- exactly what
#: its denominator is.
METRIC_DEFINITIONS = (
    ("relevant_evidence_use", "Relevant evidence inspected",
     "Decisions where at least half of the evidence the workstation made "
     "available for that decision had actually been opened before it was "
     "taken.",
     "Recorded decisions that have authored evidence available to inspect.",
     "percent"),
    ("known_channel_verification", "Known-channel verification",
     "Opportunities resolved by checking the request on a channel the "
     "request itself did not supply.",
     "Opportunities where a known-channel check was one of the ways to "
     "resolve it.",
     "percent"),
    ("credential_submissions", "Credential submissions",
     "Sessions in which a sign-in was completed on a look-alike destination.",
     "Sessions that presented at least one look-alike sign-in opportunity.",
     "percent"),
    ("unsafe_attachment_opens", "Unsafe attachments opened",
     "Opportunities resolved by opening an attachment carrying an active "
     "payload.",
     "Opportunities where opening the attachment was one of the ways to "
     "resolve it.",
     "percent"),
    ("mfa_hostile_denied", "Unexpected approval requests denied",
     "Approval requests the learner did not start that were denied.",
     "Approval requests raised that the learner did not start.",
     "percent"),
    ("false_positive_reports", "Genuine work requests reported",
     "Sessions in which at least one genuine, non-hostile work request was "
     "reported as suspicious.",
     "Sessions that actually delivered at least one genuine, non-hostile "
     "message the learner could have reported.",
     "percent"),
    ("unnecessary_isolation", "Workstation disconnected with nothing to "
     "contain",
     "Sessions in which the workstation was taken off the network while no "
     "incident was open. An operational-cost behaviour, counted separately "
     "from reporting: it is a containment action, not a report, and the two "
     "have neither the same meaning nor the same denominator.",
     "Sessions analysed. Disconnecting is available in every session from "
     "the moment it starts, so every analysed session is a session in which "
     "this could have happened.",
     "percent"),
    ("incident_containment", "Incidents contained",
     "Incidents where the workstation was disconnected and the Service Desk "
     "called.",
     "Sessions in which an incident actually opened.",
     "percent"),
    ("incident_recovery", "Recovery opportunities used",
     "Recovery opportunities that became available after containment and "
     "were then used.",
     "Recovery opportunities that became available.",
     "percent"),
)

_DEFINITION_BY_ID = {row[0]: row for row in METRIC_DEFINITIONS}


def _benign_mail_delivered(session):
    """Whether this session actually delivered a genuine, non-hostile message.

    Read from the world -- what was delivered -- against the same authored
    ``analysis.disposition`` vocabulary scoring reads, so there is no second
    opinion anywhere about which messages are genuine. A session that
    delivered only hostile mail presented no opportunity to over-report, and
    is therefore not in the denominator of a metric about over-reporting.
    """
    for mail_id, state in session.world.get_component(NS_MAIL).items():
        if state.get("delivered") and not ix.is_hostile_mail(mail_id):
            return True
    return False


def _observed_fraction(session, decision_id):
    """``(observed, total)`` evidence items for one decision, or ``None``.

    Reads the same authored ``evidence_source``/``evidence_model`` vocabulary
    :mod:`rewindsec.scoring.evidence` reads, from
    :mod:`rewindsec.workstation.content.index` -- one shared table, never a
    second copy that could drift.
    """
    source = ix.evidence_source(decision_id)
    if source is None:
        return None
    items = ix.evidence_model(*source)
    if not items:
        return None
    observed = 0
    for item in items:
        fact_id = ix.evidence_fact_id(item.get("action"))
        if fact_id and session.ledger.has(fact_id) \
                and session.ledger.get(fact_id).observed:
            observed += 1
    return observed, len(items)


def session_facts(session):
    """Every countable fact this module needs from one loaded session.

    Pure: reads the session's world, ledger and stored scoring result, and
    returns plain integers and booleans. Consumes no randomness, advances no
    clock and persists nothing -- so calling it on an active session is safe,
    though the console only ever calls it on stored ones.
    """
    resolutions, _tracked, decisions = resolve_opportunities(session)
    recorded = {decision_id for decision_id, _record, _state, _definition
                in decisions.values()}

    facts = {
        "opportunities_presented": len(resolutions),
        "opportunities_resolved": sum(1 for r in resolutions if r.resolved),
        "evidence_decisions": 0,
        "evidence_decisions_informed": 0,
        "verify_opportunities": 0,
        "verify_resolved": 0,
        "credential_opportunity": False,
        "credential_submitted": bool(recorded & _CREDENTIAL_DECISIONS),
        "unsafe_open_opportunities": 0,
        "unsafe_opens": 0,
        "mfa_hostile_prompts": 0,
        "mfa_hostile_denied": 0,
        # The denominator for the reporting metric: a session that never
        # delivered a genuine message gave the learner nothing to
        # over-report, and counting it would dilute the rate with sessions
        # that could not have contributed to the numerator.
        "benign_mail_delivered": _benign_mail_delivered(session),
        "reported_legitimate": bool(recorded
                                    & _FALSE_POSITIVE_REPORT_DECISIONS),
        "isolated_without_incident": bool(
            recorded & _UNNECESSARY_ISOLATION_DECISIONS),
        "incident_opened": False,
        "incident_contained": False,
        "recovery_opportunities": 0,
        "recovery_used": 0,
    }

    for _pair, (decision_id, _record, _state, _definition) in decisions.items():
        fraction = _observed_fraction(session, decision_id)
        if fraction is None:
            continue
        observed, total = fraction
        facts["evidence_decisions"] += 1
        if observed * 2 >= total:
            facts["evidence_decisions_informed"] += 1

    for resolution in resolutions:
        opportunity = resolution.opportunity
        resolving = set(opportunity.resolving_decisions)

        if resolving & _VERIFY_DECISIONS:
            facts["verify_opportunities"] += 1
            if resolution.decision_id in _VERIFY_DECISIONS:
                facts["verify_resolved"] += 1

        if resolving & _CREDENTIAL_DECISIONS:
            facts["credential_opportunity"] = True

        if resolving & _UNSAFE_OPEN_DECISIONS:
            facts["unsafe_open_opportunities"] += 1
            if resolution.decision_id in _UNSAFE_OPEN_DECISIONS:
                facts["unsafe_opens"] += 1

        if opportunity.opportunity_type == "prompt" \
                and opportunity.source.get("prompt_id") in _MFA_HOSTILE_PROMPTS:
            facts["mfa_hostile_prompts"] += 1
            if resolution.decision_id in _MFA_HOSTILE_DENY:
                facts["mfa_hostile_denied"] += 1

        if opportunity.opportunity_type == "containment":
            facts["incident_opened"] = True
            if resolution.decision_id == _CONTAINMENT_DECISION:
                facts["incident_contained"] = True

        if opportunity.opportunity_type == "recovery":
            facts["recovery_opportunities"] += 1
            if resolution.decision_id == _RECOVERY_DECISION:
                facts["recovery_used"] += 1

    result = scoring_state.get_result(session)
    facts["scored"] = result is not None
    facts["overall"] = None if result is None else result.overall
    return facts


def aggregate(session_facts_rows):
    """Turn per-session facts into the metric rows the console renders.

    ``session_facts_rows`` is whatever :func:`session_facts` returned for each
    session in scope -- typically every stored session belonging to the
    students being looked at. An empty input produces every metric in its
    explicit unavailable state, never zeros: "no sessions yet" and "nobody
    ever did this" are different answers and must look different.
    """
    rows = list(session_facts_rows)
    counters = {
        "relevant_evidence_use": (
            sum(f["evidence_decisions_informed"] for f in rows),
            sum(f["evidence_decisions"] for f in rows)),
        "known_channel_verification": (
            sum(f["verify_resolved"] for f in rows),
            sum(f["verify_opportunities"] for f in rows)),
        "credential_submissions": (
            sum(1 for f in rows
                if f["credential_opportunity"] and f["credential_submitted"]),
            sum(1 for f in rows if f["credential_opportunity"])),
        "unsafe_attachment_opens": (
            sum(f["unsafe_opens"] for f in rows),
            sum(f["unsafe_open_opportunities"] for f in rows)),
        "mfa_hostile_denied": (
            sum(f["mfa_hostile_denied"] for f in rows),
            sum(f["mfa_hostile_prompts"] for f in rows)),
        "false_positive_reports": (
            sum(1 for f in rows
                if f["benign_mail_delivered"] and f["reported_legitimate"]),
            sum(1 for f in rows if f["benign_mail_delivered"])),
        "unnecessary_isolation": (
            sum(1 for f in rows if f["isolated_without_incident"]), len(rows)),
        "incident_containment": (
            sum(1 for f in rows if f["incident_contained"]),
            sum(1 for f in rows if f["incident_opened"])),
        "incident_recovery": (
            sum(f["recovery_used"] for f in rows),
            sum(f["recovery_opportunities"] for f in rows)),
    }

    metrics = []
    for metric_id, label, definition, denominator_label, unit in \
            METRIC_DEFINITIONS:
        numerator, denominator = counters[metric_id]
        metrics.append(Metric(
            metric_id=metric_id, label=label, definition=definition,
            denominator_label=denominator_label, numerator=numerator,
            denominator=denominator, unit=unit,
            unavailable_reason=(
                "No session analysed yet." if not rows else None)))
    return tuple(metrics)
