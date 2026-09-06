"""Authored consequence chains, applied server-side.

In the UI prototype a decision played its authored chain on a browser timer.
That was the one assumption the prototype was explicitly not allowed to bake
in, and this module is where it is removed: a consequential decision now
schedules its steps on the session's own
:class:`~rewindsec.core.scheduler.EventScheduler`, at simulation times the
server chose, and each step is applied when its event actually fires. The
browser is told what happened; it is never the thing that decides.

What this module owns, after Batch 3
------------------------------------
The *generic* half of consequences: recording a decision, queueing its
authored chain, applying a fired step's effects, and wiring the result into
the causal graph. It does not know what a threat family is, and there is no
``if phishing / elif ransomware`` anywhere in it.

The *family-specific* half moved to :mod:`rewindsec.training.progression`,
which answers one question this module asks twice -- at scheduling and at
firing: may this step happen at all? A ransomware step that writes to a
network share cannot happen on a workstation that has been taken off the
network, and without that question "isolate the machine" would be a button
that changed a flag and nothing else.

Determinism and resume
----------------------
A step's fire time is ``now + authored_delay * mode_scale``, computed in
simulation milliseconds at scheduling time and persisted with the scheduler
entry. Nothing about it depends on the wall clock, on how long the browser was
open, or on whether anyone was connected. Persist a session mid-chain, throw
the process away, rebuild the repository, advance the clock, and the same
events fire at the same times in the same order with the same ids -- which is
what ``tests/test_rewindsec2_workstation_resume.py`` asserts.

No automatic rewind
-------------------
Nothing here undoes anything. A consequence chain only ever adds to the world.
When a chain reaches its authored settling step the session may become
*eligible* to show the safer-alternative comparison, and that comparison is an
explanation -- the factual world it describes stays exactly as it is.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.training import progression
from rewindsec.workstation import worldops
from rewindsec.workstation.bootstrap import (NS_DECISIONS, NS_INCIDENTS,
                                             NS_SESSION)
from rewindsec.workstation.content import index as ix

__all__ = ["CONSEQUENCE_EVENT_TYPE", "record_decision", "already_decided",
           "apply_step_event", "chain_for_decision", "safer_alternative_for"]

#: The one event type a scheduled authored consequence fires as. Behavioural,
#: not a classification: nothing in the type tells a learner what family of
#: thing just happened to them.
CONSEQUENCE_EVENT_TYPE = "consequence.step"

#: Namespace mapping ``"<decision_id>:<step_id>"`` to the id of the
#: :class:`~rewindsec.domain.incidents.Consequence` recorded for it, so a
#: later step can name its causal parent after a resume.
NS_CONSEQUENCE_MAP = "consequence_map"


def already_decided(session, decision_id):
    """Whether this decision has been recorded in this session before.

    Decisions are recorded once. A learner who reports the same message twice
    has done one thing, and applying its chain twice would double every
    consequence in it.
    """
    return session.world.has(NS_DECISIONS, decision_id)


def chain_for_decision(decision_id):
    definition = ix.DECISION_BY_ID.get(decision_id) or {}
    return ix.CHAIN_BY_ID.get(definition.get("chain"))


def safer_alternative_for(decision_id):
    return ix.SAFER_BY_DECISION.get(decision_id)


def record_decision(session, decision_id, action_id, where, mode_flags,
                    cause_event_id=None):
    """Record one consequential decision and schedule its authored chain.

    Returns the id of the event that represents the decision, or ``None`` if
    the decision is unknown or has already been made. The event is internal:
    the *decision* is a piece of authored pedagogy vocabulary, and a
    learner-visible event named after one would be a label.
    """
    definition = ix.DECISION_BY_ID.get(decision_id)
    if definition is None or already_decided(session, decision_id):
        return None

    seq = worldops.next_seq(session, "decision_seq")
    event = session.record_immediate_event(
        "decision.recorded", payload={"decision": decision_id},
        source=EventSource.LEARNER, visibility=EventVisibility.INTERNAL,
        causes=(cause_event_id,) if cause_event_id else ())

    session.mutate_world(NS_DECISIONS, decision_id, {
        "order": seq,
        "action_id": action_id,
        "where": where or "",
        "at_ms": session.now_ms,
    }, cause_event_id=event.event_id)

    chain = ix.CHAIN_BY_ID.get(definition.get("chain"))
    if chain is not None:
        _schedule_chain(session, chain, decision_id, action_id, mode_flags,
                        event.event_id)
    return event.event_id


def _schedule_chain(session, chain, decision_id, action_id, mode_flags,
                    cause_event_id):
    """Queue every step of an authored chain on the session's scheduler.

    The whole chain is scheduled up front rather than step-by-step. That is
    what makes the chain survive a resume without any live object holding it:
    the scheduler entries are part of the persisted session, and rebuilding
    the session from its snapshot rebuilds the pending chain exactly.
    """
    scale = mode_flags.get("consequence_delay_scale", 1.0)
    for step in chain["steps"]:
        if not progression.should_schedule(session, chain["id"], step["id"]):
            # Containment was already in force when this chain started. The
            # step is still queued -- so the chain keeps its shape, its timing
            # and its settling point -- but it is latched now, and when it
            # fires it will change nothing.
            progression.suppress(session, chain["id"], step["id"],
                                 "network_isolation",
                                 cause_event_id=cause_event_id)
        delay = int(max(1, round(step.get("delay_ms", 0) * scale)))
        session.schedule_event(
            CONSEQUENCE_EVENT_TYPE, delay_ms=delay,
            payload={
                "chain": chain["id"],
                "step": step["id"],
                "decision": decision_id,
                "action": action_id,
            },
            source=EventSource.CONSEQUENCE,
            visibility=EventVisibility.LEARNER_VISIBLE,
            scheduling_cause_event_id=cause_event_id)


def apply_step_event(session, event, mode_flags):
    """Apply one fired consequence step to the world and the causal graph.

    Called by the service for every fired event of type
    :data:`CONSEQUENCE_EVENT_TYPE`. Returns a dict describing what settled, if
    anything, so the caller can decide about the safer-alternative comparison
    -- this module never makes a pedagogy decision itself.
    """
    payload = event.payload
    chain = ix.CHAIN_BY_ID.get(payload.get("chain"))
    if chain is None:
        return {}
    step = _step(chain, payload.get("step"))
    if step is None:
        return {}

    if not progression.should_apply(session, chain["id"], step["id"]):
        # The step came due, but the effect it describes could not happen:
        # containment was already in force. No effect is applied, no incident
        # is opened and no consequence is recorded -- so nothing in the causal
        # graph points at something that did not occur.
        #
        # It still *settles* the chain if it was the settling step. The chain
        # has reached its resting point -- earlier than it would have, because
        # the learner stopped it -- and a Practice or Simulation learner is
        # owed the explanation either way.
        return {"chain": chain["id"], "step": step["id"],
                "decision": payload.get("decision"),
                "settled": step["id"] == chain.get("settles_after"),
                "suppressed": True, "summary": ""}

    decision_id = payload.get("decision")
    action_id = payload.get("action")
    incident_key = chain.get("incident_id")
    incident_id = None
    first_mutation = None

    if incident_key:
        incident_id, mutation = worldops.open_incident(
            session, incident_key, chain.get("title", "Incident"),
            _incident_note(step) or chain.get("title", ""),
            cause_event_id=event.event_id)
        first_mutation = first_mutation or mutation
        if mutation is not None and _chain_is_contained(session, chain):
            # The learner contained this before its first visible effect
            # landed. The incident is real -- something did happen to their
            # files -- and it opens already contained, because the steps that
            # would have spread it have been latched as never-to-happen.
            #
            # Generic on purpose: "a chain with latched steps opens contained"
            # is a statement about chains, not about ransomware, so a future
            # family gets the same behaviour without a branch here.
            worldops.set_incident_contained(session, incident_key, True,
                                            cause_event_id=event.event_id)

    for effect in step.get("effects", []):
        mutation = _apply_effect(session, effect, event.event_id)
        if mutation is not None and first_mutation is None:
            first_mutation = mutation

    if incident_id:
        parents = _parent_consequences(session, decision_id, step)
        consequence = session.record_consequence(
            incident_id,
            parent_consequence_ids=parents,
            cause_event_id=event.event_id,
            triggering_action_id=action_id,
            scheduled_delay_ms=step.get("delay_ms"),
            affected_namespace=(first_mutation.namespace
                                if first_mutation is not None else None),
            affected_key=(first_mutation.key
                          if first_mutation is not None else None),
            mutation_ref=(first_mutation.mutation_id
                          if first_mutation is not None else None),
            description=step.get("summary"))
        session.mutate_world(
            NS_CONSEQUENCE_MAP, "%s:%s" % (decision_id, step["id"]),
            consequence.consequence_id, cause_event_id=event.event_id)

    settled = step["id"] == chain.get("settles_after")
    return {
        "chain": chain["id"],
        "step": step["id"],
        "decision": decision_id,
        "settled": settled,
        "summary": step.get("summary", ""),
    }


def _chain_is_contained(session, chain):
    """Whether any step of this chain has been latched as suppressed."""
    return any(progression.should_apply(session, chain["id"], step["id"]) is False
               for step in chain["steps"])


def _step(chain, step_id):
    for step in chain["steps"]:
        if step["id"] == step_id:
            return step
    return None


def _incident_note(step):
    for effect in step.get("effects", []):
        if effect.get("type") == "incident":
            return effect.get("note")
    return None


def _parent_consequences(session, decision_id, step):
    """The causal parent of this step, if it has one that has already fired.

    ``cause == "decision"`` means a first-order effect and has no parent
    consequence -- its parent is the learner action, which the consequence
    records separately. A named parent that has not fired yet (possible if a
    later step has a shorter delay than its parent) simply yields no link
    rather than a dangling reference.
    """
    cause = step.get("cause")
    if not cause or cause == "decision":
        return ()
    parent = session.world.get(NS_CONSEQUENCE_MAP, "%s:%s" % (decision_id, cause))
    if parent and session.incidents.has_consequence(parent):
        return (parent,)
    return ()


# ---------------------------------------------------------------------------
# The effect vocabulary
# ---------------------------------------------------------------------------
#
# Exactly the vocabulary the authored chains use, and nothing else. An
# unrecognised effect type is ignored rather than guessed at; the prototype
# suite already asserts that every authored effect uses a type this table
# knows, so an ignored effect means the content and the engine have drifted
# and the suite says so.

def _apply_effect(session, effect, cause_event_id):
    kind = effect.get("type")

    if kind == "notification":
        return worldops.raise_notification(
            session, kind=effect.get("kind", "system"),
            title=effect.get("title", ""), body=effect.get("body", ""),
            opens=effect.get("opens"), cause_event_id=cause_event_id)

    if kind == "mail":
        mutation, _ = worldops.deliver_mail(
            session, effect.get("mail_id"), folder=effect.get("folder"),
            cause_event_id=cause_event_id)
        return mutation

    if kind == "mail_rule":
        return worldops.set_mailbox_rule(session, effect.get("text", ""),
                                         cause_event_id=cause_event_id)

    if kind == "file_state":
        return worldops.set_file_state(
            session, effect.get("file_id"), effect.get("state", "normal"),
            note=effect.get("note", ""), cause_event_id=cause_event_id)

    if kind == "message":
        return worldops.append_message(
            session, effect.get("conversation_id"), effect.get("from", ""),
            effect.get("text", ""), cause_event_id=cause_event_id)

    if kind == "mfa_prompt":
        mutation, _ = worldops.create_auth_request(
            session, effect.get("prompt_id"), cause_event_id=cause_event_id)
        return mutation

    if kind == "auth_activity":
        return worldops.record_auth_activity(
            session, app=effect.get("app", ""), result=effect.get("result", ""),
            device=effect.get("device", ""), location=effect.get("location", ""),
            when=None if effect.get("when") == "just now" else effect.get("when"),
            cause_event_id=cause_event_id)

    if kind == "task":
        return worldops.set_task(
            session, effect.get("task_id"), effect.get("state", "outstanding"),
            note=effect.get("text", ""), cause_event_id=cause_event_id)

    if kind == "incident":
        # Already handled before the effect loop, so that every other effect in
        # the step can point at an incident that exists.
        return None

    return None
