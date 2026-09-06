"""Whether a scheduled consequence step still makes sense when it comes due.

Batch 2 scheduled a decision's whole authored chain up front and applied every
step unconditionally when it fired. That is right for most chains and wrong
for exactly one thing: a step that needs the network cannot happen on a
workstation that has been taken off the network, and if it happens anyway then
"isolate the machine" is a button with no meaning.

The registry
------------
Family modules declare their own network-dependent steps as ``(chain_id,
step_id)`` pairs. This module is the union of those declarations and nothing
else -- no heuristics, no inspecting an effect to guess whether the file it
touches lives on a share. A step is network-dependent because the author said
so about the authored world.

The latch
---------
Suppression is a *latch*: written the moment containment happens, read when
the step comes due.

* **At isolation.** Every network-dependent step already pending is latched,
  with an internal event recording chain, step and reason.
* **At scheduling.** A chain that starts while isolation is already in force
  latches its network steps as it queues them.
* **At firing.** A latched step comes due, changes nothing, opens no incident
  and records no consequence -- so the causal graph never points at an effect
  that did not occur.

Leaving the scheduler entry queued rather than cancelling it is a deliberate
choice between the two designs the architecture allows. It keeps the chain's
shape, its timing, and above all its *settling point*: settling is what makes
a Practice or Simulation learner eligible for the safer-alternative
explanation, and a chain whose final step had been cancelled would simply
never finish. The suppression is auditable in its own right -- an internal
event at the simulation time it was decided, plus a latch persisted with the
session -- so nothing is lost by not cancelling.

The latch is also what makes reconnecting honest. A learner who isolates,
waits, and reconnects has not undone the containment that was in force while
the spread would have happened: the share was not reachable at the moment it
would have been written to, and that is a fact about the past. Re-deriving
suppression from the current network flag at fire time would let a reconnect
resurrect a consequence that had already been contained.

What suppression is not
-----------------------
It is not recovery, and it is not a rewind. Nothing here restores a file,
closes an incident, deletes a mailbox rule or reverses a payment. It stops a
*future* effect that isolation genuinely prevents, and leaves every effect
that already landed exactly where it is.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.training import state as engine_state
from rewindsec.training.families import (background, bec, mfa, phishing,
                                         ransomware)

__all__ = ["NETWORK_DEPENDENT", "is_network_dependent", "should_schedule",
           "should_apply", "on_isolation", "SUPPRESSION_EVENT_TYPE"]

#: The internal event a suppression records. Internal visibility: the learner
#: sees the *absence* of a consequence, which is the whole point, and an event
#: announcing "something was prevented" would be a hint.
SUPPRESSION_EVENT_TYPE = "consequence.suppressed"


def _collect():
    pairs = set()
    for module in (background, bec, mfa, phishing, ransomware):
        pairs.update(module.network_dependent_steps())
    return frozenset(pairs)


NETWORK_DEPENDENT = _collect()


def is_network_dependent(chain_id, step_id):
    return (chain_id, step_id) in NETWORK_DEPENDENT


def _latched(session, chain_id, step_id):
    return "%s:%s" % (chain_id, step_id) in engine_state.suppressed_steps(session)


def should_schedule(session, chain_id, step_id):
    """Whether this step will be able to do anything when it comes due.

    ``False`` only for a network-dependent step on a workstation that is
    already isolated -- in which case the caller queues it anyway and latches
    it, so the chain keeps its shape and its settling point.
    """
    if not engine_state.engine_is_active(session):
        return True
    if not is_network_dependent(chain_id, step_id):
        return True
    return not engine_state.is_isolated(session)


def should_apply(session, chain_id, step_id):
    """Whether a step that has just fired may be applied.

    Reads the latch rather than the current network flag, so a reconnect
    cannot revive a step whose effect isolation had already prevented.
    """
    if not engine_state.engine_is_active(session):
        return True
    return not _latched(session, chain_id, step_id)


def suppress(session, chain_id, step_id, reason, cause_event_id=None):
    """Latch one step as never-to-be-applied, and record why.

    A no-op on a session created before Batch 3. Those sessions have no engine
    state to latch into, and a consequence they were already expecting must
    not silently stop arriving halfway through their attempt.
    """
    if not engine_state.engine_is_active(session):
        return None
    if _latched(session, chain_id, step_id):
        return None
    event = session.record_immediate_event(
        SUPPRESSION_EVENT_TYPE,
        payload={"chain": chain_id, "step": step_id, "reason": reason},
        source=EventSource.SYSTEM, visibility=EventVisibility.INTERNAL,
        causes=(cause_event_id,) if cause_event_id else ())
    engine_state.latch_suppressed_step(session, chain_id, step_id,
                                       cause_event_id=event.event_id)
    return event.event_id


def on_isolation(session, cause_event_id=None):
    """Contain every network-dependent consequence that has not yet happened.

    Returns the ``(chain_id, step_id)`` pairs that were contained, in sorted
    order, so the caller can describe the containment truthfully rather than
    claim a result it did not produce -- and can say nothing at all when there
    was nothing to contain.

    Only *pending* steps are latched. A step that has already fired is
    history and is not touched: damage that has happened stays happened, which
    is the whole distinction between containment and recovery. Steps belonging
    to a chain that has not started are left alone too -- latching the entire
    registry here would suppress consequences of decisions the learner has not
    made and might never make.
    """
    from rewindsec.workstation.consequences import CONSEQUENCE_EVENT_TYPE

    if not engine_state.engine_is_active(session):
        return ()

    contained = []
    for entry in sorted(session.scheduler.pending(),
                        key=lambda item: (item.fire_at_ms, item.insertion_seq)):
        if entry.cancelled or entry.spec.type != CONSEQUENCE_EVENT_TYPE:
            continue
        payload = entry.spec.payload or {}
        chain_id = payload.get("chain")
        step_id = payload.get("step")
        if not is_network_dependent(chain_id, step_id):
            continue
        if suppress(session, chain_id, step_id, "network_isolation",
                    cause_event_id=cause_event_id) is not None:
            contained.append((chain_id, step_id))
    return tuple(sorted(contained))
