"""How a selected candidate becomes something on the learner's screen.

One adapter per activity kind, and every one of them goes through
:mod:`rewindsec.workstation.worldops`. That is the rule architecture S17 turns
into code: a message arriving because the engine chose it and a message
arriving because a consequence chain scheduled it are the same world
operation, recorded the same way, with the same causal event and the same
notification behaviour. No adapter here writes a raw world dictionary, and no
adapter invents a folder, a counter or an id of its own.

An adapter reports whether it actually changed anything. A delivery can
legitimately be a no-op -- the same approval request is already pending, the
message was already in the mailbox -- and the engine has to know, because a
family that "fired" without producing anything must not consume its
occurrence, reset its pressure or start its cooldown.
"""

from rewindsec.core.rng import STREAM_CONTENT_VARIATION
from rewindsec.workstation import worldops

__all__ = ["deliver", "ADAPTERS"]


def _deliver_mail(session, candidate, cause_event_id):
    mutation, _ = worldops.deliver_mail(session, candidate.content_ref,
                                        cause_event_id=cause_event_id)
    return mutation is not None


def _deliver_mfa(session, candidate, cause_event_id):
    mutation, _ = worldops.create_auth_request(session, candidate.content_ref,
                                               cause_event_id=cause_event_id)
    return mutation is not None


def _deliver_chatter(session, candidate, cause_event_id):
    """One line of ordinary team-channel talk.

    The line is chosen from the ``content_variation`` stream, which is the
    only stream this adapter touches. An extra line in the list changes which
    line appears and nothing else in the simulation.
    """
    from rewindsec.training.families import background

    stream = session.rng.stream(STREAM_CONTENT_VARIATION)
    text = stream.choice(background.CHATTER)
    mutation = worldops.append_message(
        session, candidate.content_ref, "Operations team", text,
        cause_event_id=cause_event_id)
    return mutation is not None


def _deliver_nudge(session, candidate, cause_event_id):
    from rewindsec.training.families import background

    stream = session.rng.stream(STREAM_CONTENT_VARIATION)
    title, body = stream.choice(background.NUDGES)
    mutation = worldops.raise_notification(
        session, kind="system", title=title, body=body, opens=None,
        cause_event_id=cause_event_id)
    return mutation is not None


#: The closed adapter table. A candidate naming a delivery that is not here is
#: a catalogue error, and :func:`deliver` says so rather than silently doing
#: nothing -- a delivery that quietly failed would look exactly like a family
#: that was never eligible.
ADAPTERS = {
    "mail": _deliver_mail,
    "mfa": _deliver_mfa,
    "chatter": _deliver_chatter,
    "nudge": _deliver_nudge,
}


def deliver(session, candidate, cause_event_id=None):
    """Materialise *candidate*. Returns whether the world actually changed."""
    adapter = ADAPTERS.get(candidate.delivery)
    if adapter is None:
        raise KeyError("no delivery adapter for %r" % candidate.delivery)
    return bool(adapter(session, candidate, cause_event_id))
