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
from rewindsec.training import recurrence
from rewindsec.workstation import worldops

__all__ = ["deliver", "ADAPTERS"]

#: Deterministic subject-line variants for a delivered mail, keyed by
#: ``content_ref``. Chosen from the ``content_variation`` stream at delivery
#: time -- the same stream the team-channel chatter and workstation nudges
#: already use, and for the same reason: an extra draw here must not move a
#: single threat-selection, timing or consequence draw. Wiring content
#: variation into an actual delivered mail (rather than only chatter/nudge
#: text) is what makes the runtime content pipeline's deterministic-variant
#: mechanism (:func:`rewindsec.content.generate.choose_variant`) reach a
#: real mailbox, not just its own test suite.
_SUBJECT_VARIANTS = {
    "m-facilities-followup": (
        "Quick look before it goes out?",
        "Two minutes for a second pair of eyes?",
    ),
}


def _deliver_mail(session, candidate, cause_event_id):
    """Deliver *candidate*'s mail, resolving a recurring occurrence first.

    Most candidates have exactly one occurrence, always the same mail id --
    ``occurrence_mail_id`` returns ``None`` for those and the target is
    simply ``candidate.content_ref``, unchanged from before this function
    knew about recurrence at all. A recurring candidate (see
    ``rewindsec.training.recurrence``) instead resolves the *n*-th physical
    mail id from its own occurrence count, which is read *before* this
    delivery succeeds -- the engine only bumps it afterward -- so occurrence
    0 is the candidate's first-ever delivery and occurrence 1 its second.
    """
    occurrence = _occurrence_count(session, candidate.candidate_id)
    target_mail_id = (recurrence.occurrence_mail_id(candidate.candidate_id, occurrence)
                      or candidate.content_ref)

    mutation, _ = worldops.deliver_mail(session, target_mail_id,
                                        cause_event_id=cause_event_id)
    if mutation is None:
        return False

    generated = recurrence.generated_surface(
        session, candidate.candidate_id, occurrence)
    if generated is not None:
        worldops.set_mail_field(session, target_mail_id,
                                cause_event_id=mutation.cause_event_id,
                                **generated)
    else:
        variants = _SUBJECT_VARIANTS.get(target_mail_id)
        if variants:
            stream = session.rng.stream(STREAM_CONTENT_VARIATION)
            subject = stream.choice(variants)
            worldops.set_mail_field(session, target_mail_id,
                                    cause_event_id=mutation.cause_event_id,
                                    subject_override=subject)
    return True


def _deliver_mfa(session, candidate, cause_event_id):
    occurrence = _occurrence_count(session, candidate.candidate_id)
    variant = recurrence.mfa_notification_variant(
        session, candidate.candidate_id, occurrence)
    mutation, _ = worldops.create_auth_request(
        session, candidate.content_ref, cause_event_id=cause_event_id,
        app_override=(variant["app"] if variant else None),
        notification_body=(variant["body"] if variant else None),
        content_variation_id=(variant["content_id"] if variant else None))
    return mutation is not None


def _occurrence_count(session, candidate_id):
    """How many times *candidate_id* has already been delivered, ever.

    Read from the engine's own persisted per-candidate state, which the
    engine bumps only *after* a delivery succeeds (see
    ``rewindsec.training.engine._after_selection`` and ``.force_candidate``)
    -- so this is always the 0-based index of the occurrence about to be
    attempted, consistent whether the arrival came from the lottery or from
    forced development tooling.
    """
    from rewindsec.training import state as engine_state
    return engine_state.candidate_state(session, candidate_id)["occurrences"]


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
