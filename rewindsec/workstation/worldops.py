"""The primitive world operations every learner action and consequence uses.

One place where "a message is delivered", "a file becomes unreadable", "a
notification is raised" are actually written down. Both the action handlers in
:mod:`rewindsec.workstation.service` and the authored consequence engine in
:mod:`rewindsec.workstation.consequences` call through here, so a learner
reporting a message and a consequence chain filing one away go through the
same code and cannot drift into two different notions of what a folder is.

Every function here takes the session and returns the
:class:`~rewindsec.domain.world.WorldMutation` it produced (or ``None`` when
nothing changed), because the causal graph needs the mutation id to point at.
None of them decide *whether* something should happen -- that judgement lives
with the caller. These are the verbs, not the rules.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.workstation import clock
from rewindsec.workstation.bootstrap import (NS_AUTH_HISTORY, NS_AUTH_REQUESTS,
                                             NS_BROWSER, NS_FILES, NS_INCIDENTS,
                                             NS_MAIL, NS_MAILBOX, NS_MAIL_SENT,
                                             NS_MESSAGES, NS_NOTES,
                                             NS_NOTIFICATIONS, NS_SESSION,
                                             NS_TASKS, introduce_document_fact,
                                             mail_attachment_fact,
                                             mail_body_fact, mail_header_fact,
                                             mail_link_fact, prompt_fact)
from rewindsec.workstation.content import index as ix

__all__ = [
    "deliver_mail", "set_mail_field", "add_sent_mail", "set_mailbox_rule",
    "raise_notification", "set_file_state", "add_downloaded_file",
    "append_message", "create_auth_request", "record_auth_activity",
    "set_task", "open_incident", "set_incident_contained", "set_browser_state",
    "set_session_flag", "set_note", "next_seq", "resolve_download_name",
    "payment_release_key", "available_payment_contexts",
]

#: Security Operations mail is what the authored mailbox rule hides. Kept as a
#: named constant because it is a rule about one address, not a rule about
#: "suspicious senders", and burying it in a conditional would make it look
#: like the latter.
_RULE_FILED_SENDER = "security@northbridge.example"


def next_seq(session, key):
    """Allocate and persist the next value of a named world counter.

    World-level counters (notification ids, sent-mail ids, note ids) have to
    survive a resume and have to be identical on a replay, so they live in the
    world rather than in a Python variable.
    """
    current = session.world.get(NS_SESSION, key, 0)
    if not isinstance(current, int) or isinstance(current, bool):
        current = 0
    session.mutate_world(NS_SESSION, key, current + 1)
    return current + 1


# ---------------------------------------------------------------------------
# Mail
# ---------------------------------------------------------------------------

def set_mail_field(session, mail_id, cause_event_id=None, **changes):
    """Merge *changes* into a message's world record."""
    state = session.world.get(NS_MAIL, mail_id)
    if state is None:
        return None
    updated = dict(state)
    updated.update(changes)
    if updated == state:
        # Recorded anyway: a consequence that re-confirms state is still a
        # consequence, and the causal graph may need to point at it.
        pass
    return session.mutate_world(NS_MAIL, mail_id, updated,
                                cause_event_id=cause_event_id)


def deliver_mail(session, mail_id, folder=None, cause_event_id=None):
    """Put an authored message into the mailbox for the first time.

    Returns ``(mutation, notification_mutation)``; both are ``None`` when the
    message was already delivered, so a repeated delivery is a no-op rather
    than a duplicate arrival.

    The mailbox rule created earlier in a consequence chain is applied *here*,
    at delivery, rather than by the rule's own step: that is what makes it
    behave like a rule -- it files a message that has not arrived yet -- and it
    is why the Security Operations follow-up is genuinely missed rather than
    merely displayed differently.
    """
    state = session.world.get(NS_MAIL, mail_id)
    if state is None or state.get("delivered"):
        return None, None

    message = ix.MAIL_BY_ID.get(mail_id)
    if message is None:
        return None, None
    surface = message["surface"]

    target_folder = folder or state.get("folder") or "inbox"
    rule = session.world.get(NS_MAILBOX, "rule")
    if rule and surface.get("from_address") == _RULE_FILED_SENDER:
        target_folder = "archive"

    event = session.record_immediate_event(
        "mail.delivered", payload={"message": mail_id, "folder": target_folder},
        source=EventSource.WORLD if cause_event_id is None else EventSource.CONSEQUENCE,
        visibility=EventVisibility.LEARNER_VISIBLE,
        causes=(cause_event_id,) if cause_event_id else ())

    mutation = session.mutate_world(NS_MAIL, mail_id, dict(
        state, delivered=True, unread=True, read=False,
        folder=target_folder, received=clock.workday_label(session.now_ms),
        delivered_at_ms=session.now_ms),
        cause_event_id=event.event_id)

    _make_mail_facts_available(session, message)

    notification = None
    if target_folder != "archive":
        notification = raise_notification(
            session, kind="mail", title=surface.get("from_name", ""),
            body=surface.get("subject", ""),
            opens={"app": "mail", "mail_id": mail_id},
            cause_event_id=event.event_id)
    return mutation, notification


def _make_mail_facts_available(session, message):
    """A delivered message makes its own details available -- not observed."""
    mail_id = message["id"]
    surface = message["surface"]
    ids = [mail_body_fact(mail_id), mail_header_fact(mail_id)]
    ids.extend(mail_link_fact(mail_id, i)
               for i in range(len(surface.get("links") or [])))
    ids.extend(mail_attachment_fact(mail_id, i)
               for i in range(len(surface.get("attachments") or [])))
    for key in ((message.get("analysis") or {}).get("establishes_context") or ()):
        ids.append("org.%s" % key)
    for fact_id in ids:
        if session.ledger.has(fact_id) and not session.ledger.get(fact_id).available:
            session.make_fact_available(fact_id)


def add_sent_mail(session, subject, to, body, cause_event_id=None):
    """Record a reply the learner actually wrote, in the Sent folder.

    Stored because the learner deliberately authored it and the mailbox would
    be incoherent without it -- not as telemetry. It is plain text, bounded by
    :mod:`rewindsec.workstation.actions`, and rendered as text.
    """
    seq = next_seq(session, "sent_seq")
    sent_id = "m-sent-%d" % seq
    session.mutate_world(NS_MAIL_SENT, sent_id, {
        "subject": subject,
        "to": to,
        "body": body,
        "received": clock.workday_label(session.now_ms),
        "order": 900 + seq,
    }, cause_event_id=cause_event_id)
    return sent_id


def set_mailbox_rule(session, text, cause_event_id=None):
    return session.mutate_world(NS_MAILBOX, "rule", text,
                                cause_event_id=cause_event_id)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def raise_notification(session, kind, title, body, opens=None,
                       cause_event_id=None):
    """Add one notification. Ordering is a persisted counter, not a timestamp.

    Two notifications raised in the same simulation millisecond still have a
    defined order, and that order is identical after a resume.
    """
    seq = next_seq(session, "notification_seq")
    notification_id = "n-%d" % seq
    event = session.record_immediate_event(
        "notification.raised", payload={"notification": notification_id,
                                        "kind": kind},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.WORLD,
        causes=(cause_event_id,) if cause_event_id else ())
    return session.mutate_world(NS_NOTIFICATIONS, notification_id, {
        "order": seq,
        "kind": kind,
        "title": title,
        "body": body,
        "when": clock.workday_label(session.now_ms),
        "opens": opens,
        "unread": True,
    }, cause_event_id=event.event_id)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def set_file_state(session, file_id, state, note="", cause_event_id=None):
    """Change a synthetic file's readability.

    Nothing on the host filesystem is touched, now or ever: a file here is a
    row in the world, and "unavailable" is a value in that row. The Docker
    integration that gives ransomware effects real isolated technical state is
    a later batch and does not run from this function.
    """
    current = session.world.get(NS_FILES, file_id)
    if current is None:
        return None
    event = session.record_immediate_event(
        "file.state_changed", payload={"file": file_id, "state": state},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.WORLD,
        causes=(cause_event_id,) if cause_event_id else ())
    display = current.get("name")
    if state == "unavailable" and display and ".demo_locked" not in display:
        display = "%s.demo_locked" % display
    return session.mutate_world(NS_FILES, file_id, dict(
        current, state=state, note=note or "", display_name=display),
        cause_event_id=event.event_id)


def _split_extension(name):
    """Split a filename the way a file manager does: stem, then extension.

    Only the *last* dot separates an extension, which is why
    ``archive.tar.gz`` has the stem ``archive.tar`` and not ``archive``, and
    a name with no dot at all has no extension. A leading dot is part of the
    stem -- ``.profile`` is a name, not an extension -- so a copy of it is
    ``.profile (1)`` rather than the nonsense `` (1).profile``.
    """
    dot = name.rfind(".")
    if dot <= 0:
        return name, ""
    return name[:dot], name[dot:]


def resolve_download_name(session, location_id, name):
    """The name a download will actually be saved under in *location_id*.

    A download never lands on top of a file the learner already has. If the
    name is free it is used unchanged; if it is taken, the first free
    ``name (n).ext`` is used instead, counting up from one -- the "keep both"
    behaviour every desktop file manager has, so a learner who downloads the
    invoice they were already sent can see that they now have two of them.

    Three properties this has to have, and has:

    * It is decided **here**, on the server. The client asks to download an
      attachment; it does not get to say what the file ends up called, and
      there is no parameter through which it could.
    * It is a pure function of world state -- the names currently in that
      folder -- so it consumes no randomness, reads no clock and touches
      nothing outside the synthetic world. Two identical sessions resolve
      identical names, and a resumed session resolves the same name it would
      have before it was saved.
    * Comparison is case-insensitive, because this synthetic workstation
      presents itself as an ordinary desktop: ``Report.PDF`` and
      ``report.pdf`` are the same file to a learner looking at the folder,
      and treating them as different would put two rows in the Files app that
      appear to be the same file.

    Deleted files hold no name: the learner cannot see them in the Files app,
    so a name they freed is free.
    """
    taken = set()
    for state in session.world.get_component(NS_FILES).values():
        if state.get("deleted") or state.get("location") != location_id:
            continue
        existing = str(state.get("name") or "")
        if existing:
            taken.add(existing.lower())

    if name.lower() not in taken:
        return name

    stem, extension = _split_extension(name)
    counter = 1
    # Bounded by the number of names already in the folder: each turn of the
    # loop either returns or rules out one of them.
    while True:
        candidate = "%s (%d)%s" % (stem, counter, extension)
        if candidate.lower() not in taken:
            return candidate
        counter += 1


def add_downloaded_file(session, file_id, location_id, name, kind, size,
                        source, macro, origin_mail, cause_event_id=None):
    """Materialise a downloaded attachment as a file in Downloads.

    Downloading the same attachment twice is not two files: the file id is
    derived from what was downloaded, so the second attempt finds the first
    one already there and changes nothing. Two *different* downloads that
    happen to share a filename are two files, and the second one is renamed
    rather than allowed to sit on top of the first -- see
    :func:`resolve_download_name`.
    """
    existing = session.world.get(NS_FILES, file_id)
    if existing is not None:
        return None
    introduce_document_fact(session, file_id)
    return session.mutate_world(NS_FILES, file_id, {
        "location": location_id,
        "name": resolve_download_name(session, location_id, name),
        "display_name": None,
        "kind": kind,
        "size": size,
        "modified": clock.workday_label(session.now_ms),
        "state": "downloaded",
        "note": "",
        "owner": None,
        "source": source,
        "preview": [],
        "order": 0,
        "macro": bool(macro),
        "origin_mail": origin_mail,
    }, cause_event_id=cause_event_id)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def append_message(session, conversation_id, sender, text, unread=True,
                   cause_event_id=None):
    conversation = session.world.get(NS_MESSAGES, conversation_id)
    if conversation is None:
        return None
    event = session.record_immediate_event(
        "message.received", payload={"conversation": conversation_id},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.LEARNER,
        causes=(cause_event_id,) if cause_event_id else ())
    entries = list(conversation.get("entries") or [])
    entries.append({"from": sender, "when": clock.workday_label(session.now_ms),
                    "text": text})
    return session.mutate_world(NS_MESSAGES, conversation_id, dict(
        conversation, entries=entries, unread=bool(unread)),
        cause_event_id=event.event_id)


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

def create_auth_request(session, prompt_id, cause_event_id=None,
                        app_override=None, notification_body=None,
                        content_variation_id=None):
    """Raise one approval request, unless an identical one is already pending.

    The request id is derived from a persisted counter rather than from the
    prompt id alone, because the same authored prompt can legitimately be
    raised twice in one session and the learner has to be able to act on each.

    *app_override*, *notification_body* and *content_variation_id* are an
    optional, deterministic content-variation choice made by the caller (see
    ``rewindsec.training.recurrence``) -- the authored prompt surface
    (application, device, location, network) is unchanged and remains the
    only thing the learner can actually inspect; only the request's own
    displayed application label and its arrival notification's wording may
    vary between two requests raised from the same authored prompt.
    """
    for key, value in session.world.get_component(NS_AUTH_REQUESTS).items():
        if value.get("prompt_id") == prompt_id and value.get("status") == "pending":
            return None, None
    if prompt_id not in ix.PROMPT_BY_ID:
        return None, None

    seq = next_seq(session, "auth_seq")
    request_id = "req-%d" % seq
    event = session.record_immediate_event(
        "auth.request_created", payload={"request": request_id},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.WORLD,
        causes=(cause_event_id,) if cause_event_id else ())
    mutation = session.mutate_world(NS_AUTH_REQUESTS, request_id, {
        "prompt_id": prompt_id,
        "status": "pending",
        "arrived": clock.workday_label(session.now_ms),
        "order": seq,
        "at_ms": session.now_ms,
        "app_override": app_override,
        "content_variation_id": content_variation_id,
    }, cause_event_id=event.event_id)

    fact_id = prompt_fact(prompt_id)
    if session.ledger.has(fact_id) and not session.ledger.get(fact_id).available:
        session.make_fact_available(fact_id)

    surface = ix.PROMPT_BY_ID[prompt_id]["surface"]
    body = notification_body or "%s . %s" % (
        surface.get("app", ""), surface.get("location", ""))
    notification = raise_notification(
        session, kind="auth", title="Approval requested", body=body,
        opens={"app": "authenticator"}, cause_event_id=event.event_id)
    return mutation, notification


def record_auth_activity(session, app, result, device, location, when=None,
                         cause_event_id=None):
    seq = next_seq(session, "auth_history_seq")
    entry_id = "auth-run-%d" % seq
    event = session.record_immediate_event(
        "auth.activity_recorded", payload={"entry": entry_id},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.WORLD,
        causes=(cause_event_id,) if cause_event_id else ())
    return session.mutate_world(NS_AUTH_HISTORY, entry_id, {
        # Newly recorded activity sorts above the authored history, which uses
        # ordinals from zero upward.
        "order": 1000 + seq,
        "app": app,
        "result": result,
        "device": device,
        "location": location,
        "when": when or clock.workday_label(session.now_ms),
    }, cause_event_id=event.event_id)


# ---------------------------------------------------------------------------
# Tasks and incidents
# ---------------------------------------------------------------------------

def set_task(session, task_id, state, note="", cause_event_id=None):
    current = session.world.get(NS_TASKS, task_id)
    if current is None:
        return None
    event = session.record_immediate_event(
        "task.updated", payload={"task": task_id, "state": state},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.LEARNER,
        causes=(cause_event_id,) if cause_event_id else ())
    return session.mutate_world(NS_TASKS, task_id, dict(
        current, state=state, note=note or current.get("note", "")),
        cause_event_id=event.event_id)


def payment_release_key(context_id):
    """The :data:`NS_BROWSER` key holding one release-queue entry's outcome.

    One key per *payment context*, never one per page. Two occurrences of a
    recurring BEC surface settle the same invoice of record through the same
    payments page, and a single page-wide "released" flag would make the
    second occurrence unreachable the moment the first was actioned -- which
    is exactly the blocker this correction removes.
    """
    return "payment_released:%s" % context_id


def _payment_context_available(session, context):
    """Whether this release-queue entry has actually been raised yet.

    A context with no ``requires_mail`` is part of the ordinary release queue
    and is available from the start of the session: the invoice is genuinely
    due whether or not anybody ever asks for the account to be changed. A
    context that names one is a *second* release request raised by a later
    occurrence, and it does not exist until that occurrence's message has
    actually been delivered -- so a client cannot settle a payment nothing in
    the learner's day has raised, and cannot use the presence of a second
    queue entry to learn that a second message is coming.
    """
    required = context.get("requires_mail")
    if not required:
        return True
    state = session.world.get(NS_MAIL, required)
    return bool(state and state.get("delivered"))


def available_payment_contexts(session, url):
    """The release-queue entries on one page that have actually been raised."""
    return tuple(context for context in ix.payment_contexts_for_page(url)
                 if _payment_context_available(session, context))


def open_incident(session, incident_key, title, note, cause_event_id=None):
    """Open (or reuse) one incident, in the world *and* in the causal graph.

    Two records, deliberately. The :class:`~rewindsec.domain.incidents
    .IncidentGraph` entry is the causal spine that the debrief walks; the world
    row is what the workstation shows -- a banner in Files, an entry on the
    Service Desk page. They are kept in step here so neither can exist without
    the other.
    """
    existing = session.world.get(NS_INCIDENTS, incident_key)
    if existing is not None:
        return existing.get("incident_id"), None

    event = session.record_immediate_event(
        "incident.opened", payload={"incident": incident_key},
        source=EventSource.CONSEQUENCE if cause_event_id else EventSource.WORLD,
        visibility=EventVisibility.LEARNER_VISIBLE,
        causes=(cause_event_id,) if cause_event_id else ())
    incident = session.open_incident(title, opening_event_id=event.event_id)
    mutation = session.mutate_world(NS_INCIDENTS, incident_key, {
        "incident_id": incident.incident_id,
        "title": title,
        "note": note,
        "contained": False,
        "opened": clock.workday_label(session.now_ms),
        "opened_at_ms": session.now_ms,
    }, cause_event_id=event.event_id)
    return incident.incident_id, mutation


def set_incident_contained(session, incident_key, contained=True,
                           cause_event_id=None):
    current = session.world.get(NS_INCIDENTS, incident_key)
    if current is None:
        return None
    updated = dict(current, contained=bool(contained))
    if contained and "contained_at_ms" not in current:
        # Recorded once, at first containment -- an opportunity's timestamp
        # must not move if the same containment is (harmlessly) re-recorded.
        updated["contained_at_ms"] = session.now_ms
    return session.mutate_world(NS_INCIDENTS, incident_key, updated,
                                cause_event_id=cause_event_id)


def set_incident_recovered(session, incident_key, cause_event_id=None):
    """Mark an incident recovered: a fact layered *on top of* containment.

    Distinct from :func:`set_incident_contained` on purpose -- Architecture
    Spec v1.1 (Batch 4) S24 requires containment and recovery to remain
    separate facts. Recovering does not close, delete or reopen the incident;
    it does not touch ``contained``; it is simply one more true statement
    about what happened to this incident, after the fact it describes.
    """
    current = session.world.get(NS_INCIDENTS, incident_key)
    if current is None:
        return None
    return session.mutate_world(NS_INCIDENTS, incident_key, dict(
        current, recovered=True), cause_event_id=cause_event_id)


def set_browser_state(session, key, value, cause_event_id=None):
    return session.mutate_world(NS_BROWSER, key, value,
                                cause_event_id=cause_event_id)


def set_session_flag(session, key, value, cause_event_id=None):
    return session.mutate_world(NS_SESSION, key, value,
                                cause_event_id=cause_event_id)


def set_note(session, note_id, title, body, order, cause_event_id=None):
    return session.mutate_world(NS_NOTES, note_id, {
        "title": title,
        "body": body,
        "updated": clock.workday_label(session.now_ms),
        "order": order,
    }, cause_event_id=cause_event_id)
