"""Seeding one session's authoritative world and context ledger.

This runs exactly once per session, at creation, and it is the moment the
authored content in :mod:`rewindsec.workstation.content` stops being the
truth. Afterwards the truth is the session's
:class:`~rewindsec.domain.world.WorldState` and
:class:`~rewindsec.domain.context_ledger.ContextLedger`; the content modules
are consulted only to resolve an authored *definition* by id -- what a browser
page contains, what a chain's next step is -- never to find out what has
happened.

Batch 2 boundary
----------------
Seeding from one fixed authored scenario is not the Batch 3 training engine.
There is no generation here, no threat-family selection, no eligibility
evaluation and no hazard state. What this module establishes is the
*mechanism* those will use: a world made of namespaced, auditable components,
and a ledger in which every fact records whether the workplace has made it
available and whether the learner has actually looked at it.

The available/observed split
----------------------------
Architecture spec S7 makes ``AVAILABLE != OBSERVED`` first-class, and this
module is where that distinction is given its content. A fact becomes
*available* when the simulated workplace surfaces the thing that carries it --
a message arriving makes its headers available. It becomes *observed* only
when the learner performs the action that actually reveals it, which for a
header means opening the header, not receiving the mail. The projection
enforces the second half of the bargain by withholding an inspection-only
value until its fact is observed, so "available but unobserved" is a real
state of the learner's screen and not just a flag in a database.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.workstation import clock
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.content import scenario, world

__all__ = [
    "seed_session", "NS_MAIL", "NS_MAIL_SENT", "NS_MAILBOX", "NS_FILES",
    "NS_NOTES", "NS_MESSAGES", "NS_AUTH_REQUESTS", "NS_AUTH_HISTORY",
    "NS_NOTIFICATIONS", "NS_BROWSER", "NS_TASKS", "NS_INCIDENTS",
    "NS_SESSION", "NS_DECISIONS", "NS_DIRECTORY", "NS_FILE_LOCATIONS", "mail_header_fact", "mail_link_fact",
    "mail_attachment_fact", "mail_body_fact", "prompt_fact", "contact_fact",
    "contact_callback_fact", "file_fact", "conversation_fact", "page_fact",
    "context_fact", "AUTH_HISTORY_FACT",
]

# -- world namespaces --------------------------------------------------------
#
# One namespace per workstation application plus three for session-level
# bookkeeping. Keys inside a namespace are the ids the content authored, so a
# world dump reads as "this is what happened to m-rate-card" rather than as an
# opaque blob.

NS_MAIL = "mail"
NS_MAIL_SENT = "mail_sent"
NS_MAILBOX = "mailbox"
NS_FILES = "files"
NS_FILE_LOCATIONS = "file_locations"
NS_NOTES = "notes"
NS_MESSAGES = "messages"
NS_AUTH_REQUESTS = "auth_requests"
NS_AUTH_HISTORY = "auth_history"
NS_NOTIFICATIONS = "notifications"
NS_BROWSER = "browser"
NS_TASKS = "tasks"
NS_INCIDENTS = "incidents"
NS_DIRECTORY = "directory"
NS_SESSION = "session"
NS_DECISIONS = "decisions"


# -- fact ids ----------------------------------------------------------------
#
# Built by rule rather than authored, so a new message automatically gets the
# same fact vocabulary as every other message and cannot quietly be born
# without one.

def mail_header_fact(mail_id):
    return "mail.%s.headers" % mail_id


def mail_body_fact(mail_id):
    return "mail.%s.body" % mail_id


def mail_link_fact(mail_id, index):
    return "mail.%s.link.%d" % (mail_id, index)


def mail_attachment_fact(mail_id, index):
    return "mail.%s.attachment.%d" % (mail_id, index)


def prompt_fact(prompt_id):
    return "auth.%s.context" % prompt_id


def contact_fact(contact_id):
    return "directory.%s.record" % contact_id


def contact_callback_fact(contact_id):
    return "directory.%s.callback" % contact_id


def file_fact(file_id):
    return "file.%s.metadata" % file_id


def conversation_fact(conversation_id):
    return "messages.%s.thread" % conversation_id


def page_fact(url):
    return "browser.%s.page" % ix.url_slug(url)


def context_fact(key):
    """A fact an authored message ``establishes_context`` for.

    These are the organisational facts a later hard event may depend on --
    which host payroll actually uses, which address the service desk sends
    from. Making them explicit is what lets a future eligibility rule ask
    "was this available?" without asking "did the learner read message
    seven?".
    """
    return "org.%s" % key


AUTH_HISTORY_FACT = "auth.history"

#: Fact ids are constrained by the domain to ``[A-Za-z0-9_.:-]``; the authored
#: ids all satisfy it, and this is the guard that says so out loud rather than
#: failing three layers down inside the ledger.
_FACT_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:")


def _fact_id(value):
    text = str(value)
    if not text or len(text) > 128:
        raise ValueError("fact id %r is out of bounds" % text)
    for char in text:
        if char not in _FACT_ID_CHARS:
            raise ValueError("fact id %r contains %r" % (text, char))
    return text


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------

def seed_session(session, delivered_arrivals=("opening",)):
    """Populate *session* with the authored starting workplace.

    ``delivered_arrivals`` names which authored ``arrival`` values are already
    in the mailbox when the learner sits down. Everything else exists in the
    world as undelivered -- present, but not yet part of the learner's day --
    which is what lets a later delivery be a real world mutation with a real
    causal event rather than an item appearing from nowhere.
    """
    now = session.now_ms

    start_event = session.record_immediate_event(
        "session.started",
        payload={"focus": session.focus.value, "mode": session.mode.value},
        source=EventSource.SYSTEM,
        visibility=EventVisibility.INTERNAL)

    _seed_mail(session, delivered_arrivals, start_event.event_id)
    _seed_files(session)
    _seed_notes(session)
    _seed_messages(session)
    _seed_authenticator(session)
    _seed_notifications(session)
    _seed_directory(session)
    _seed_browser(session)
    _seed_tasks(session)
    _seed_session_flags(session)

    return start_event


def _seed_mail(session, delivered_arrivals, start_event_id):
    for message in ix.ALL_MAIL:
        delivered = message.get("arrival") in delivered_arrivals
        session.mutate_world(NS_MAIL, message["id"], {
            "folder": message.get("folder", "inbox"),
            "delivered": delivered,
            "unread": bool(message.get("unread")) if delivered else False,
            "read": (not message.get("unread")) if delivered else False,
            "reported": False,
            "forwarded": False,
            "replied": False,
            "order": message.get("order", 0),
            "received": message.get("received", ""),
        }, cause_event_id=start_event_id if delivered else None)
        _introduce_mail_facts(session, message, available=delivered,
                              event_id=start_event_id if delivered else None)

    session.mutate_world(NS_MAILBOX, "rule", None)


def _introduce_mail_facts(session, message, available, event_id):
    """Every inspectable detail of one message, as ledger facts.

    Note what is *not* here: the subject, the sender's display name and the
    body are not inspection-only, because a mail client shows them the moment
    you open the message. What is inspection-only is the full header, where a
    link actually points, and an attachment's type and provenance -- the
    things a learner has to go and look at.
    """
    surface = message["surface"]
    mail_id = message["id"]

    session.introduce_fact(
        _fact_id(mail_body_fact(mail_id)), category="mail_content",
        value={"subject": surface.get("subject", "")},
        source="mailbox", introduced_by_event_id=event_id, available=available)

    session.introduce_fact(
        _fact_id(mail_header_fact(mail_id)), category="mail_header",
        value={
            "from_address": surface.get("from_address", ""),
            "reply_to": surface.get("reply_to") or surface.get("from_address", ""),
            "to": surface.get("to", ""),
            "cc": surface.get("cc"),
        },
        source="mailbox", introduced_by_event_id=event_id, available=available)

    for index, link in enumerate(surface.get("links") or []):
        session.introduce_fact(
            _fact_id(mail_link_fact(mail_id, index)), category="mail_link",
            value={"text": link.get("text", ""), "href": link.get("href", "")},
            source="mailbox", introduced_by_event_id=event_id,
            available=available)

    for index, attachment in enumerate(surface.get("attachments") or []):
        session.introduce_fact(
            _fact_id(mail_attachment_fact(mail_id, index)),
            category="mail_attachment",
            value={
                "name": attachment.get("name", ""),
                "size": attachment.get("size", ""),
                "kind_label": ix.attachment_kind_label(attachment.get("kind")),
                "sender": surface.get("from_address", ""),
            },
            source="mailbox", introduced_by_event_id=event_id,
            available=available)

    for key in ((message.get("analysis") or {}).get("establishes_context") or ()):
        fact_id = _fact_id(context_fact(key))
        # Several messages can establish the same organisational fact; the
        # first one to arrive introduces it, later ones only make it available.
        if session.ledger.has(fact_id):
            if available and not session.ledger.get(fact_id).available:
                session.make_fact_available(fact_id)
            continue
        session.introduce_fact(
            fact_id, category="organisation_fact",
            value={"key": key, "established_by": mail_id},
            source="workplace history", introduced_by_event_id=event_id,
            available=available)


def _seed_files(session):
    for order, location in enumerate(world.FILE_TREE):
        session.mutate_world(NS_FILE_LOCATIONS, location["id"], {
            "name": location.get("name", ""),
            "path": location.get("path", ""),
            "order": order,
        })
        for position, entry in enumerate(location["files"]):
            session.mutate_world(NS_FILES, entry["id"], {
                "location": location["id"],
                "name": entry.get("name", ""),
                "display_name": None,
                "kind": entry.get("kind", "document"),
                "size": entry.get("size", ""),
                "modified": entry.get("modified", ""),
                "state": entry.get("state", "normal"),
                "note": "",
                "owner": entry.get("owner"),
                "source": entry.get("source"),
                "preview": list(entry.get("preview") or []),
                "order": position,
                # Whether the file carries executable content. Visible
                # evidence, not an answer key: the workstation says so on the
                # attachment before it is ever downloaded.
                "macro": entry.get("kind") == "spreadsheet-macro",
                "origin_mail": None,
            })
            session.introduce_fact(
                _fact_id(file_fact(entry["id"])), category="file_metadata",
                value={"name": entry.get("name", ""),
                       "size": entry.get("size", ""),
                       "modified": entry.get("modified", ""),
                       "owner": entry.get("owner"),
                       "source": entry.get("source")},
                source="filesystem", available=True)


def _seed_notes(session):
    for order, note in enumerate(world.NOTES):
        session.mutate_world(NS_NOTES, note["id"], {
            "title": note.get("title", ""),
            "body": note.get("body", ""),
            "updated": note.get("updated", ""),
            "order": order,
        })


def _seed_messages(session):
    for conversation in world.CONVERSATIONS:
        session.mutate_world(NS_MESSAGES, conversation["id"], {
            "entries": [
                {"from": line.get("from", ""), "when": line.get("when", ""),
                 "text": line.get("text", "")}
                for line in conversation.get("messages") or []
            ],
            "unread": bool(conversation.get("unread")),
            "verified": False,
        })
        session.introduce_fact(
            _fact_id(conversation_fact(conversation["id"])),
            category="conversation",
            value={"name": conversation.get("name", "")},
            source="messages", available=True)


def _seed_authenticator(session):
    for order, entry in enumerate(world.AUTH_HISTORY):
        session.mutate_world(NS_AUTH_HISTORY, entry["id"], {
            "order": order,
            "app": entry.get("app", ""),
            "result": entry.get("result", ""),
            "device": entry.get("device", ""),
            "location": entry.get("location", ""),
            "when": entry.get("when", ""),
        })
    session.introduce_fact(
        _fact_id(AUTH_HISTORY_FACT), category="auth_activity",
        value={"entries": len(world.AUTH_HISTORY)},
        source="authenticator", available=True)

    # Every authored prompt gets its context fact up front, unavailable until
    # the prompt itself exists. Introducing it now keeps fact identity stable
    # across a resume; making it available is the delivery's job.
    for prompt in world.MFA_PROMPTS:
        surface = prompt["surface"]
        session.introduce_fact(
            _fact_id(prompt_fact(prompt["id"])), category="auth_request_context",
            value={"device": surface.get("device", ""),
                   "location": surface.get("location", ""),
                   "network": surface.get("network", ""),
                   "ip_class": surface.get("ip_class", "")},
            source="authenticator", available=False)


def _seed_notifications(session):
    for order, notification in enumerate(world.OPENING_NOTIFICATIONS):
        session.mutate_world(NS_NOTIFICATIONS, notification["id"], {
            "order": order,
            "kind": notification.get("kind", "system"),
            "title": notification.get("title", ""),
            "body": notification.get("body", ""),
            "when": notification.get("when", ""),
            "opens": notification.get("opens"),
            "unread": False,
        })
    session.mutate_world(NS_SESSION, "notification_seq",
                         len(world.OPENING_NOTIFICATIONS))


def _seed_directory(session):
    for contact in world.DIRECTORY:
        session.introduce_fact(
            _fact_id(contact_fact(contact["id"])), category="directory_record",
            value={"name": contact.get("name", ""),
                   "email": contact.get("email", ""),
                   "extension": contact.get("extension", ""),
                   "channels": list(contact.get("channels") or [])},
            source="organisation directory", available=True)
        if contact.get("callback"):
            session.introduce_fact(
                _fact_id(contact_callback_fact(contact["id"])),
                category="known_channel",
                value={"contact": contact["id"]},
                source="organisation directory", available=True)


def _seed_browser(session):
    session.mutate_world(NS_BROWSER, "home", world.BROWSER_HOME)
    # The learner opens on the intranet home page, so that page is already
    # part of their own browsing history when the session starts.
    session.mutate_world(NS_BROWSER, "visited", [world.BROWSER_HOME])
    session.mutate_world(NS_BROWSER, "payment_account", None)
    session.mutate_world(NS_BROWSER, "payment_released", None)
    for url in ix.PAGE_BY_URL:
        session.introduce_fact(
            _fact_id(page_fact(url)), category="browser_page",
            value={"url": url}, source="browser", available=True)


def _seed_tasks(session):
    for task in scenario.TASKS:
        session.mutate_world(NS_TASKS, task["id"], {
            "label": task.get("label", ""),
            "state": task.get("state", "outstanding"),
            "note": task.get("note", ""),
        })


def _seed_session_flags(session):
    session.mutate_world(NS_SESSION, "queue_index", 0)
    session.mutate_world(NS_SESSION, "network_disconnected", False)
    session.mutate_world(NS_SESSION, "vpn_connected", False)
    #: The decision whose safer-alternative comparison is waiting to be shown,
    #: or ``None``. Server-owned: an Assessment attempt never sets it, so the
    #: material is absent from the projection rather than hidden by CSS.
    session.mutate_world(NS_SESSION, "pending_comparison", None)
    session.mutate_world(NS_SESSION, "decision_seq", 0)
    session.mutate_world(NS_SESSION, "sent_seq", 0)
    session.mutate_world(NS_SESSION, "note_seq", 0)
    session.mutate_world(NS_SESSION, "started_label",
                         clock.workday_label(session.now_ms))
