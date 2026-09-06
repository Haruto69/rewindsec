"""The learner-safe view of a session. The wall between truth and screen.

Nothing else in this package may hand data to a browser. Everything the
workstation renders passes through :func:`learner_snapshot`, and this module
is written as an **allowlist**: it names, field by field, what a learner may
see, and copies only those fields out of the session. It never takes a world
value or an authored record and removes the sensitive parts, because a
denylist is a promise that every future author will remember to extend it.

What is deliberately withheld
-----------------------------
* Every ``analysis`` block in the authored content -- disposition, threat
  family, rationale, the authored signal list, the evidence model. A learner
  who opened developer tools and read this JSON must not be able to tell which
  message is hostile. That is the single most important property here, and
  ``tests/test_rewindsec2_workstation_leakage.py`` asserts it by walking the
  whole document.
* Authored decision classes (``unsafe``, ``safe``, ``over_suspicious``), which
  are the answer key by another name.
* Inspection-only context facts that the learner has not yet observed: a
  message's full header, where a link actually points, an attachment's type
  and provenance, an approval request's device and location. These are present
  in the session and *available* to the learner -- the value simply is not in
  the document until the corresponding observational action has marked the
  fact observed. Withholding rather than flagging is the point: sending the
  value with ``"observed": false`` beside it would put the evidence on the
  wire and make the ledger decorative.
* During an Assessment attempt, the safer-alternative comparison and every
  form of correctness feedback. Omitted from the projection, not hidden with
  CSS -- there is nothing in the document to reveal.
* Internal events, scheduler state, RNG state, the root seed, the causal
  graph, the learner reference, and the raw session snapshot. None of it is a
  learner's business and most of it is an oracle.

What is deliberately included
-----------------------------
Everything an attentive person sitting at a real workstation could see: the
sender's display name and address on an opened message, the attachment's
file name, the padlock state of a browser page, the organisation's own
directory. Ambiguity is preserved by making hostile and legitimate records
structurally identical, not by hiding evidence the learner has earned.
"""

from rewindsec.domain.enums import Mode, SessionStatus
from rewindsec.domain.json_safe import thaw
from rewindsec.workstation import clock
from rewindsec.workstation import worldops
from rewindsec.workstation.bootstrap import (NS_AUTH_HISTORY, NS_AUTH_REQUESTS,
                                             NS_BROWSER, NS_DIRECTORY,
                                             NS_FILE_LOCATIONS, NS_FILES,
                                             NS_INCIDENTS, NS_MAIL,
                                             NS_MAILBOX, NS_MAIL_SENT,
                                             NS_MESSAGES, NS_NOTES,
                                             NS_NOTIFICATIONS, NS_SESSION,
                                             NS_TASKS, mail_attachment_fact,
                                             mail_header_fact, mail_link_fact,
                                             prompt_fact, AUTH_HISTORY_FACT,
                                             file_document_fact)
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.content import world as content_world

__all__ = ["learner_snapshot", "MAIL_FOLDERS"]

#: The folders a learner can see. Fixed, because a folder list that grew from
#: whatever the world happened to contain would leak the existence of a
#: message that has not arrived.
MAIL_FOLDERS = ("inbox", "archive", "sent", "reported", "deleted")


def learner_snapshot(session, mode_flags):
    """The whole learner-visible workplace, as one JSON-safe document.

    Pure: it reads the session and returns a new dict. It advances no clock,
    consumes no sequence number, draws no random value, schedules nothing and
    observes nothing. Calling it twice in a row leaves ``capture_state()``
    byte-for-byte identical, which ``tests`` assert directly -- a projection
    that mutated would make every GET a hidden write.
    """
    assessment = session.mode is Mode.ASSESSMENT
    return {
        "session": _session_view(session, mode_flags, assessment),
        "organization": _organization_view(),
        "learner": _learner_view(),
        "mail": _mail_view(session),
        "files": _files_view(session),
        "browser": _browser_view(session),
        "notifications": _notifications_view(session),
        "notes": _notes_view(session),
        "authenticator": _authenticator_view(session),
        "messages": _messages_view(session),
        "directory": _directory_view(session),
        "tasks": _tasks_view(session),
        "incidents": _incidents_view(session),
        "comparison": _comparison_view(session, mode_flags, assessment),
    }


# ---------------------------------------------------------------------------
# Session, organisation, learner
# ---------------------------------------------------------------------------

def _session_view(session, mode_flags, assessment):
    return {
        "revision": session.revision,
        "focus": session.focus.value,
        "mode": session.mode.value,
        "status": session.status.value,
        "active": session.status is SessionStatus.ACTIVE,
        # Simulation time, server-owned. The client may interpolate the
        # displayed clock between updates, but it resynchronises to this and
        # nothing in the simulation ever reads the browser's idea of time.
        "sim_time_ms": session.now_ms,
        "clock": clock.workday_label(session.now_ms),
        "clock_rate": clock.DISPLAY_COMPRESSION,
        "network_disconnected": bool(session.world.get(
            NS_SESSION, "network_disconnected", False)),
        "vpn_connected": bool(session.world.get(NS_SESSION, "vpn_connected", False)),
        # Mode semantics, so the shell can render the right chrome. These are
        # the learner's own choice reflected back, not a hint: the *content*
        # each flag gates is withheld separately, above.
        "flags": {
            "coaching": bool(mode_flags.get("coaching")) and not assessment,
            "explicit_confirmation": (bool(mode_flags.get("explicit_confirmation"))
                                      and not assessment),
            "safer_alternative": (bool(mode_flags.get("safer_alternative"))
                                  and not assessment),
            "retry_visible": bool(mode_flags.get("retry_visible")) and not assessment,
            "investigation_hints": (bool(mode_flags.get("investigation_hints"))
                                    and not assessment),
        },
    }


def _organization_view():
    org = content_world.ORGANIZATION
    return {
        "name": org["name"],
        "short_name": org["short_name"],
        "domain": org["domain"],
        "workstation_id": org["workstation_id"],
    }


def _learner_view():
    learner = content_world.LEARNER
    return {
        "name": learner["name"],
        "given_name": learner["given_name"],
        "initials": learner["initials"],
        "role": learner["role"],
        "department": learner["department"],
        "email": learner["email"],
    }


# ---------------------------------------------------------------------------
# Mail
# ---------------------------------------------------------------------------

def _mail_view(session):
    messages = []
    for mail_id, state in sorted(session.world.get_component(NS_MAIL).items()):
        if not state.get("delivered"):
            # An undelivered message is not "hidden": as far as the learner's
            # day is concerned it has not happened yet, and putting it in the
            # document with a flag would let a curious client read tomorrow's
            # post.
            continue
        record = ix.MAIL_BY_ID.get(mail_id)
        if record is None:
            continue
        messages.append(_message_view(session, mail_id, state, record))

    for sent_id, state in sorted(session.world.get_component(NS_MAIL_SENT).items()):
        messages.append({
            "id": sent_id,
            "folder": "sent",
            "unread": False,
            "read": True,
            "reported": False,
            "forwarded": False,
            "replied": False,
            "order": state.get("order", 900),
            "received": state.get("received", ""),
            "subject": state.get("subject", ""),
            "from_name": content_world.LEARNER["name"],
            "from_address": content_world.LEARNER["email"],
            "to": state.get("to", ""),
            "body": [state.get("body", "")],
            "links": [],
            "attachments": [],
            "headers": None,
            "own": True,
        })

    messages.sort(key=lambda item: item["order"], reverse=True)
    return {
        "folders": list(MAIL_FOLDERS),
        "messages": messages,
        "rule": session.world.get(NS_MAILBOX, "rule"),
    }


def _message_view(session, mail_id, state, record):
    surface = record["surface"]
    return {
        "id": mail_id,
        "folder": state.get("folder", "inbox"),
        "unread": bool(state.get("unread")),
        "read": bool(state.get("read")),
        "reported": bool(state.get("reported")),
        "forwarded": bool(state.get("forwarded")),
        "replied": bool(state.get("replied")),
        "order": state.get("order", 0),
        "received": state.get("received", ""),
        # Shown the moment a message is opened, exactly as a mail client
        # does. ``subject_override``/``from_name_override`` are a
        # deterministic content-variation choice made at delivery time (see
        # rewindsec.training.recurrence) -- authored surface data with a
        # field swapped, never a different message. ``opening_line_override``
        # replaces only the first paragraph of the authored body for the
        # same reason: everything else about the message -- the financial
        # detail, the closing, the attachment -- stays byte-identical to the
        # authored surface.
        "subject": state.get("subject_override") or surface.get("subject", ""),
        "from_name": state.get("from_name_override") or surface.get("from_name", ""),
        "from_address": surface.get("from_address", ""),
        "body": _body_view(surface, state.get("opening_line_override")),
        "links": [
            _link_view(session, mail_id, index, link)
            for index, link in enumerate(surface.get("links") or [])
        ],
        "attachments": [
            _attachment_view(session, mail_id, index, attachment)
            for index, attachment in enumerate(surface.get("attachments") or [])
        ],
        # Inspection-only. ``None`` until the learner opens the header.
        "headers": _observed_value(session, mail_header_fact(mail_id)),
        "own": False,
    }


def _body_view(surface, opening_line_override):
    """The authored body, with only its first paragraph swapped, if at all.

    The rest of the message -- financial detail, closing, everything a
    consequence or a decision might reason about -- is never touched here.
    """
    body = list(surface.get("body") or [])
    if opening_line_override and body:
        body = [opening_line_override] + body[1:]
    return body


def _link_view(session, mail_id, index, link):
    """A link's visible text always; its destination only once inspected.

    This is the available/observed distinction at its most load-bearing. The
    destination is genuinely available -- one click on "Where does this go?"
    and it is there -- but until that click it is not on the wire, so
    inspecting a link is a real act of investigation rather than a checkbox
    over information the client already had.
    """
    observed = _observed_value(session, mail_link_fact(mail_id, index))
    return {
        "index": index,
        "text": link.get("text", ""),
        "href": observed.get("href") if observed else None,
    }


def _attachment_view(session, mail_id, index, attachment):
    observed = _observed_value(session, mail_attachment_fact(mail_id, index))
    return {
        "index": index,
        "name": attachment.get("name", ""),
        "size": attachment.get("size", ""),
        "detail": None if observed is None else {
            "kind_label": observed.get("kind_label", ""),
            "sender": observed.get("sender", ""),
        },
    }


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def _files_view(session):
    locations = []
    for location_id, state in session.world.get_component(NS_FILE_LOCATIONS).items():
        locations.append({
            "id": location_id,
            "name": state.get("name", ""),
            "path": state.get("path", ""),
            "order": state.get("order", 0),
        })
    locations.sort(key=lambda item: item["order"])

    files = []
    for file_id, state in sorted(session.world.get_component(NS_FILES).items()):
        if state.get("deleted"):
            continue
        files.append({
            "id": file_id,
            "location": state.get("location"),
            "name": state.get("name", ""),
            "display_name": state.get("display_name"),
            "kind": state.get("kind", "document"),
            "size": state.get("size", ""),
            "modified": state.get("modified", ""),
            "state": state.get("state", "normal"),
            "note": state.get("note", ""),
            "owner": state.get("owner"),
            "source": state.get("source"),
            "preview": list(state.get("preview") or []),
            "order": state.get("order", 0),
            # Visible evidence, not ground truth: a macro-enabled workbook
            # says so on its own attachment card before it is downloaded, and
            # a legitimate one would say the same.
            "macro": bool(state.get("macro")),
            # The structured synthetic document, if this file is bound to
            # one -- absent until the learner opens it (``files.open`` marks
            # the fact observed), and absent forever if the file has no bound
            # document at all. See ``rewindsec.workstation.content.documents``
            # the front end renders this with safe DOM construction only --
            # see ``static/prototype/workstation.js``'s document viewer.
            "document": _observed_value(session, file_document_fact(file_id)),
        })
    files.sort(key=lambda item: item["order"])
    return {"locations": locations, "files": files}


# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------

def _browser_view(session):
    """Only pages the learner has actually reached this session.

    The whole authored site map is not sent up front. Two reasons: a client
    that has every page can enumerate destinations before the message that
    mentions them has arrived, and "which addresses have I been to" is
    genuinely part of the learner's own history rather than a static asset.
    """
    visited = session.world.get(NS_BROWSER, "visited") or []
    pages = {}
    for url in visited:
        page = ix.PAGE_BY_URL.get(url)
        if page is not None:
            pages[url] = _page_view(session, url, page)
    return {
        "home": session.world.get(NS_BROWSER, "home", content_world.BROWSER_HOME),
        "bookmarks": [dict(entry) for entry in content_world.BROWSER_BOOKMARKS],
        "history": [dict(entry) for entry in content_world.BROWSER_HISTORY],
        "visited": list(visited),
        "pages": pages,
        "payment_account": session.world.get(NS_BROWSER, "payment_account"),
        "payment_released": session.world.get(NS_BROWSER, "payment_released"),
    }


def _page_view(session, url, page):
    view = {
        "url": url,
        "title": page.get("title", ""),
        # The padlock. Legitimate external suppliers are "external" too, so
        # this separates internal from external, not safe from hostile.
        "chrome": page.get("chrome", "external"),
        "kind": page.get("kind", "portal"),
        "heading": page.get("heading", ""),
        "subheading": page.get("subheading", ""),
        "note": page.get("note", ""),
        "sections": [
            {"title": section.get("title", ""),
             "items": list(section.get("items") or [])}
            for section in page.get("sections") or []
        ],
        "signed_in": session.world.get(NS_BROWSER, "signin:%s" % url),
    }
    # Deliberately absent: ``signin_id``. It names the authored sign-in
    # handler, and one of those names says what the page is. The client posts
    # the address and the server resolves the handler.
    # What this page offers to download: a display name, a size and the id
    # the client sends back. Never a URL to retrieve and never a path -- there
    # is nothing to retrieve. Both a legitimate and a look-alike site offer
    # one, and they project identically, so the presence of a download is not
    # itself evidence.
    resources = ix.resources_for_page(url)
    if resources:
        view["resources"] = [
            {"id": resource["id"], "name": resource.get("name", ""),
             "size": resource.get("size", ""),
             "label": resource.get("label", ""),
             "kind_label": ix.attachment_kind_label(resource.get("kind"))}
            for resource in resources
        ]
    if page.get("kind") == "filelist":
        view["location_id"] = page.get("location_id")
    if page.get("kind") == "payments" and page.get("invoice"):
        invoice = page["invoice"]
        view["invoice"] = {
            "reference": invoice.get("reference", ""),
            "supplier": invoice.get("supplier", ""),
            "amount": invoice.get("amount", ""),
            "approved_by": invoice.get("approved_by", ""),
            "account_of_record": invoice.get("account_of_record", ""),
        }
        # The release queue. One entry per *payment context* that has
        # actually been raised -- see
        # ``rewindsec.workstation.worldops.available_payment_contexts``: an
        # entry belonging to a message that has not arrived is absent, not
        # flagged, so the queue never says what the mailbox has not.
        #
        # Deliberately absent from every entry: ``authorize_decision`` and
        # ``occurrence_key``. The first names an authored decision, and a
        # decision id says what the release means before the learner has
        # decided anything; the second names which presented occurrence the
        # entry belongs to, which is recurrence structure and no part of a
        # finance queue. The client sends back ``id`` and the server recovers
        # both. Each entry restates the invoice of record it settles, because
        # two entries on one page settle the same invoice and a queue that
        # showed the reference once would look like a single payment.
        view["payment_contexts"] = [
            {
                "id": context["id"],
                "queue_ref": context.get("queue_ref", ""),
                "reference": invoice.get("reference", ""),
                "supplier": invoice.get("supplier", ""),
                "amount": invoice.get("amount", ""),
                "approved_by": invoice.get("approved_by", ""),
                "account_of_record": invoice.get("account_of_record", ""),
                "released_account": session.world.get(
                    NS_BROWSER, worldops.payment_release_key(context["id"])),
            }
            for context in worldops.available_payment_contexts(session, url)
        ]
    return view


# ---------------------------------------------------------------------------
# Notifications, notes, tasks, incidents
# ---------------------------------------------------------------------------

def _notifications_view(session):
    entries = []
    for notification_id, state in session.world.get_component(NS_NOTIFICATIONS).items():
        if state.get("dismissed"):
            continue
        entries.append({
            "id": notification_id,
            "kind": state.get("kind", "system"),
            "title": state.get("title", ""),
            "body": state.get("body", ""),
            "when": state.get("when", ""),
            "opens": state.get("opens"),
            "unread": bool(state.get("unread")),
            "order": state.get("order", 0),
        })
    entries.sort(key=lambda item: item["order"], reverse=True)
    return entries


def _notes_view(session):
    notes = []
    for note_id, state in session.world.get_component(NS_NOTES).items():
        if state.get("deleted"):
            continue
        notes.append({
            "id": note_id,
            "title": state.get("title", ""),
            "body": state.get("body", ""),
            "updated": state.get("updated", ""),
            "order": state.get("order", 0),
        })
    notes.sort(key=lambda item: item["order"], reverse=True)
    return notes


def _tasks_view(session):
    tasks = []
    for task_id, state in sorted(session.world.get_component(NS_TASKS).items()):
        tasks.append({
            "id": task_id,
            "label": state.get("label", ""),
            "state": state.get("state", "outstanding"),
            "note": state.get("note", ""),
        })
    return tasks


def _incidents_view(session):
    """Incidents the workstation itself is showing the learner.

    The world row, not the causal graph. The graph carries triggering actions
    and consequence parents, which is exactly the sort of "why did this
    happen" material the learner is supposed to work out.
    """
    incidents = []
    for key, state in sorted(session.world.get_component(NS_INCIDENTS).items()):
        incidents.append({
            "key": key,
            "title": state.get("title", ""),
            "note": state.get("note", ""),
            "contained": bool(state.get("contained")),
            "recovered": bool(state.get("recovered")),
            "opened": state.get("opened", ""),
        })
    return incidents


# ---------------------------------------------------------------------------
# Authenticator, messages, directory
# ---------------------------------------------------------------------------

def _authenticator_view(session):
    requests = []
    for request_id, state in session.world.get_component(NS_AUTH_REQUESTS).items():
        if state.get("status") != "pending":
            continue
        prompt = ix.PROMPT_BY_ID.get(state.get("prompt_id"))
        if prompt is None:
            continue
        surface = prompt["surface"]
        observed = _observed_value(session, prompt_fact(state["prompt_id"]))
        requests.append({
            "id": request_id,
            # ``app_override`` is a deterministic content-variation choice
            # made at delivery time (see rewindsec.training.recurrence),
            # exactly like a mail's ``subject_override``: authored surface
            # data with the displayed application label swapped, never a
            # different prompt and never a change to what "Details" reveals.
            "app": state.get("app_override") or surface.get("app", ""),
            "arrived": state.get("arrived", ""),
            "number_match": surface.get("number_match", ""),
            "order": state.get("order", 0),
            # Inspection-only: the device, the place, the network. Available
            # behind one "Details" press; not on the wire until it is pressed.
            "details": None if observed is None else {
                "device": observed.get("device", ""),
                "location": observed.get("location", ""),
                "network": observed.get("network", ""),
                "ip_class": observed.get("ip_class", ""),
            },
        })
    requests.sort(key=lambda item: item["order"], reverse=True)

    history = []
    history_observed = session.ledger.has(AUTH_HISTORY_FACT) \
        and session.ledger.get(AUTH_HISTORY_FACT).observed
    for entry_id, state in session.world.get_component(NS_AUTH_HISTORY).items():
        history.append({
            "id": entry_id,
            "app": state.get("app", ""),
            "result": state.get("result", ""),
            "device": state.get("device", ""),
            "location": state.get("location", ""),
            "when": state.get("when", ""),
            "order": state.get("order", 0),
        })
    history.sort(key=lambda item: item["order"], reverse=True)
    return {"requests": requests, "history": history,
            "history_observed": bool(history_observed)}


def _messages_view(session):
    conversations = []
    for conversation_id, state in session.world.get_component(NS_MESSAGES).items():
        record = ix.CONVERSATION_BY_ID.get(conversation_id)
        if record is None:
            continue
        verification = record.get("verification_reply") or {}
        conversations.append({
            "id": conversation_id,
            "name": record.get("name", ""),
            "initials": record.get("initials", ""),
            "presence": record.get("presence", ""),
            "unread": bool(state.get("unread")),
            "entries": [
                {"from": entry.get("from", ""), "when": entry.get("when", ""),
                 "text": entry.get("text", "")}
                for entry in state.get("entries") or []
            ],
            # The button label only. What the colleague actually says arrives
            # as a real message, appended by the server when the learner asks.
            "verify_prompt": (verification.get("prompt")
                              if verification and not state.get("verified")
                              else None),
        })
    conversations.sort(key=lambda item: item["id"])
    return conversations


def _directory_view(session):
    calls = session.world.get_component(NS_DIRECTORY)
    contacts = []
    for contact in content_world.DIRECTORY:
        called = (calls.get(contact["id"]) or {}).get("called")
        contacts.append({
            "id": contact["id"],
            "name": contact.get("name", ""),
            "initials": contact.get("initials", ""),
            "role": contact.get("role", ""),
            "department": contact.get("department", ""),
            "email": contact.get("email", ""),
            "extension": contact.get("extension", ""),
            "location": contact.get("location", ""),
            "relationship": contact.get("relationship", ""),
            "kind": contact.get("kind", "employee"),
            "channels": list(contact.get("channels") or []),
            "note": contact.get("note"),
            "can_call": bool(contact.get("callback")),
            # What the person says when you ring the number the *directory*
            # holds. Withheld until the call is actually made -- it is the
            # result of an action, not a field on a record.
            "call_result": contact.get("callback") if called else None,
        })
    return contacts


# ---------------------------------------------------------------------------
# The safer-alternative comparison (architecture S12, provisional)
# ---------------------------------------------------------------------------

def _comparison_view(session, mode_flags, assessment):
    """The pedagogical comparison, or ``None``.

    Three independent gates, all server-side:

    1. an Assessment attempt never has one -- the material is absent from the
       document, so there is nothing for a client to un-hide;
    2. the mode's authored profile must allow it at all;
    3. a chain must actually have settled and set ``pending_comparison``.

    It explains; it does not undo. ``still_true`` is part of the authored
    content precisely so the screen says out loud that the world has not been
    rolled back.
    """
    if assessment or not mode_flags.get("safer_alternative"):
        return None
    decision_id = session.world.get(NS_SESSION, "pending_comparison")
    if not decision_id:
        return None
    authored = ix.SAFER_BY_DECISION.get(decision_id)
    if authored is None:
        return None
    return {
        "decision": decision_id,
        "heading": authored.get("heading", ""),
        "what_you_did": authored.get("what_you_did", ""),
        "what_followed": list(authored.get("what_followed") or []),
        "safer_process": list(authored.get("safer_process") or []),
        "likely_outcome": authored.get("likely_outcome", ""),
        "still_true": authored.get("still_true", ""),
        "evidence": _evidence_view(session, decision_id),
    }


def _evidence_view(session, decision_id):
    """Which decision-relevant evidence was actually inspected beforehand.

    Only ever built for a comparison that is already being shown -- that is,
    after the decision and its consequences, and never during an Assessment
    attempt. It reports *observation*, not correctness: the label of an
    evidence item names where it lives, not what it proves.
    """
    source = _evidence_source(decision_id)
    if source is None:
        return []
    kind, ref = source
    out = []
    for item in ix.evidence_model(kind, ref):
        fact_id = _evidence_fact_id(item.get("action"))
        observed = bool(fact_id and session.ledger.has(fact_id)
                        and session.ledger.get(fact_id).observed)
        out.append({"id": item.get("id"), "label": item.get("label"),
                    "where": item.get("where"), "observed": observed})
    return out


#: Kept as module-level aliases of the shared, content-layer versions in
#: :mod:`rewindsec.workstation.content.index` -- the post-session report, the
#: scoring package and this module must all resolve a decision's evidence
#: model the same way, so the vocabulary itself lives once, in content, not
#: here.
_evidence_source = ix.evidence_source
_evidence_fact_id = ix.evidence_fact_id


# ---------------------------------------------------------------------------
# The observation gate
# ---------------------------------------------------------------------------

def _observed_value(session, fact_id):
    """A fact's value if the learner has observed it, else ``None``.

    The single choke point for inspection-only material. Every caller above
    goes through it, so "did we remember to check observation for this field?"
    is answered by grep rather than by review.
    """
    if not session.ledger.has(fact_id):
        return None
    fact = session.ledger.get(fact_id)
    if not fact.observed:
        return None
    # ``thaw`` rather than a shallow dict comprehension: a fact's frozen value
    # may nest further dicts/lists (a structured synthetic document's blocks
    # and tables, for one), and a shallow copy would leave an inner
    # ``MappingProxyType`` in the response, which ``jsonify`` cannot encode.
    return thaw(fact.value)
