"""The post-session debrief document: what actually happened, from the session.

Everything here is derived from the persisted session -- its event log, its
action log, its causal consequence graph, its world and its context ledger --
rather than from anything the browser accumulated while the learner worked.
That is the whole point of it existing: after Batch 2 the results screen is
looking at the server's record of the session, not at a tally the front end
kept for itself.

When it is available
--------------------
Only once the session is no longer active. Architecture spec S4.3 requires
that an Assessment attempt shows no feedback and no score until it finishes,
and the cheapest way to guarantee that is for the material to be unreachable
rather than merely unrendered. The same gate applies in every mode, because a
Simulation learner asking for their own answer key mid-session would be no
better.

Because it runs after the attempt, this document *is* allowed to contain the
authored ground truth -- the decision classes, the threat families, the
evidence model. That is what a debrief is. Nothing in
:mod:`rewindsec.workstation.projection` may import from here, and nothing here
is ever merged into a learner snapshot.

Scoring
-------
Since Batch 4, ``document["scoring"]`` carries the real, server-derived
result from :mod:`rewindsec.scoring` -- computed once, at session completion,
and persisted immutably (see :mod:`rewindsec.scoring.state`). A session
created before Batch 4 carries no scoring stamp and gets the explicit legacy
projection instead; its historical demo numbers, if the old prototype
presentation is still reachable, are not RewindSec 2.0 scoring and must never
be reported as such.
"""

from rewindsec.domain.enums import SessionStatus
from rewindsec.scoring import state as scoring_state
from rewindsec.workstation import clock
from rewindsec.workstation.bootstrap import (NS_DECISIONS, NS_FILES,
                                             NS_INCIDENTS, NS_MAIL, NS_TASKS)
from rewindsec.workstation.consequences import NS_CONSEQUENCE_MAP
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.errors import ForbiddenActionError

_evidence_fact_id = ix.evidence_fact_id
_evidence_source = ix.evidence_source

__all__ = ["debrief_document"]


def debrief_document(session):
    """Build the debrief for a finished session.

    Raises :class:`~rewindsec.workstation.errors.ForbiddenActionError` while
    the session is still active, in every mode.
    """
    if session.status is SessionStatus.ACTIVE:
        raise ForbiddenActionError(
            "Results are available once the session has finished.")

    decisions = _decisions(session)
    return {
        "focus": session.focus.value,
        "mode": session.mode.value,
        "status": session.status.value,
        "assessmentId": None,
        "endedAt": clock.workday_label(session.now_ms),
        "durationMinutes": max(
            0, clock.workday_minute(session.now_ms) - clock.DAY_START_MINUTE),
        "timeline": _timeline(session),
        "decisions": decisions,
        "chains": _chains(session, decisions),
        "incidents": _incidents(session),
        "tasks": _tasks(session),
        "observed": [fact.fact_id for fact in session.ledger.observed_facts()],
        "available": [fact.fact_id for fact in session.ledger.available_facts()],
        "evidenceUniverse": _evidence_universe(session),
        "hostileDelivered": _hostile_delivered(session),
        "hostilePrompts": _hostile_prompts(session),
        "deletedHostile": _deleted_hostile(session),
        "filesImpacted": _files_impacted(session),
        "counts": {
            "events": len(session.event_log.events()),
            "actions": len(session.action_log.actions()),
            "observational_actions": sum(
                1 for a in session.action_log.actions() if a.is_observational),
            "consequential_actions": sum(
                1 for a in session.action_log.actions() if a.is_consequential),
            "consequences": len(session.incidents.consequences()),
            "available_facts": len(session.ledger.available_facts()),
            "observed_facts": len(session.ledger.observed_facts()),
        },
        # The real, server-derived rubric result -- or the explicit legacy
        # projection for a session that predates it. Computed once, at
        # completion, and persisted immutably; never recomputed on a later GET.
        "scoring": scoring_state.learner_view(session),
    }


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

#: How a recorded event reads in the debrief. Anything not named here is
#: machinery -- notification plumbing, internal markers -- and is left out
#: rather than rendered as noise.
_EVENT_LABELS = {
    "mail.delivered": ("event", "Message received"),
    "auth.request_created": ("event", "Approval requested"),
    "file.state_changed": ("consequence", "File state changed"),
    "message.received": ("event", "Message from a colleague"),
    "incident.opened": ("consequence", "Incident opened"),
    "consequence.step": ("consequence", "Consequence"),
    "task.updated": ("action", "Task updated"),
}

#: How a learner action reads. The verbs are the learner's, not a judgement.
_ACTION_LABELS = {
    "mail.open": ("action", "Opened a message"),
    "mail.inspect_headers": ("investigation", "Opened the full header"),
    "mail.inspect_link": ("investigation", "Checked where a link goes"),
    "mail.inspect_attachment": ("investigation", "Looked at attachment details"),
    "mail.open_link": ("action", "Followed a link from a message"),
    "mail.report": ("decision", "Reported a message"),
    "mail.delete": ("decision", "Deleted a message"),
    "mail.forward": ("action", "Forwarded a message"),
    "mail.reply": ("decision", "Replied to a message"),
    "mail.download_attachment": ("decision", "Downloaded an attachment"),
    "browser.navigate": ("action", "Opened an address"),
    "browser.sign_in": ("decision", "Signed in on a page"),
    "browser.sign_in_retry": ("action", "Returned to a sign-in page"),
    "browser.release_payment": ("decision", "Released a payment"),
    "browser.support_action": ("decision", "Used the Service Desk"),
    "files.inspect": ("investigation", "Inspected a file"),
    "files.open": ("decision", "Opened a file"),
    "files.delete": ("action", "Deleted a file"),
    "files.rename": ("action", "Renamed a file"),
    "notifications.open": ("action", "Opened a notification"),
    "notifications.mark_read": ("action", "Cleared notifications"),
    "notes.create": ("action", "Started a note"),
    "notes.open": ("investigation", "Consulted Notes"),
    "notes.save": ("action", "Wrote in Notes"),
    "notes.delete": ("action", "Deleted a note"),
    "auth.inspect_request": ("investigation", "Opened approval details"),
    "auth.inspect_history": ("investigation", "Checked approval history"),
    "auth.approve": ("decision", "Approved an approval request"),
    "auth.deny": ("decision", "Denied an approval request"),
    "messages.open": ("investigation", "Opened a conversation"),
    "messages.send": ("action", "Sent a message"),
    "messages.verify": ("decision", "Checked on a known channel"),
    "directory.open": ("investigation", "Opened a Directory record"),
    "directory.call": ("decision", "Called a contact on the number of record"),
    "session.acknowledge": ("action", "Continued"),
}


def _timeline(session):
    """Events and actions in one chronological list, ordered deterministically.

    Sorted by simulation time, then by kind, then by sequence: two things that
    happened in the same simulation millisecond still have one fixed order,
    and it is the same order after a resume.
    """
    rows = []
    for event in session.event_log.events():
        entry = _EVENT_LABELS.get(event.type)
        if entry is None:
            continue
        kind, label = entry
        rows.append((event.sim_time_ms, 0, event.seq, {
            "at": clock.workday_label(event.sim_time_ms),
            "kind": kind,
            "label": _event_label(session, event, label),
            "detail": _event_detail(session, event),
            "cause": None,
        }))
    for action in session.action_log.actions():
        entry = _ACTION_LABELS.get(action.action_type)
        if entry is None:
            continue
        kind, label = entry
        rows.append((action.sim_time_ms, 1, action.seq, {
            "at": clock.workday_label(action.sim_time_ms),
            "kind": kind,
            "label": label,
            "detail": action.target or "",
            "cause": None,
        }))
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    return [row[3] for row in rows]


def _event_label(session, event, default):
    payload = event.payload
    if event.type == "mail.delivered":
        record = ix.MAIL_BY_ID.get(payload.get("message"))
        if record:
            return "Message received: %s" % record["surface"].get("subject", "")
    if event.type == "consequence.step":
        chain = ix.CHAIN_BY_ID.get(payload.get("chain"))
        step = _find_step(chain, payload.get("step")) if chain else None
        if step:
            return step.get("summary", default)
    if event.type == "incident.opened":
        state = session.world.get(NS_INCIDENTS, payload.get("incident")) or {}
        return "Incident opened: %s" % state.get("title", "")
    return default


def _event_detail(session, event):
    payload = event.payload
    if event.type == "mail.delivered":
        record = ix.MAIL_BY_ID.get(payload.get("message"))
        if record:
            return "From %s" % record["surface"].get("from_name", "")
    if event.type == "consequence.step":
        chain = ix.CHAIN_BY_ID.get(payload.get("chain"))
        return chain.get("title", "") if chain else ""
    if event.type == "auth.request_created":
        return "Authenticator"
    return ""


def _find_step(chain, step_id):
    for step in chain.get("steps", []):
        if step["id"] == step_id:
            return step
    return None


# ---------------------------------------------------------------------------
# Decisions and chains
# ---------------------------------------------------------------------------

def _decisions(session):
    """One row per decision *record*, not per semantic decision class.

    A recurring decision class (an MFA approval, a shared-portal credential
    submission) can now be recorded more than once in a session -- once per
    occurrence, see :mod:`rewindsec.workstation.consequences` -- so ``id``
    here is the row's own storage key (unique per record) while
    ``decisionId`` carries the semantic class those two (or more) rows share.
    Everything that reads a decision's authored meaning (label, class,
    family, dimensions, evidence model) still keys off ``decisionId``.
    """
    rows = []
    for record_id, state in session.world.get_component(NS_DECISIONS).items():
        decision_id = state.get("decision_class", record_id)
        definition = ix.DECISION_BY_ID.get(decision_id) or {}
        evidence = _evidence_state(session, decision_id)
        rows.append({
            "id": record_id,
            "decisionId": decision_id,
            "label": definition.get("label", decision_id),
            # Authored ground truth. Legitimate here and nowhere else: this is
            # the explanation the learner has finished earning.
            "klass": definition.get("class"),
            "family": definition.get("family"),
            "dimensions": list(definition.get("dimensions") or []),
            "at": clock.workday_label(state.get("at_ms", 0)),
            "order": state.get("order", 0),
            "where": state.get("where", ""),
            "evidence": evidence,
            "inspectedBefore": sum(1 for item in evidence if item["observed"]),
            "evidenceTotal": len(evidence),
        })
    rows.sort(key=lambda row: row["order"])
    return rows


def _evidence_state(session, decision_id):
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


def _chains(session, decisions):
    """One causal tree per decision that set a chain off.

    Read from the world's consequence map and the incident graph rather than
    reconstructed from the authored chain definition, so a chain that was
    still unfolding when the session ended shows the steps that actually
    happened and not the ones that were going to.
    """
    # NS_CONSEQUENCE_MAP is keyed by the same occurrence-scoped record id
    # ``_decisions`` exposes as ``id`` (see
    # ``rewindsec.workstation.consequences._schedule_chain``), so a second
    # occurrence's steps land under a distinct key here too and can never be
    # attributed to the wrong occurrence's chain.
    by_record = {}
    for key, consequence_id in session.world.get_component(NS_CONSEQUENCE_MAP).items():
        record_id, _, step_id = key.partition(":")
        by_record.setdefault(record_id, []).append((step_id, consequence_id))

    chains = []
    for decision in decisions:
        definition = ix.DECISION_BY_ID.get(decision["decisionId"]) or {}
        chain = ix.CHAIN_BY_ID.get(definition.get("chain"))
        if chain is None:
            continue
        steps = []
        for step_id, consequence_id in by_record.get(decision["id"], []):
            if not session.incidents.has_consequence(consequence_id):
                continue
            consequence = session.incidents.get_consequence(consequence_id)
            authored = _find_step(chain, step_id) or {}
            steps.append({
                "id": step_id,
                "cause": authored.get("cause"),
                "summary": consequence.description or authored.get("summary", ""),
                "at": clock.workday_label(consequence.sim_time_ms),
                "order": consequence.seq,
                "consequence_id": consequence_id,
                "parents": list(consequence.parent_consequence_ids),
            })
        steps.sort(key=lambda item: item["order"])
        chains.append({
            "chainId": chain["id"],
            "decisionId": decision["decisionId"],
            "recordId": decision["id"],
            "title": chain.get("title", ""),
            "incidentId": chain.get("incident_id"),
            "startedAt": decision["at"],
            "steps": steps,
        })
    return chains


# ---------------------------------------------------------------------------
# World summaries
# ---------------------------------------------------------------------------

def _incidents(session):
    return {
        key: {"id": key, "title": state.get("title", ""),
              "note": state.get("note", ""),
              "contained": bool(state.get("contained")),
              "recovered": bool(state.get("recovered")),
              "openedAt": state.get("opened", "")}
        for key, state in session.world.get_component(NS_INCIDENTS).items()
    }


def _tasks(session):
    return {
        key: {"id": key, "label": state.get("label", ""),
              "state": state.get("state", "outstanding"),
              "note": state.get("note", "")}
        for key, state in session.world.get_component(NS_TASKS).items()
    }


def _hostile_delivered(session):
    return sorted(
        mail_id for mail_id, state in session.world.get_component(NS_MAIL).items()
        if state.get("delivered") and ix.is_hostile_mail(mail_id))


def _hostile_prompts(session):
    from rewindsec.workstation.bootstrap import NS_AUTH_REQUESTS
    return sum(1 for state in session.world.get_component(NS_AUTH_REQUESTS).values()
               if ix.is_hostile_prompt(state.get("prompt_id")))


def _deleted_hostile(session):
    return sum(1 for mail_id, state in session.world.get_component(NS_MAIL).items()
               if state.get("folder") == "deleted" and ix.is_hostile_mail(mail_id))


def _files_impacted(session):
    return sum(1 for state in session.world.get_component(NS_FILES).values()
               if state.get("state") == "unavailable" and not state.get("deleted"))


def _evidence_universe(session):
    """Every decision-relevant evidence item the workplace actually surfaced.

    Available-versus-observed, reduced to the two columns the debrief shows.
    An item counts as in play once the message or prompt that carries it has
    been delivered; whether it was inspected is read from the ledger.
    """
    seen = {}
    for mail_id, state in session.world.get_component(NS_MAIL).items():
        if not state.get("delivered"):
            continue
        _collect_evidence(session, "mail", mail_id, seen)
    from rewindsec.workstation.bootstrap import NS_AUTH_REQUESTS
    for state in session.world.get_component(NS_AUTH_REQUESTS).values():
        _collect_evidence(session, "prompt", state.get("prompt_id"), seen)
    return [seen[key] for key in sorted(seen)]


def _collect_evidence(session, kind, ref, seen):
    for item in ix.evidence_model(kind, ref):
        item_id = item.get("id")
        if not item_id or item_id in seen:
            continue
        fact_id = _evidence_fact_id(item.get("action"))
        observed = bool(fact_id and session.ledger.has(fact_id)
                        and session.ledger.get(fact_id).observed)
        seen[item_id] = {"id": item_id, "label": item.get("label"),
                         "where": item.get("where"), "observed": observed}
