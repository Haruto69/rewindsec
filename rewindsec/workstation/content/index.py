"""Indexed, read-only lookups over the authored bootstrap content.

The content modules are written to be *read by a person* -- long literal lists
in the order the author thought about them. This module is what the rest of
the application reads instead: dictionaries keyed by id, built once at import,
never mutated.

Everything returned from here is authored definition, not session state. Two
consequences follow, and both matter:

1. A lookup never tells you what is *true in a session*. Whether a message has
   been delivered, whether a file is readable, whether a prompt is still
   pending -- all of that lives in the session's
   :class:`~rewindsec.domain.world.WorldState` and is read from there.
2. Several of these records carry ``analysis`` blocks, which are authored
   ground truth. Nothing in this module strips them, because the consequence
   engine and the debrief legitimately need them. Stripping is the
   projection's job, and :mod:`rewindsec.workstation.projection` is the only
   module allowed to hand anything to a learner.
"""

from rewindsec.workstation.content import scenario, world

__all__ = [
    "MAIL_BY_ID", "ALL_MAIL", "FILE_BY_ID", "FILE_LOCATION_BY_ID",
    "LOCATION_OF_FILE", "PROMPT_BY_ID", "CONTACT_BY_ID", "CONVERSATION_BY_ID",
    "NOTE_BY_ID", "PAGE_BY_URL", "CHAIN_BY_ID", "DECISION_BY_ID",
    "SAFER_BY_DECISION", "MODE_BY_ID", "TASK_BY_ID", "FOCUS_IDS", "MODE_IDS",
    "RESOURCE_BY_ID", "resources_for_page", "resource_on_page",
    "PAYMENT_CONTEXT_BY_ID", "payment_contexts_for_page",
    "payment_context_on_page",
    "mode_flags", "timeline_for", "url_slug", "attachment_kind_label",
    "is_hostile_mail", "is_hostile_prompt", "is_hostile_page",
    "evidence_model", "evidence_source", "evidence_fact_id",
]


def _index(records, key="id"):
    return {record[key]: record for record in records}


#: Every authored message, including the ones that only arrive as the effect
#: of a decision. One flat index, because "which list was it authored in" is
#: an authoring convenience and not a property of the message.
ALL_MAIL = list(world.MAIL) + list(scenario.CONSEQUENCE_MAIL)
MAIL_BY_ID = _index(ALL_MAIL)

FILE_LOCATION_BY_ID = _index(world.FILE_TREE)
FILE_BY_ID = {}
LOCATION_OF_FILE = {}
for _location in world.FILE_TREE:
    for _file in _location["files"]:
        FILE_BY_ID[_file["id"]] = _file
        LOCATION_OF_FILE[_file["id"]] = _location["id"]

PROMPT_BY_ID = _index(world.MFA_PROMPTS)
CONTACT_BY_ID = _index(world.DIRECTORY)
CONVERSATION_BY_ID = _index(world.CONVERSATIONS)
NOTE_BY_ID = _index(world.NOTES)
PAGE_BY_URL = dict(world.BROWSER_PAGES)

#: Downloadable resources, keyed by ``(url, resource_id)``. A page offers a
#: file; the client names the *resource*, never a filename and never a path,
#: and the server decides what actually lands in Downloads and what it is
#: called. Both a legitimate and a look-alike site offer one, so the presence
#: of a download is not itself a signal.
RESOURCE_BY_ID = {}
for _url, _page in PAGE_BY_URL.items():
    for _resource in _page.get("resources") or ():
        RESOURCE_BY_ID[(_url, _resource["id"])] = _resource


def resources_for_page(url):
    """The downloadable resources on one page, in authored order."""
    page = PAGE_BY_URL.get(url) or {}
    return tuple(page.get("resources") or ())


def resource_on_page(url, resource_id):
    """One resource, or ``None`` if that page does not offer it."""
    return RESOURCE_BY_ID.get((url, resource_id))


#: Payment contexts -- one release-queue entry -- keyed by ``(url,
#: context_id)``. Batch 4 review correction: a recurring BEC surface presents
#: the *same* invoice of record more than once, so "which payment is being
#: released" cannot be derived from the page alone. The client names the page
#: and the context id the projection gave it; the server resolves that pair
#: here and recovers the occurrence the release belongs to.
#:
#: Context ids are unique across the whole site map, not merely within a
#: page -- ``test_rewindsec2_bec_occurrence_payments`` asserts it -- so a
#: context id can be carried in a decision record or an evidence source
#: without also carrying the page it came from.
PAYMENT_CONTEXT_BY_ID = {}
for _url, _page in PAGE_BY_URL.items():
    for _context in _page.get("payment_contexts") or ():
        PAYMENT_CONTEXT_BY_ID[(_url, _context["id"])] = _context


def payment_contexts_for_page(url):
    """The release-queue entries authored on one payments page, in order.

    Authored order is the queue order the learner sees, and the order the
    server falls back to when a client names no context at all.
    """
    page = PAGE_BY_URL.get(url) or {}
    return tuple(page.get("payment_contexts") or ())


def payment_context_on_page(url, context_id):
    """One release-queue entry, or ``None`` if that page has no such entry.

    Scoped to the page deliberately: naming a context id that exists on a
    *different* payments page must not resolve, or one supplier's release
    action could settle another supplier's queue entry.
    """
    return PAYMENT_CONTEXT_BY_ID.get((url, context_id))


CHAIN_BY_ID = dict(scenario.CONSEQUENCE_CHAINS)
DECISION_BY_ID = dict(scenario.DECISIONS)
SAFER_BY_DECISION = dict(scenario.SAFER_ALTERNATIVES)
MODE_BY_ID = _index(scenario.MODES)
TASK_BY_ID = _index(scenario.TASKS)

FOCUS_IDS = tuple(option["id"] for option in scenario.FOCUS_OPTIONS)
MODE_IDS = tuple(mode["id"] for mode in scenario.MODES)


def mode_flags(mode_id):
    """The authored scaffolding profile for a mode.

    This is what makes the Practice/Simulation/Assessment difference a
    *server* decision rather than a CSS one: consequence delay scaling,
    explicit confirmation, and whether the safer-alternative comparison exists
    at all are all read from here, on the server, before anything reaches a
    projection.
    """
    mode = MODE_BY_ID.get(mode_id)
    if mode is None:
        mode = MODE_BY_ID["simulation"]
    return dict(mode["flags"])


def timeline_for(focus_id):
    """The authored delivery sequence for a focus. **Legacy.**

    Batch 3 replaced this with the context-conditioned scheduler in
    :mod:`rewindsec.training.engine`, and no session created since uses it.
    It survives for exactly two reasons: sessions created *before* Batch 3
    still have a half-played timeline and pending Batch 2 events in their
    scheduler, and silently moving those into a different event universe
    mid-attempt would change what the learner was being asked to do; and the
    prototype UI fixtures still describe it. Neither is a reason to keep
    extending it.
    """
    timeline = scenario.TIMELINES.get(focus_id)
    if timeline is None:
        timeline = scenario.TIMELINES["mixed"]
    return [dict(entry) for entry in timeline]


def url_slug(url):
    """A ledger-safe fact-id fragment for a synthetic address.

    Fact ids are restricted to ``[A-Za-z0-9_.:-]`` by the domain, and an
    address contains ``/``. Substituting rather than hashing keeps the id
    readable in a database row, which is worth more here than compactness.
    """
    return "".join(char if (char.isalnum() or char in "-_.") else "_"
                   for char in str(url))[:96]


_ATTACHMENT_KIND_LABELS = {
    "spreadsheet-macro": "Spreadsheet containing macros (.xlsm)",
    "spreadsheet": "Spreadsheet (.xlsx)",
    "pdf": "Portable document (.pdf)",
}


def attachment_kind_label(kind):
    """How an attachment's type reads in the workstation.

    Note what this is and is not: ``.xlsm`` genuinely *is* a macro-enabled
    workbook, and a real mail client shows that. It is visible evidence, not
    an answer key -- a legitimate macro workbook would carry the same label.
    """
    return _ATTACHMENT_KIND_LABELS.get(kind, "Document")


# ---------------------------------------------------------------------------
# Authored ground truth
# ---------------------------------------------------------------------------
#
# These three predicates read ``analysis``. They exist so that exactly one
# vocabulary for "the author marked this hostile" is used across the
# consequence engine, and so that a search for their names finds every place a
# server-side decision depends on ground truth. None of them may be called
# from :mod:`rewindsec.workstation.projection`.

def is_hostile_mail(mail_id):
    record = MAIL_BY_ID.get(mail_id)
    analysis = (record or {}).get("analysis") or {}
    return analysis.get("disposition") == "hostile"


def is_hostile_prompt(prompt_id):
    record = PROMPT_BY_ID.get(prompt_id)
    analysis = (record or {}).get("analysis") or {}
    return analysis.get("disposition") == "hostile"


def is_hostile_page(url):
    page = PAGE_BY_URL.get(url) or {}
    analysis = page.get("analysis") or {}
    return analysis.get("disposition") == "hostile"


def evidence_model(kind, ref):
    """The authored evidence items for a message or prompt, or ``()``.

    Used by the debrief and by the safer-alternative comparison, both of which
    run *after* the decision they describe. Never projected during an attempt.
    """
    if kind == "mail":
        record = MAIL_BY_ID.get(ref)
    elif kind == "prompt":
        record = PROMPT_BY_ID.get(ref)
    else:
        record = None
    analysis = (record or {}).get("analysis") or {}
    return tuple(analysis.get("evidence") or ())


#: Which authored artifact carries the evidence model for a decision. A small
#: authored map rather than a guess, because "the message this decision was
#: about" is knowledge the content has and the code does not.
#:
#: Shared between the projection/debrief (which resolve it into the
#: available/observed comparison a learner or a debrief sees) and the scoring
#: package (which resolves it into Evidence Use / Verification Discipline
#: evidence). One vocabulary, so the two can never drift apart.
_EVIDENCE_SOURCE = {
    "d-phish-credentials": ("mail", "m-payroll-restructure"),
    "d-phish-report": ("mail", "m-payroll-restructure"),
    "d-phish-verify": ("mail", "m-payroll-restructure"),
    "d-phish-delete": ("mail", "m-payroll-restructure"),
    "d-phish2-credentials": ("mail", "m-benefits-verify"),
    "d-phish2-report": ("mail", "m-benefits-verify"),
    "d-phish2-verify": ("mail", "m-benefits-verify"),
    "d-phish2-delete": ("mail", "m-benefits-verify"),
    "d-phish3-report": ("mail", "m-benefits-verify-o2"),
    "d-phish3-delete": ("mail", "m-benefits-verify-o2"),
    "d-ransom-open": ("mail", "m-rate-card"),
    "d-ransom-report": ("mail", "m-rate-card"),
    "d-ransom2-open": ("mail", "m-audit-checklist"),
    "d-ransom2-report": ("mail", "m-audit-checklist"),
    "d-ransom3-open": ("mail", "m-audit-checklist-o2"),
    "d-ransom3-report": ("mail", "m-audit-checklist-o2"),
    "d-bec-authorize": ("mail", "m-invoice-amend"),
    "d-bec-reply": ("mail", "m-invoice-amend"),
    "d-bec-verify": ("mail", "m-invoice-amend"),
    "d-bec-report": ("mail", "m-invoice-amend"),
    "d-bec2-authorize": ("mail", "m-meridian-amend"),
    "d-bec2-reply": ("mail", "m-meridian-amend"),
    "d-bec2-verify": ("mail", "m-meridian-amend"),
    "d-bec2-report": ("mail", "m-meridian-amend"),
    "d-bec3-reply": ("mail", "m-meridian-amend-o2"),
    "d-bec3-report": ("mail", "m-meridian-amend-o2"),
    "d-mfa-approve-hostile": ("prompt", "mfa-unexpected"),
    "d-mfa-deny-hostile": ("prompt", "mfa-unexpected"),
    "d-mfa-approve-legit": ("prompt", "mfa-vpn"),
    "d-mfa-deny-legit": ("prompt", "mfa-vpn"),
}


def evidence_source(decision_id):
    """Which authored (kind, ref) a decision's evidence model belongs to."""
    return _EVIDENCE_SOURCE.get(decision_id)


def evidence_fact_id(action_key):
    """Map an authored evidence ``action`` key onto a ledger fact id.

    The authored keys predate the ledger (they were the prototype's flat
    observation map). Translating here rather than rewriting the content
    keeps the authored evidence model stable while the mechanism underneath
    it became real.
    """
    from rewindsec.workstation.bootstrap import (AUTH_HISTORY_FACT,
                                                  contact_callback_fact,
                                                  contact_fact,
                                                  mail_attachment_fact,
                                                  mail_body_fact,
                                                  mail_header_fact,
                                                  mail_link_fact, prompt_fact)
    if not action_key or ":" not in action_key:
        if action_key == "open_auth_history":
            return AUTH_HISTORY_FACT
        return None
    verb, ref = action_key.split(":", 1)
    if verb == "inspect_headers":
        return mail_header_fact(ref)
    if verb == "inspect_link":
        return mail_link_fact(ref, 0)
    if verb == "inspect_attachment":
        return mail_attachment_fact(ref, 0)
    if verb == "inspect_mfa":
        return prompt_fact(ref)
    if verb == "open_contact":
        return contact_fact(ref)
    if verb in ("call_contact", "verify_message"):
        return contact_callback_fact(ref)
    if verb == "open_mail":
        return mail_body_fact(ref)
    return None
