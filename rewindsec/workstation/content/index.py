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
    "mode_flags", "timeline_for", "url_slug", "attachment_kind_label",
    "is_hostile_mail", "is_hostile_prompt", "is_hostile_page",
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
    """The authored delivery sequence for a focus.

    A fixed authored list, deliberately. Batch 3 replaces this with the
    context-conditioned hazard scheduler; until then, calling this a
    "scheduler" would be a claim the code does not support.
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
