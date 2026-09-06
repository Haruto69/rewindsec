"""Assessment progress, counted in **scored interactions**.

This module is the whole of Batch 5's answer to "how far through an
assessment is this attempt", and the answer is deliberately narrow.

What a scored interaction is
----------------------------
One :class:`~rewindsec.scoring.opportunities.Opportunity` that the session
actually presented **and** that a recorded decision resolved, matched by the
exact ``(decision_id, occurrence_key)`` rule
:func:`rewindsec.scoring.evidence.resolve_opportunities` already implements.
Nothing is re-derived here: this module calls that function and counts what
comes back. There is one implementation of "was this occurrence resolved" in
the system, and scoring owns it.

What a scored interaction is *not*
----------------------------------
* **Not an event count.** ``session.event_log`` is never consulted.
* **Not a message count.** Benign and context traffic produces no
  opportunity at all -- ``opportunities._MAIL_RESOLUTIONS`` names only the
  mails that present a decision -- so an ordinary working day's mail cannot
  move progress by a single interaction.
* **Not elapsed time.** No clock, simulation or real, is read.
* **Not scheduler ticks.** The scheduler is never consulted.
* **Not a benign/malicious quota.** There is no ratio anywhere in here.

Three consequences worth stating explicitly, because each is a way the count
could have gone wrong:

* **Investigation is not progress.** Opening a message, inspecting a header,
  reading a document and calling a contact are *observational* actions. They
  record no decision, so they resolve no opportunity, so they add nothing to
  the count. Clicking every investigation control in the workstation moves
  progress by zero.
* **A retried decision cannot inflate the count.** The workstation refuses an
  idempotent repeat before it mutates anything, and even if a repeat were
  recorded it would land on the same occurrence-scoped world row; scoring's
  ``consumed`` set additionally stops one unscoped record from resolving
  several occurrences of the same class. Two occurrences of a recurring
  surface remain two independently countable interactions -- which is
  correct, and is the behaviour Batch 4 already models.
* **An ignored opportunity does not vanish.** It is still presented and still
  counted in ``presented``. Before the exact Assessment boundary it produces
  Batch 4's explicit negative evidence at finalization. Once a v2 boundary
  exists, only its N admitted opportunities are scoreable; an unrelated
  unadmitted opportunity remains factual history but contributes neither a
  decision nor an ignored penalty. Nothing here deletes or rewrites it.

Interpretation chosen where Batch 4 left room
---------------------------------------------
"Completed scored interaction" is read in the **narrow** sense: an
opportunity with a resolving decision recorded against it. The wider reading
-- counting an ignored opportunity as "interacted with, badly" -- was
rejected, because an assessment that a learner completes by ignoring
everything is not an assessment. Ignoring an admitted opportunity still costs
the learner their score; it does not buy them progress.
"""

from rewindsec.scoring.evidence import resolve_opportunities

__all__ = ["SCORED_INTERACTION_MODEL_VERSION", "scored_interactions",
           "attempt_progress"]

#: Versioned independently of the rubric: this governs only how *progress* is
#: counted from opportunities, never how anything is scored.
SCORED_INTERACTION_MODEL_VERSION = "rewindsec-scored-interaction/v1"


def scored_interactions(session):
    """``(completed, presented, detail)`` for one session.

    ``completed``
        Opportunities resolved by a recorded decision. This is the number an
        assessment's ``required_interactions`` is compared against.
    ``presented``
        Every opportunity the session presented, resolved or not.
    ``detail``
        One JSON-safe row per opportunity: its id, type, whether it was
        resolved, and its simulation timestamp. Deliberately carries **no**
        ``resolving_decisions``, no recorded decision id and no dimension
        list: those are answer-key-shaped, and this function is called while
        an Assessment attempt is still running.
    """
    resolutions, _tracked, _decisions = resolve_opportunities(session)
    detail = []
    completed = 0
    for resolution in resolutions:
        opportunity = resolution.opportunity
        if resolution.resolved:
            completed += 1
        detail.append({
            "opportunity_id": opportunity.opportunity_id,
            "opportunity_type": opportunity.opportunity_type,
            "sim_time_ms": opportunity.sim_time_ms,
            "resolved": bool(resolution.resolved),
        })
    return completed, len(resolutions), tuple(detail)


def attempt_progress(session, required_interactions):
    """The learner-safe progress document for one attempt.

    Safe to return to a learner mid-attempt: it says how many required
    interactions have been handled and how many remain, and says nothing at
    all about *how well* any of them was handled. There is no score here, no
    correctness, no disposition, no dimension and no decision id -- an
    assessment that told the learner which of their answers had counted would
    be an answer key delivered one interaction at a time.
    """
    completed, presented, _detail = scored_interactions(session)
    required = int(required_interactions)
    return {
        "model_version": SCORED_INTERACTION_MODEL_VERSION,
        "required": required,
        "completed": completed,
        "remaining": max(0, required - completed),
        "presented": presented,
        "met": completed >= required,
    }
