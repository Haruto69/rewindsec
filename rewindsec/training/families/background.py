"""Ordinary work. The thing that makes the rest of it a simulation.

A training environment in which every arrival is a security decision is not a
workplace; it is a quiz with a desktop background. Worse, it is a quiz whose
optimal strategy -- report it, delete it, deny it -- is exactly the behaviour
the product is supposed to discourage, because in that environment the
strategy is *correct*.

So the engine schedules ordinary work as a first-class activity, from its own
RNG stream, competing for nothing with the threat families. A travel claim is
approved. A manager wants a headcount figure before Friday. The weekly
newsletter goes out. Somebody mentions the stand-up in the team channel.

Three rules this module obeys, and they are the whole of its ethics:

1. **Nothing is labelled.** No arrival carries "benign" any more than another
   carries "hostile". The projection could not tell you which module produced
   a message even if it were allowed to look.
2. **Ordinary work has consequences too.** Reporting the headcount request
   escalates it, closes with no finding, and leaves the manager still waiting
   -- the existing ``d-report-legitimate`` chain. Over-suspicion is not free.
3. **No points.** Nothing here awards, deducts or computes a score. That is
   Batch 4's, and pretending otherwise now would produce numbers nobody can
   defend.

Content variation
-----------------
The team-channel chatter picks its line from the ``content_variation`` stream,
which is the whole reason that stream exists: adding a fifth line to the list
below must not move a single threat draw, a single arrival time, or a single
consequence. There is a test that says so.
"""

from rewindsec.training import eligibility as el
from rewindsec.training.families import _candidate

__all__ = ["FAMILY", "candidates", "network_dependent_steps", "CHATTER",
           "NUDGES"]

FAMILY = "background"

#: Team-channel lines. Explicitly synthetic, deliberately unremarkable, and
#: about nothing at all -- a colleague talking about a room booking is not
#: evidence about anything and must not read as though it were.
CHATTER = (
    "Stand-up is in Meeting Room 2 today, not 4. Second time this week.",
    "Whoever has the good projector adaptor, the ops room needs it back.",
    "Reminder that the Q3 review pre-read is due with Marcus before Friday.",
    "Coffee machine on 3 is out again. Facilities have been told.",
)

#: Low-key workstation notices. Ordinary chrome for an ordinary morning.
NUDGES = (
    ("Calendar", "Q3 operations review at 14:00, Meeting Room 2."),
    ("Storage", "Your Documents folder is at 62% of its quota."),
    ("Updates", "Two updates will install when you next restart."),
)


def candidates():
    return (
        _candidate(
            "cand-bg-facilities-notice", FAMILY, activity="mail",
            delivery="mail", content_ref="m-facilities-notice",
            delivers_mail="m-facilities-notice", weight=8,
            streams=("background",)),
        _candidate(
            "cand-bg-headcount-request", FAMILY, activity="mail",
            delivery="mail", content_ref="m-headcount",
            delivers_mail="m-headcount", weight=12,
            prerequisites=(
                el.Prereq(el.FACT_AVAILABLE, "org.manager_contact"),
            ),
            streams=("background",)),
        _candidate(
            "cand-bg-newsletter", FAMILY, activity="mail",
            delivery="mail", content_ref="m-newsletter",
            delivers_mail="m-newsletter", weight=8,
            streams=("background",)),
        _candidate(
            "cand-bg-travel-claim", FAMILY, activity="mail",
            delivery="mail", content_ref="m-travel-reimb",
            delivers_mail="m-travel-reimb", weight=10,
            streams=("background",)),
        _candidate(
            # Batch 4: the first candidate whose delivery is enriched from
            # the runtime content pipeline (a deterministic subject-line
            # variant drawn from ``content_variation``, and an attachment
            # bound to a document the pipeline's catalogue actually
            # generated -- see rewindsec.workstation.content.documents).
            "cand-bg-facilities-followup", FAMILY, activity="mail",
            delivery="mail", content_ref="m-facilities-followup",
            delivers_mail="m-facilities-followup", weight=8,
            streams=("background", "content_variation")),
        _candidate(
            # Batch 4 review correction: the second previously-unwired
            # background archetype ("arche-mail-ordinary-team-update") now
            # live.
            "cand-bg-standup-notes", FAMILY, activity="mail",
            delivery="mail", content_ref="m-standup-notes",
            delivers_mail="m-standup-notes", weight=8,
            streams=("background",)),
        _candidate(
            "cand-bg-team-chatter", FAMILY, activity="message",
            delivery="chatter", content_ref="conv-ops-team", weight=10,
            max_occurrences=4, cooldown_ms=40000,
            streams=("background", "content_variation")),
        _candidate(
            "cand-bg-workstation-nudge", FAMILY, activity="notification",
            delivery="nudge", content_ref=None, weight=6,
            max_occurrences=3, cooldown_ms=60000,
            # A local notice from the machine itself: it does not need the
            # network, so it keeps arriving after the learner isolates. That
            # is deliberate -- an isolated workstation is quiet, not dead.
            requires_network=False,
            streams=("background", "content_variation")),
    )


def network_dependent_steps():
    return ()
