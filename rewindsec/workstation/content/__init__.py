"""Authored synthetic **bootstrap** content for a RewindSec 2.0 session.

What this is
------------
One fixed, hand-authored fictional workplace: an organisation, its people, its
mail, its files, its browser pages, its conversations, its authenticator
prompts, and the authored consequence chains that some learner decisions set
off. A session is *seeded* from this content at creation time; from that moment
the authoritative state belongs to the session's
:class:`~rewindsec.domain.world.WorldState` and
:class:`~rewindsec.domain.context_ledger.ContextLedger`, and this module is
never consulted for runtime truth again except to resolve an authored
definition by id (what a chain's next step is, what a browser page contains).

What this is **not**
--------------------
It is not the Batch 3 training engine. There is no generation here, no
threat-family selection, no hazard or pressure state, no context-conditioned
event selection and no dataset pipeline. ``TIMELINES`` is a fixed authored
sequence, not a scheduler; ``CONSEQUENCE_CHAINS`` are authored trees, not
derived ones. Replacing this module with a real engine is Batch 3's job and
nothing outside it should have to change shape when that happens.

Two vocabularies live side by side in these records and must never be confused:

``surface``
    Everything the learner may see inside the workstation. Ordinary workplace
    language; a hostile message reads exactly like a real one.
``analysis``
    Authored ground truth -- disposition, family, evidence model, rationale.
    **This must never reach a learner-facing projection.** It exists for the
    post-hoc comparison screen, the debrief, and development tooling.
    :mod:`rewindsec.workstation.projection` is the wall, and
    ``tests/test_rewindsec2_workstation_leakage.py`` is what holds it up.
"""

from rewindsec.workstation.content import scenario, world

__all__ = ["world", "scenario"]
