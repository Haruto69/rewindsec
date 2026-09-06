"""The RewindSec 2.0 training engine.

The layer that decides what the simulated workplace does next. It sits between
the workstation application service and the deterministic core::

    HTTP / prototype adapter
            v
    rewindsec.workstation      (validates actions, mutates the world)
            v
    rewindsec.training         (decides what happens next)
            v
    rewindsec.domain + rewindsec.core

Pure Python. No Flask, no SQLAlchemy, no Jinja, no browser vocabulary, no
network, no subprocess, no wall clock, no ambient randomness -- every one of
those is asserted structurally by
``tests/test_rewindsec2_training_boundaries.py``, because the guarantees this
package makes are only worth what the import graph makes true.

The pieces
----------
``policy``       every authored constant, and the occurrence rule written out.
``state``        what is persisted, and where.
``eligibility``  LOCKED or ELIGIBLE, with reasons, before any draw.
``candidate``    the candidate value object.
``catalog``      every candidate there is, in one deterministic order.
``families/``    per-family candidates and network-dependence declarations.
``selection``    weighted choice that consumes exactly one draw.
``delivery``     turning a chosen candidate into world state.
``progression``  whether a scheduled consequence still makes sense.
``engine``       the evaluation pulse that ties them together.

What lives elsewhere, on purpose
--------------------------------
The scheduler stays a generic deterministic scheduler in
:mod:`rewindsec.core.scheduler`: it knows about fire times and cancellation
and nothing about threat families, context, eligibility, pedagogy or scoring.
Applying a consequence's effects stays in
:mod:`rewindsec.workstation.consequences`. Scoring does not exist yet and is
Batch 4's.
"""

__all__ = ["catalog", "candidate", "delivery", "eligibility", "engine",
           "families", "policy", "progression", "selection", "state"]
