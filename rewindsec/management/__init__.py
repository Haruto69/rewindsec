"""RewindSec 2.0 management records: students, groups, assessments, attempts.

Batch 5. This package owns the *administrative* half of RewindSec 2.0 -- who
a learner is, which groups they belong to, which assessments they have been
assigned and by what route, and which attempts they have made -- and nothing
else. It consumes the simulation (:mod:`rewindsec.domain`,
:mod:`rewindsec.workstation`) and the scoring system
(:mod:`rewindsec.scoring`); it never reimplements either.

Boundaries this package holds, deliberately
-------------------------------------------
* **No simulation randomness is ever consumed here.** Student, group,
  assessment, assignment and attempt identifiers are minted from
  :mod:`secrets` or derived with SHA-256 (:mod:`rewindsec.management.ids`),
  never from a session's named RNG streams and never from ``hash()``. Two
  sessions given the same seed and the same learner inputs still replay
  identically whatever administrative rows exist alongside them.
* **No wall clock reaches a simulation decision.** Administrative rows carry
  ordinary application timestamps (created/started/ended), because an audit
  trail with no time on it is not an audit trail -- but nothing in
  :mod:`rewindsec.core`, :mod:`rewindsec.training` or
  :mod:`rewindsec.workstation` ever reads one.
* **Scoring is consumed, never recomputed.** A completed attempt's result is
  the session's own immutable, finalized
  :class:`~rewindsec.scoring.result.ScoringResult`, stored under the versions
  it was produced with. There is no second "trainer score".
* **Progress is counted in scored interactions**, resolved through
  :func:`rewindsec.scoring.evidence.resolve_opportunities` -- never events,
  never messages, never elapsed time, never scheduler ticks.
* **Nothing here imports Flask or SQLAlchemy.** The HTTP adapter lives in
  :mod:`rewindsec.prototype.trainer_api`; the storage adapter lives in
  :mod:`rewindsec.persistence.management_adapter`; this package talks to both
  only through :mod:`rewindsec.management.ports`.
"""

__all__ = []
