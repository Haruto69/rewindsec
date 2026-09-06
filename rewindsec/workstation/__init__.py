"""RewindSec 2.0 workstation application layer (Batch 2).

This package is the seam between the HTTP adapter and the simulation domain.
It is the only place that knows *both* what a mail message is and what a
:class:`~rewindsec.domain.session.SimulationSession` is, and it exists so that
neither of the two layers it joins has to know about the other:

    Flask / prototype HTTP adapter
            |
            v
    rewindsec.workstation   (this package: content, actions, service,
            |                projection, consequences, updates)
            v
    rewindsec.domain        (SimulationSession and its parts)
            |
            v
    rewindsec.persistence   (SessionRepository port + adapter)

Rules for anything added here:

* **No Flask, no HTTP, no templates, no browser vocabulary.** A request object,
  a status code and a JSON response body all belong to the adapter above. This
  package raises :class:`~rewindsec.workstation.errors.WorkstationError`
  subclasses, which the adapter maps onto status codes.
* **No v1 modules.** Same boundary the rest of ``rewindsec/`` observes.
* **No ambient randomness or wall clock anywhere.** Simulation
  randomness comes from the session's :class:`~rewindsec.core.rng.SeededRandom`
  and simulation time from its :class:`~rewindsec.core.simtime.SimClock`. The
  one deliberate exception is :mod:`rewindsec.workstation.seeds`, which mints
  a *root seed* for a brand-new session -- infrastructure, outside the
  deterministic simulation, and injectable so tests are deterministic.
* **Simulation time advances only by stated amounts.** Nothing here measures
  real elapsed time; no module in this package imports ``time``, ``datetime``
  or ``calendar``. A heartbeat advances one authored constant, and the
  development tooling advances an amount its caller names. What a session
  becomes is therefore a function of its seed and the sequence of application
  inputs it was given -- not of how fast the machine was, how long a request
  took, or how often a browser timer happened to fire.

Batch 2 boundary
----------------
This package wires the *already approved* prototype workstation to real
server-authoritative state. It does not implement the Batch 3 training engine:
there is no dynamic workplace activity generation, no threat-family selection,
no hazard/pressure algorithm, no context-conditioned event selection, and no
scoring engine. The authored content under
:mod:`rewindsec.workstation.content` is **bootstrap content** -- one fixed
authored scenario used to seed a session -- and is explicitly not a generator.
"""

__all__ = []
