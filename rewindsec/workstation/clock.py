"""Turning server-owned simulation time into a workday the learner can read.

Two separate things are deliberately kept apart here.

**Simulation time** is integer milliseconds owned by the session's
:class:`~rewindsec.core.simtime.SimClock`. Every scheduling decision, every
consequence delay and every recorded timestamp is expressed in it. It is
authoritative, it is persisted, and it survives a refresh unchanged.

**The workday label** is presentation: the "09:14" in the corner of the
workstation. It is a pure function of simulation time, computed on the server
so that two clients looking at the same session see the same clock, and
recomputed on every projection so it can never drift.

The compression factor exists because a plausible working morning does not fit
in a review session. It affects *only* the label. Nothing in the simulation
reads it, and no consequence delay is scaled by it -- authored delays are in
simulation milliseconds and stay there.
"""

__all__ = ["DAY_START_MINUTE", "DISPLAY_COMPRESSION", "workday_label",
           "workday_minute"]

#: The synthetic working day starts at 09:00.
DAY_START_MINUTE = 9 * 60

#: One second of simulation time reads as twelve seconds on the wall clock in
#: the corner of the screen. Display only.
DISPLAY_COMPRESSION = 12


def workday_minute(sim_time_ms):
    """Minutes past midnight in the synthetic working day."""
    return DAY_START_MINUTE + (int(sim_time_ms) * DISPLAY_COMPRESSION) // 60000


def workday_label(sim_time_ms):
    """``"HH:MM"`` for a simulation timestamp. Wraps at midnight."""
    total = workday_minute(sim_time_ms)
    hours = (total // 60) % 24
    minutes = total % 60
    return "%02d:%02d" % (hours, minutes)
