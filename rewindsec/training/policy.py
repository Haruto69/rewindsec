"""Every authored constant the training engine reads. One file, on purpose.

The architecture (S9.3) requires the occurrence rule to be *explicit,
versioned, deterministic and testable*. The cheapest way to break all four at
once is to scatter magic numbers across a family module here and a delivery
adapter there, so none of them live anywhere but this module.

What this is, and is not
------------------------
This is **authored system logic**. It is not a published algorithm, it is not
derived from human-learning research, and no claim is made that these numbers
improve retention, realism or difficulty calibration. They are implementation
parameters pending evaluation, and the paper must describe them that way.

The rule, in full
-----------------
Simulation time is divided into *evaluation pulses* (see
:mod:`rewindsec.training.engine`). At each pulse:

1. **Eligibility first.** Every candidate is resolved to ELIGIBLE or LOCKED
   from world, ledger, focus, mode, cooldown and occurrence state. No random
   value is drawn while doing so, and a LOCKED candidate consumes nothing.

2. **Pressure.** For every threat family holding at least one eligible
   candidate::

       raw        = threat_stream.randint(3, 10)            # percentage points
       scaled     = raw * focus_percent[f] * mode_percent / 10000
       starvation = min(STARVATION_CAP, starved_pulses[f] * STARVATION_STEP)
       pressure[f] = min(FAMILY_PRESSURE_CAP,
                         pressure[f] + max(1, scaled) + starvation)

   All of it is integer arithmetic in percentage points. Floating point would
   be perfectly deterministic for these operations too, but integers make
   "the same number on every platform" obvious rather than argued.

   A family with no eligible candidate is **frozen**: its pressure is neither
   raised nor decayed, its starvation counter is reset to zero, and it draws
   nothing. Eligibility that disappears and returns therefore resumes from the
   pressure it had, with starvation starting again from zero.

3. **Occurrence.** ``total = min(HAZARD_CAP, sum(pressure over eligible
   families))``; one draw ``roll = threat_stream.randint(1, 100)``; an event
   occurs when ``roll <= total``.

4. **Family.** Chosen among eligible families with weight ``pressure[f]``,
   from the same stream. Focus has already been folded into pressure, so it is
   applied exactly once.

5. **Candidate.** Chosen among that family's eligible candidates with their
   authored weights.

6. **Reset.** The selected family's pressure returns to
   :data:`PRESSURE_AFTER_SELECTION`, its starvation counter to zero, and it
   enters cooldown. Every *other* eligible family's starvation counter
   increments.

Background workplace activity runs the same rule on its own state and its own
RNG stream, and only when no threat fired in this pulse -- so an ordinary day
still contains ordinary work, and an extra background draw cannot move a
threat draw.
"""

__all__ = [
    "ENGINE_VERSION", "CATALOG_VERSION", "FAMILIES", "THREAT_FAMILIES",
    "BACKGROUND_FAMILY", "HAZARD_CAP", "FAMILY_PRESSURE_CAP",
    "PRESSURE_INCREMENT_MIN", "PRESSURE_INCREMENT_MAX",
    "PRESSURE_AFTER_SELECTION", "STARVATION_STEP", "STARVATION_CAP",
    "FOCUS_PERCENT_SELECTED", "FOCUS_PERCENT_OTHER", "FAMILY_COOLDOWN_MS",
    "MODE_POLICY", "focus_percent", "mode_policy", "cooldown_ms",
    "evaluation_delay_ms", "MIN_EVALUATION_INTERVAL_MS", "TRACE_DEPTH",
]

#: The engine/policy version. Persisted with every session created under it.
#:
#: Changing *any* number in this module, the order of the steps above, or the
#: streams they draw from changes what a stored seed replays to. That is a
#: deliberate, versioned act: bump this string, and leave sessions created
#: under the old one to be read as history rather than replayed as if nothing
#: had changed.
ENGINE_VERSION = "training-engine/v1"

#: The candidate catalogue version, separately versioned for the same reason:
#: adding, removing or reweighting a candidate materially changes replay even
#: when the selection rule has not moved.
CATALOG_VERSION = "training-catalog/v1"

#: The four threat families, in the fixed order every deterministic iteration
#: uses. Never a set, never a dict's insertion order.
THREAT_FAMILIES = ("bec", "mfa", "phishing", "ransomware")

#: Benign workplace activity keeps family-shaped state so the same pressure,
#: cooldown and starvation vocabulary applies to it -- but it is drawn
#: separately and never competes in the threat lottery.
BACKGROUND_FAMILY = "background"

FAMILIES = THREAT_FAMILIES + (BACKGROUND_FAMILY,)

# ---------------------------------------------------------------------------
# Pressure / hazard
# ---------------------------------------------------------------------------

#: Ceiling on the *total* occurrence probability at one pulse, in percentage
#: points. Without it, four eligible families at full pressure would make an
#: arrival certain at every pulse, which is a queue and not a simulation.
HAZARD_CAP = 85

#: Ceiling on any one family's pressure. Keeps a family that has been eligible
#: for a long time from monopolising the weighted family draw.
FAMILY_PRESSURE_CAP = 60

#: The bounded seeded increment per eligible non-occurrence, in percentage
#: points, before focus/mode scaling. The architecture (S9.3) envisages
#: "around +3 to +10 percentage points"; this is that range.
PRESSURE_INCREMENT_MIN = 3
PRESSURE_INCREMENT_MAX = 10

#: Pressure a family returns to immediately after one of its candidates fires.
PRESSURE_AFTER_SELECTION = 0

#: Starvation: percentage points added per consecutive pulse at which a family
#: was eligible and something *else* (or nothing) was selected, and the cap on
#: that contribution.
#:
#: This is not a quota. It never guarantees a family appears; it only makes a
#: family that keeps being passed over progressively more likely, and it stops
#: accruing the moment the family stops being eligible.
STARVATION_STEP = 2
STARVATION_CAP = 12

#: Focus weighting, as integer percentages applied to the pressure increment.
#: The learner's chosen focus accumulates pressure three times as fast as an
#: unrelated family; every family still accumulates, so nothing is excluded.
#: ``Mixed`` selects no family, so every family gets ``FOCUS_PERCENT_OTHER``
#: and catalogue order has no influence at all.
FOCUS_PERCENT_SELECTED = 300
FOCUS_PERCENT_OTHER = 100

#: Per-family cooldown after one of its candidates fires, in simulation
#: milliseconds, before the mode's scale is applied. Ransomware is longest
#: because its consequence chain is the longest-running; MFA is shortest
#: because an approval prompt is a short-lived thing.
FAMILY_COOLDOWN_MS = {
    "phishing": 70000,
    "ransomware": 90000,
    "mfa": 50000,
    "bec": 70000,
    "background": 20000,
}

# ---------------------------------------------------------------------------
# Mode pacing
# ---------------------------------------------------------------------------

#: How each mode paces the engine. These are the *cadence* half of mode
#: semantics; the scaffolding half (confirmation, comparison, coaching) stays
#: in the authored mode flags, which the service already reads.
#:
#: ``gate_on_active_primary`` is what makes Practice learner-paced: while an
#: arrival is still unresolved the engine evaluates, updates pressure and
#: schedules its next pulse, but selects nothing. ``allow_pileup`` is the
#: Assessment counterpart: arrivals may accumulate on top of each other.
#:
#: None of these numbers are claimed to be optimal for learning. They are
#: authored product constants.
MODE_POLICY = {
    "practice": {
        "evaluation_base_ms": 20000,
        "evaluation_jitter_ms": 6000,
        "pressure_percent": 20,
        "cooldown_percent": 160,
        "gate_on_active_primary": True,
        "allow_pileup": False,
    },
    "simulation": {
        "evaluation_base_ms": 12000,
        "evaluation_jitter_ms": 5000,
        "pressure_percent": 30,
        "cooldown_percent": 100,
        "gate_on_active_primary": False,
        "allow_pileup": False,
    },
    "assessment": {
        "evaluation_base_ms": 5000,
        "evaluation_jitter_ms": 2000,
        "pressure_percent": 60,
        "cooldown_percent": 40,
        "gate_on_active_primary": False,
        "allow_pileup": True,
    },
}

#: No pulse may ever be scheduled less than this far ahead. The engine
#: schedules its own successor, so a zero or negative interval would be an
#: infinite loop inside one ``_advance``; this is the floor that makes
#: "every pulse moves simulation time forward" structurally true rather than
#: merely intended.
MIN_EVALUATION_INTERVAL_MS = 1000

#: How many evaluation records the internal audit trail keeps. Bounded so the
#: persisted session cannot grow without limit over a long attempt.
TRACE_DEPTH = 16


def mode_policy(mode_id):
    """The pacing policy for a mode id, defaulting to Simulation."""
    return dict(MODE_POLICY.get(mode_id) or MODE_POLICY["simulation"])


def focus_percent(focus_id, family):
    """The focus multiplier, as an integer percentage, for one family.

    ``Mixed`` is not a family, so it matches nothing and every family gets the
    unselected weight -- which is exactly the required property: with Mixed,
    no family is privileged, including by catalogue order.
    """
    if focus_id == family:
        return FOCUS_PERCENT_SELECTED
    return FOCUS_PERCENT_OTHER


def cooldown_ms(family, mode_id):
    """Cooldown for *family* under *mode_id*, in simulation milliseconds."""
    base = FAMILY_COOLDOWN_MS.get(family, 60000)
    percent = mode_policy(mode_id)["cooldown_percent"]
    return max(1, (base * percent) // 100)


def evaluation_delay_ms(mode_id, timing_stream):
    """How far ahead the next evaluation pulse is scheduled.

    Draws exactly one value from the *timing* stream, so cadence jitter cannot
    perturb family selection or content variation -- and so a session's
    arrival rhythm is reproducible from its seed. Never returns less than
    :data:`MIN_EVALUATION_INTERVAL_MS`.
    """
    policy = mode_policy(mode_id)
    base = int(policy["evaluation_base_ms"])
    jitter = int(policy["evaluation_jitter_ms"])
    if jitter > 0:
        base += timing_stream.randint(-jitter, jitter)
    return max(MIN_EVALUATION_INTERVAL_MS, base)
