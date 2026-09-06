"""Versioned Assessment runtime capacity and self-directed defaults.

An Assessment definition may ask only for interactions the current runtime
can actually present.  The capacity is derived from the live training
candidate catalogue and the scoring opportunity registry; it is not a UI
range and it is not duplicated in an API adapter.

Focus is a weighting policy, not an exclusion rule, but a focused assessment
must be feasible from its selected family's own authored primary surfaces.
``mixed`` uses the sum of all four threat families.  Conditional incident
containment/recovery opportunities are deliberately not counted: they remain
natural consequences, but a trainer cannot make completion depend on a
learner first choosing the mistake that unlocks one.
"""

from rewindsec.scoring.opportunities import primary_candidate_capacity
from rewindsec.training import catalog, policy

__all__ = [
    "ASSESSMENT_RUNTIME_POLICY_VERSION",
    "SELF_DIRECTED_DEFINITION_VERSION",
    "SELF_DIRECTED_REQUIRED_INTERACTIONS",
    "capacity_by_focus",
    "required_interaction_capacity",
    "self_directed_assessment_id",
]

ASSESSMENT_RUNTIME_POLICY_VERSION = "rewindsec-assessment-runtime-policy/v1"
SELF_DIRECTED_DEFINITION_VERSION = \
    "rewindsec-self-directed-assessment-definition/v1"
SELF_DIRECTED_REQUIRED_INTERACTIONS = 3


def _family_capacity(family):
    return sum(primary_candidate_capacity(candidate)
               for candidate in catalog.for_family(family))


def capacity_by_focus():
    """Return the deterministic, registry-derived capacity for every focus."""
    family = {name: _family_capacity(name)
              for name in policy.THREAT_FAMILIES}
    return {
        "phishing": family["phishing"],
        "ransomware": family["ransomware"],
        "mfa": family["mfa"],
        "bec": family["bec"],
        "mixed": sum(family.values()),
    }


def required_interaction_capacity(focus):
    """Maximum feasible required count for *focus* under this policy."""
    capacities = capacity_by_focus()
    if focus not in capacities:
        raise ValueError("unknown assessment focus %r" % focus)
    return capacities[focus]


def self_directed_assessment_id(focus):
    """Stable id of the persisted system definition for one focus."""
    required_interaction_capacity(focus)
    return "system-self-directed-assessment-v1-%s" % focus
