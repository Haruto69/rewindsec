"""The six authoritative scoring dimensions, and nothing else.

Architecture Spec v1.1 (Batch 4) is explicit that the real score has exactly
these six dimensions -- no Easy/Medium/Hard axis, no renaming without a
compelling architecture reason. They are named to match the ``dimensions``
lists already authored on every decision in
:data:`rewindsec.workstation.content.scenario.DECISIONS` (``security_judgment``,
``evidence_use``, ``verification_discipline``, ``incident_response``,
``operational_accuracy``, ``recovery_quality``), which is deliberate: that
authored vocabulary already existed before this batch and is the evidence
graph's primary input, so the dimension ids here are not a new invention, they
are the same ids given a home.
"""

__all__ = ["DIMENSION_IDS", "DIMENSION_LABELS", "DIMENSION_DESCRIPTIONS",
           "is_dimension"]

DIMENSION_IDS = (
    "security_judgment",
    "evidence_use",
    "verification_discipline",
    "incident_response",
    "operational_accuracy",
    "recovery_quality",
)

DIMENSION_LABELS = {
    "security_judgment": "Security Judgment",
    "evidence_use": "Evidence Use",
    "verification_discipline": "Verification Discipline",
    "incident_response": "Incident Response",
    "operational_accuracy": "Operational Accuracy",
    "recovery_quality": "Recovery Quality",
}

DIMENSION_DESCRIPTIONS = {
    "security_judgment":
        "Consequential security decisions: whether hostile activity was "
        "recognised and refused, and whether legitimate activity was not "
        "treated as hostile.",
    "evidence_use":
        "Whether evidence that was genuinely available -- headers, link "
        "destinations, attachment details, approval context -- was actually "
        "inspected before a decision was made.",
    "verification_discipline":
        "Whether an independent, trusted channel was used to check a "
        "suspicious request, rather than the channel the request itself "
        "supplied.",
    "incident_response":
        "Response after a hostile message, approval request or incident: "
        "reporting, containment, and not making things worse.",
    "operational_accuracy":
        "Whether legitimate workplace tasks were completed correctly while "
        "security stayed intact, without treating ordinary work as a threat.",
    "recovery_quality":
        "Recovery after an incident, once a recovery opportunity actually "
        "existed -- distinct from containment.",
}


def is_dimension(value):
    return value in DIMENSION_IDS
