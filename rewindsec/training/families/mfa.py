"""The MFA family: approvals the learner started, and approvals they did not.

Both kinds exist, and that is the design. A workstation where every approval
request is hostile teaches "deny everything", which is a strategy that passes
the exercise and fails at work: the learner who denies their own remote-access
sign-in has interrupted their own day, and the simulation says so.

The two candidates
------------------
* **Unsolicited.** An approval for a mail sign-in from a device and country
  the learner has never used. Nothing started it. Approving it completes an
  attacker's session; denying it stops one.
* **Re-authentication.** A second approval for the remote-access session the
  learner is *already running*. It is gated on ``vpn_connected`` -- the world
  flag that only becomes true when the learner has signed in at the access
  gateway and approved the first prompt -- so it can only ever arrive as a
  consequence of something the learner actually did. Denying it drops the
  session they are in the middle of using.

Cross-family causality, without coupled randomness
--------------------------------------------------
An account compromise makes an unsolicited approval *more* plausible, and the
architecture asks for that link to be factual rather than scripted. It is
expressed as a weighting, not as a trigger: the compromise-conditioned variant
is a separate candidate whose prerequisite is an open account incident. It
becomes eligible because a fact about the world changed, and the trace records
that as its reason -- no family reaches into another family's RNG stream, and
nothing anywhere says "if phishing then fire MFA".

Nothing in the projection distinguishes the three. The authenticator shows an
app, a device, a location, a network and a number to match; whether that adds
up is the learner's problem, and it is the only thing being asked.
"""

from rewindsec.training import eligibility as el
from rewindsec.training.families import _candidate

__all__ = ["FAMILY", "candidates", "network_dependent_steps"]

FAMILY = "mfa"


def candidates():
    return (
        _candidate(
            "cand-mfa-unsolicited", FAMILY, activity="mfa",
            delivery="mfa", content_ref="mfa-unexpected", hostile=True,
            weight=12,
            prerequisites=(
                # Not while an account incident is already open: the
                # compromise-conditioned variant below covers that case, and
                # two candidates racing to raise the same prompt would be one
                # arrival with two explanations.
                el.Prereq(el.INCIDENT_ABSENT, "inc-account"),
            )),
        _candidate(
            # Batch 4 correction (content pipeline wiring): the family's
            # recurring candidate -- already bounded to two occurrences by
            # ``max_occurrences``/``cooldown_ms``, modelling MFA-fatigue
            # behaviour. Each raised request now draws its notification
            # wording and the authenticator's displayed application label
            # from the ``content_variation`` stream at delivery time -- see
            # ``rewindsec.training.delivery._deliver_mfa`` -- while the
            # legitimate/hostile ground truth and the approval prompt's
            # inspectable device/location/network detail stay exactly as
            # authored.
            "cand-mfa-after-compromise", FAMILY, activity="mfa",
            delivery="mfa", content_ref="mfa-unexpected", hostile=True,
            weight=18, max_occurrences=2, cooldown_ms=45000,
            streams=("threat_selection", "content_variation"),
            prerequisites=(
                # The factual link. An attacker with a session tries again.
                el.Prereq(el.INCIDENT_OPEN, "inc-account"),
            )),
        _candidate(
            "cand-mfa-reauth", FAMILY, activity="mfa",
            delivery="mfa", content_ref="mfa-vpn", hostile=False,
            weight=10, max_occurrences=2, cooldown_ms=60000,
            prerequisites=(
                # Only ever a follow-up to the learner's own sign-in.
                el.Prereq(el.WORLD_FLAG, "vpn_connected"),
            )),
    )


def network_dependent_steps():
    """None.

    An approval request reaches a phone, not this workstation, and an
    attacker's session lives at the mail provider. Taking the workstation off
    the network neither stops the prompt nor evicts the session, and modelling
    it as though it did would teach the wrong lesson about what containment
    buys you.
    """
    return ()
