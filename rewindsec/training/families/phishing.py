"""The phishing family: credential lures, and the ordinary mail beside them.

Two candidates, and the second one is the point of the first. A family that
only ever produces hostile messages teaches "a message arrived, report it",
which is the failure mode this product exists to avoid: a learner who reports
everything scores perfectly on a corpus of nothing but attacks. So the family
contributes a genuine payroll notice as well, structurally identical to the
lure -- same sender department, same kind of link, same tone -- and the
difference between them is evidence the learner has to go and find.

Context prerequisites
---------------------
The lure is gated on the *real* payroll domain being available in the mailbox
(``org.payroll_host``, established by the opening payslip notice). The reason
is fairness, not difficulty: ``payroll-northbridge.example`` is only
recognisable as a look-alike if ``payroll.northbridge.example`` has been in
front of the learner at some point. It is an AVAILABLE prerequisite and
deliberately not an OBSERVED one -- a learner who never opened the payslip
notice has still had the genuine domain in their mailbox, and gating on
attention would let inattention opt out of the hard events.

Consequences
------------
Unchanged from the authored chains, which already model this well: a
credential submission produces an attacker session, a mailbox rule that hides
Security Operations, an alert that the rule files away, and a colleague who
receives something purporting to come from the learner. Nothing is rewound.
The cross-family link -- a compromised account later producing an unsolicited
approval request -- is expressed as a *prerequisite* on the MFA family rather
than as a hard-coded "then fire MFA", so the follow-up has a real eligibility
reason and can be explained.
"""

from rewindsec.training import eligibility as el
from rewindsec.training.families import _candidate

__all__ = ["FAMILY", "candidates", "network_dependent_steps"]

FAMILY = "phishing"


def candidates():
    return (
        _candidate(
            "cand-phish-payroll-lure", FAMILY, activity="mail",
            delivery="mail", content_ref="m-payroll-restructure",
            delivers_mail="m-payroll-restructure", hostile=True, weight=12,
            prerequisites=(
                # AVAILABLE, not OBSERVED: the genuine payroll host has to
                # exist in this workplace for the look-alike to be judgeable.
                el.Prereq(el.FACT_AVAILABLE, "org.payroll_host"),
                el.Prereq(el.FACT_AVAILABLE, "org.payroll_sender"),
            )),
        _candidate(
            "cand-phish-payroll-genuine", FAMILY, activity="mail",
            delivery="mail", content_ref="m-payroll-genuine",
            delivers_mail="m-payroll-genuine", hostile=False, weight=8,
            prerequisites=(
                el.Prereq(el.FACT_AVAILABLE, "org.payroll_sender"),
            )),
        _candidate(
            # Batch 4 review correction: a second, distinct phishing surface
            # -- a benefits/HR themed lure, so a session's phishing exposure
            # is not limited to a single one-shot payroll message. Its own
            # decision quad (d-phish2-*), its own opportunity
            # (rewindsec.scoring.opportunities), the same generic
            # chain-credentials/chain-reported-hostile consequence model.
            # Ungated: the genuine benefits page (intranet.northbridge
            # .example/people/benefits) is always in the world already, so
            # -- unlike the payroll lure, whose look-alike is only fair to
            # judge once the genuine payroll host has appeared -- there is no
            # equivalent fairness gate needed here.
            #
            # Batch 4 correction (content pipeline wiring): this is now the
            # family's *recurring* candidate. ``max_occurrences=2`` -- the
            # first occurrence is the authored ``m-benefits-verify`` message
            # above; a second, later occurrence targets a distinct pre-seeded
            # mail row (``m-benefits-verify-o2``, its own decision quad
            # ``d-phish3-*``) whose subject, sender persona and opening line
            # are drawn deterministically from the ``content_variation``
            # stream at delivery time -- see
            # ``rewindsec.training.delivery._deliver_mail`` and
            # ``rewindsec.training.recurrence``. ``delivers_mail`` is
            # deliberately left unset: that prerequisite would lock this
            # candidate the moment the *first* occurrence's mail is
            # delivered, which is exactly the recurrence this candidate now
            # provides. Gating instead relies on ``max_occurrences`` and
            # ``cooldown_ms``, exactly as every other recurring candidate in
            # the catalogue already does.
            "cand-phish-benefits-lure", FAMILY, activity="mail",
            delivery="mail", content_ref="m-benefits-verify",
            hostile=True, weight=10, max_occurrences=2, cooldown_ms=50000,
            streams=("threat_selection", "content_variation")),
    )


def network_dependent_steps():
    """Chain steps that cannot happen while the workstation is off the network.

    The attacker's session, the mailbox rule and the colleague's message are
    all *server-side* events at the mail provider: they do not need this
    workstation to be online, and pretending otherwise would make network
    isolation a cure for account compromise, which it is not.

    So this family contributes nothing. Isolation contains file-level spread;
    it does not un-steal a credential.
    """
    return ()
