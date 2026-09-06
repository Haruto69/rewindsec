"""The BEC family: payment redirection inside a thread that is already real.

BEC is the family where context does the work. There is no bad domain to spot
in the ordinary case and no attachment to refuse; there is a supplier the
company genuinely uses, an invoice that genuinely exists, and a request to
settle it somewhere new. What separates the fraud from the routine is whether
the learner checks the account against the record they already hold, on a
channel the request did not supply.

The OBSERVED prerequisite
-------------------------
The hostile candidate arrives as ``Re: Calderwood Facilities — invoice
CF-20411``, threaded onto a message that is already in the mailbox. That reply
is gated on the learner having **observed** the original invoice
(``mail.m-vendor-invoice.body``), and this is the one place in the catalogue
where OBSERVED is the right semantics rather than AVAILABLE:

* a reply to a thread the learner has read is an ordinary thing that happens;
* the same reply to a thread they have never opened is a message from nowhere,
  and the "Re:" is a claim about a conversation that, from where the learner
  is sitting, did not take place.

The account of record (``org.vendor_account``) is required only to be
AVAILABLE. The learner does not have to have looked it up for the fraud to be
fair -- looking it up is precisely the thing being measured, and requiring it
first would grade the answer before asking the question.

The legitimate comparison
-------------------------
The same supplier also sends an ordinary purchase-order update, from the real
domain, changing nothing about settlement. Refusing to act on it, reporting
it, or demanding verification for it are all over-suspicious responses to
routine work, and the world responds accordingly.

Consequences
------------
Releasing a payment to the changed account queues it, brings Finance asking
who authorised the change, and leaves the real supplier still unpaid --
factual, sequenced, and not undone by anything the learner does afterwards.
Verifying through Messages or the Directory reaches the supplier on a number
that came from the organisation's own records rather than from the request.
"""

from rewindsec.training import eligibility as el
from rewindsec.training.families import _candidate

__all__ = ["FAMILY", "candidates", "network_dependent_steps"]

FAMILY = "bec"


def candidates():
    return (
        _candidate(
            "cand-bec-account-change", FAMILY, activity="mail",
            delivery="mail", content_ref="m-invoice-amend",
            delivers_mail="m-invoice-amend", hostile=True, weight=12,
            prerequisites=(
                # AVAILABLE: the account of record must exist in the world.
                el.Prereq(el.FACT_AVAILABLE, "org.vendor_account"),
                # OBSERVED: a reply only threads onto a conversation the
                # learner has actually had.
                el.Prereq(el.FACT_OBSERVED, "mail.m-vendor-invoice.body"),
            )),
        _candidate(
            "cand-bec-legit-po", FAMILY, activity="mail",
            delivery="mail", content_ref="m-vendor-po-update",
            delivers_mail="m-vendor-po-update", hostile=False, weight=8,
            prerequisites=(
                el.Prereq(el.FACT_AVAILABLE, "org.vendor_contact"),
            )),
    )


def network_dependent_steps():
    """None.

    A payment instruction is submitted through the finance system before any
    isolation decision is taken, and Finance and the supplier are not on this
    workstation. Isolating after releasing a payment does not recall it, and
    the simulation must not imply that it might.
    """
    return ()
