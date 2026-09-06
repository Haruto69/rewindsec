"""The ransomware family: document-borne impact, and what containment means.

Everything here is world state. No file on the host is read, written,
renamed, encrypted or executed; "unavailable" is a value in a row of the
synthetic file table, and the only thing that ever sets it is
:func:`rewindsec.workstation.worldops.set_file_state`. There is no payload, no
propagation, no real binary and no path from this module to a filesystem call.
The narrowly sandboxed Docker component the architecture reserves for real
isolated technical state is a later batch and does not run from here.

Entry vectors
-------------
Two, and both end in the same place: a macro-bearing workbook sitting in
Downloads with a hostile origin recorded against it.

* the attachment on the rate-card message, downloaded and then opened;
* a download from the look-alike billing portal in the Browser, which is new
  in this batch and which materialises the file through the *same* server-side
  collision resolver every other download uses.

Staged progression
------------------
The authored chain is already staged -- four steps with explicit causal
parents and explicit delays -- and Batch 3 does not flatten it. What it adds
is the distinction that makes containment mean something:

===============  ===========================================================
``s-file-1``     Local. A document on this machine stops opening.
``s-file-2``     Local. More of this machine's own files fail.
``s-file-3``     **Network.** The shared folder is written to over the LAN.
``s-file-4``     **Network.** A colleague notices, over the network.
``s-unc-1``      **Network.** Further shared-folder loss.
``s-unc-2``      **Network.** Finance lose the contracts workbook.
===============  ===========================================================

A workstation that is off the network cannot write to a share, so the network
steps do not happen -- and the local ones, having already happened, stay
happened. That asymmetry is the entire training point: containment is not
recovery, and nothing is rewound.
"""

from rewindsec.training import eligibility as el
from rewindsec.training.families import _candidate

__all__ = ["FAMILY", "candidates", "network_dependent_steps"]

FAMILY = "ransomware"


def candidates():
    return (
        _candidate(
            "cand-ransom-rate-card", FAMILY, activity="mail",
            delivery="mail", content_ref="m-rate-card",
            delivers_mail="m-rate-card", hostile=True, weight=12,
            prerequisites=(
                # The genuine supplier relationship has to exist before a
                # look-alike of it is a fair thing to send.
                el.Prereq(el.FACT_AVAILABLE, "org.vendor_contact"),
            )),
        _candidate(
            "cand-ransom-legit-guide", FAMILY, activity="mail",
            delivery="mail", content_ref="m-it-attachment",
            delivers_mail="m-it-attachment", hostile=False, weight=8,
            prerequisites=(
                el.Prereq(el.FACT_AVAILABLE, "org.servicedesk_contact"),
            )),
        _candidate(
            # Batch 4 review correction: a second, distinct ransomware lure
            # -- an audit-checklist pretext instead of a rate card -- so a
            # session's ransomware exposure is not limited to one one-shot
            # message. Independent decisions (d-ransom2-*), independent
            # opportunity, the same generic file-availability consequence
            # model (chain-file-incident/chain-uncontained) the rate-card
            # lure already uses.
            #
            # Batch 4 correction (content pipeline wiring): the family's
            # recurring candidate. ``max_occurrences=2`` -- the first
            # occurrence is the authored ``m-audit-checklist`` message
            # above; a second occurrence targets a distinct pre-seeded mail
            # row (``m-audit-checklist-o2``, its own decision pair
            # ``d-ransom3-*``) whose subject, sender persona and opening
            # line vary deterministically from the ``content_variation``
            # stream at delivery time; the attachment converges on the same
            # completely synthetic file-availability consequence model as
            # every other macro lure. See
            # ``rewindsec.training.delivery._deliver_mail`` and
            # ``rewindsec.training.recurrence``. ``delivers_mail`` is
            # deliberately unset for the same reason as the other two
            # recurring candidates: it would lock this candidate after the
            # first occurrence.
            "cand-ransom-audit-checklist", FAMILY, activity="mail",
            delivery="mail", content_ref="m-audit-checklist",
            hostile=True, weight=10, max_occurrences=2, cooldown_ms=50000,
            streams=("threat_selection", "content_variation")),
    )


def network_dependent_steps():
    """The chain steps that need a network to happen at all.

    Named as ``(chain_id, step_id)`` pairs rather than inferred from what an
    effect touches: "this file lives on a share" is a fact about the authored
    world, and guessing it from an effect's shape would silently start or stop
    suppressing steps whenever the content changed.
    """
    return (
        ("chain-file-incident", "s-file-3"),
        ("chain-file-incident", "s-file-4"),
        ("chain-uncontained", "s-unc-1"),
        ("chain-uncontained", "s-unc-2"),
    )
