"""Bounded, deterministic recurrence for the live threat-family candidates.

Batch 4 review correction. The synthetic-content pipeline
(:mod:`rewindsec.content`) shipped generation primitives -- a stable id
derivation and a stream-driven variant chooser -- with exactly one production
consumer: a subject-line override on one background candidate. This module is
what makes the pipeline reach an actual recurring *threat* surface, for one
candidate in each of the phishing, BEC and ransomware families, without
turning candidate selection itself into anything other than what Batch 3
already made it.

The shape, deliberately narrow
-------------------------------
A recurring candidate's **first** occurrence is exactly the authored message
it always was -- unchanged surface, unchanged decision quad, unchanged
opportunity. Its **second** occurrence targets a second, distinct, pre-seeded
mail row (its own id, its own small decision quad, its own opportunity in
:mod:`rewindsec.scoring.opportunities`) whose presentation -- subject, sender
persona, opening line -- is chosen deterministically at delivery time from the
session's own ``content_variation`` stream via
:func:`rewindsec.content.generate.choose_variant`, and whose stable identity
is derived via :func:`rewindsec.content.generate.derive_content_id` -- never
Python's ``hash()``.

Nothing here decides *whether* a candidate fires: that is still the engine's
lottery, drawing from ``threat_selection``, gated by the candidate's own
``max_occurrences``/``cooldown_ms`` exactly like every other candidate. This
module runs only *after* :mod:`rewindsec.training.delivery` has already put a
message in the mailbox, and it draws from ``content_variation`` alone, so an
extra field in a variant tuple below can change what a learner reads and
nothing else -- not which candidate was selected, not when, not what happens
next.

Underlying financial/organisational facts never vary
------------------------------------------------------
The BEC second occurrence keeps the exact vendor, sort code and account
number the first occurrence already established: recurrence here means a
second message about the same fraud, not a second, fabricated supplier
relationship. Nothing in this module ever invents an account, a vendor or an
organisation that is not already part of the authored synthetic world.
"""

from rewindsec.content import generate

__all__ = ["OCCURRENCE_MAIL_IDS", "SURFACE_VARIANTS", "occurrence_mail_id",
           "generated_surface"]

#: candidate_id -> the mail id delivered for each 0-based occurrence index.
#: Occurrence 0 is always the pre-existing, fully-authored message; only
#: occurrence 1 onward is a pipeline-generated surface. Kept as an explicit
#: table (rather than a naming convention like ``"%s-o%d"``) so a stable id
#: is never guessed from a candidate id at runtime.
OCCURRENCE_MAIL_IDS = {
    "cand-phish-benefits-lure": ("m-benefits-verify", "m-benefits-verify-o2"),
    "cand-bec2-account-change": ("m-meridian-amend", "m-meridian-amend-o2"),
    "cand-ransom-audit-checklist": ("m-audit-checklist", "m-audit-checklist-o2"),
}

#: candidate_id -> authored presentation fields for its *generated*
#: occurrences (index 1 onward). Each value is a tuple of variants; callers
#: draw exactly one per field via :func:`choose_variant`, so the number of
#: draws is fixed and proportional to the number of fields, never to the size
#: of a variant pool. Every string here is internally authored synthetic
#: content -- no real organisation, domain or person.
SURFACE_VARIANTS = {
    "cand-phish-benefits-lure": {
        "subject": (
            "Reminder: your benefits selections are still unconfirmed",
            "Second notice — confirm your benefits enrolment today",
        ),
        "from_name": (
            "Northbridge Benefits",
            "Northbridge Benefits Enrolment Team",
        ),
        "opening_line": (
            "Following up on our earlier note — enrolment closes at the end "
            "of the day and your selections are still showing as "
            "unconfirmed.",
            "One more reminder: our records still show your benefits "
            "enrolment as incomplete for this cycle.",
        ),
    },
    "cand-bec2-account-change": {
        "subject": (
            "Re: Meridian Print Services — invoice MP-7734 (following up)",
            "Re: Meridian Print Services — invoice MP-7734, still open",
        ),
        "from_name": (
            "Gordon Whyte",
            "Gordon Whyte, Meridian Print Services",
        ),
        "opening_line": (
            "Checking in on this — were you able to get the account details "
            "updated on your side yet?",
            "Just following up again, since this is still showing as "
            "outstanding on our end.",
        ),
    },
    "cand-ransom-audit-checklist": {
        "subject": (
            "Reminder: compliance self-audit checklist still due",
            "Second notice — self-audit checklist outstanding",
        ),
        "from_name": (
            "Northbridge Compliance",
            "Northbridge Compliance Office",
        ),
        "opening_line": (
            "Following up on the self-audit checklist sent earlier this "
            "week — it is still showing as outstanding.",
            "Reminder: the attached self-audit checklist has not been "
            "returned yet and is now overdue.",
        ),
    },
}

#: candidate_id -> notification-body phrasing for the *authenticator*
#: family's recurring candidate. MFA has no second physical mail id -- the
#: same authored prompt (``mfa-unexpected``) is legitimately raised more than
#: once, so recurrence here varies only the arrival notification and the
#: authenticator's displayed application label, never the inspectable
#: device/location/network detail, which stays exactly as authored.
MFA_NOTIFICATION_VARIANTS = {
    "cand-mfa-after-compromise": {
        "body": (
            "Sign-in approval requested again from an unrecognised device.",
            "Another approval request from a device you have not used "
            "before.",
        ),
        "app": (
            "Mail",
            "Mail (web)",
        ),
    },
}


def occurrence_mail_id(candidate_id, occurrence):
    """The mail id delivery should target for *occurrence* (0-based).

    ``None`` if this candidate is not one of the recurring mail candidates,
    or if *occurrence* is out of the table's bounds -- callers treat either
    as "nothing to deliver", never as an error, because
    ``max_occurrences``/eligibility is what is supposed to keep this in
    range and a defensive ``None`` here is cheaper than trusting it blindly.
    """
    mail_ids = OCCURRENCE_MAIL_IDS.get(candidate_id)
    if mail_ids is None or occurrence < 0 or occurrence >= len(mail_ids):
        return None
    return mail_ids[occurrence]


def generated_surface(session, candidate_id, occurrence):
    """The generated presentation fields for one occurrence, or ``None``.

    ``None`` for occurrence 0 (the authored message needs no generation) and
    for any candidate with no authored variant table. Otherwise draws exactly
    one value per field from the session's own ``content_variation`` stream,
    via :func:`rewindsec.content.generate.choose_variant`, and returns a dict
    of override field values plus a stable ``content_id`` derived from
    ``(session identity, candidate id, occurrence)`` -- never regenerated
    from the current RNG position, only ever computed once at delivery and
    then persisted by the caller.
    """
    if occurrence <= 0:
        return None
    variants = SURFACE_VARIANTS.get(candidate_id)
    if variants is None:
        return None
    stream = session.rng.stream(_content_variation_stream())
    subject = generate.choose_variant(stream, variants["subject"])
    from_name = generate.choose_variant(stream, variants["from_name"])
    opening_line = generate.choose_variant(stream, variants["opening_line"])
    content_id = generate.derive_content_id(
        session.session_id, candidate_id, occurrence)
    return {
        "subject_override": subject,
        "from_name_override": from_name,
        "opening_line_override": opening_line,
        "content_variation_id": content_id,
    }


def mfa_notification_variant(session, candidate_id, occurrence):
    """The generated notification wording for one MFA occurrence, or ``None``.

    Unlike :func:`generated_surface`, this draws for *every* occurrence
    (including the first) -- there is no "authored baseline" occurrence for a
    request that legitimately repeats, and each request is already its own
    fresh row in the world (see
    :func:`rewindsec.workstation.worldops.create_auth_request`).
    """
    variants = MFA_NOTIFICATION_VARIANTS.get(candidate_id)
    if variants is None:
        return None
    stream = session.rng.stream(_content_variation_stream())
    body = generate.choose_variant(stream, variants["body"])
    app = generate.choose_variant(stream, variants["app"])
    content_id = generate.derive_content_id(
        session.session_id, candidate_id, occurrence)
    return {"body": body, "app": app, "content_id": content_id}


def _content_variation_stream():
    from rewindsec.core.rng import STREAM_CONTENT_VARIATION
    return STREAM_CONTENT_VARIATION
