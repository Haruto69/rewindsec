"""RewindSec 2.0 Batch 4 review correction: no more early exhaustion.

The architecture review's core complaint about the first correction pass:
"a session is no longer effectively exhausted after the original tiny
one-shot threat catalogue" was not actually true yet -- only one live
background candidate had been added. This suite asserts the acceptance test
the review specified directly: over a long simulated horizon, a session
receives multiple distinct threat surfaces, multiple legitimate/background
surfaces, and at least two concrete instances from a recurring family --
without asserting exact prose or draw ordering, which is not the product
requirement.
"""

from rewindsec.workstation.bootstrap import (NS_AUTH_REQUESTS, NS_MAIL)
from tests.workstation_helpers import Driver, build_service, sqlite_uri

#: Long enough that the old one-shot-per-family catalogue would have been
#: fully exhausted several times over; short enough to run quickly under test.
_LONG_HORIZON_MS = 30 * 60 * 1000

#: The mail ids this batch's review correction added. If a long session never
#: sees any of these, the breadth correction did not actually reach a normal
#: (non-forced) session.
_NEW_SURFACE_MAIL_IDS = {
    "m-benefits-verify", "m-meridian-invoice", "m-meridian-amend",
    "m-audit-checklist", "m-facilities-followup", "m-standup-notes",
}

_HOSTILE_FAMILIES = {
    "m-payroll-restructure": "phishing", "m-benefits-verify": "phishing",
    "m-rate-card": "ransomware", "m-audit-checklist": "ransomware",
    "m-invoice-amend": "bec", "m-meridian-amend": "bec",
}


def _delivered_mail_ids(session):
    return {mail_id for mail_id, state in session.world.get_component(NS_MAIL).items()
           if state.get("delivered")}


def _raised_prompt_count(session):
    return len(session.world.get_component(NS_AUTH_REQUESTS))


def _run_long_session(tmp_path, name, focus):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    driver = Driver.start(service, focus=focus, mode="simulation")
    driver.advance(_LONG_HORIZON_MS)
    return driver


def test_a_long_mixed_session_receives_meaningfully_varied_content(tmp_path):
    driver = _run_long_session(tmp_path, "long_mixed.db", "mixed")
    delivered = _delivered_mail_ids(driver.session())

    # Meaningfully more than the old one-shot-per-family baseline (three
    # hostile mails plus a handful of background/legitimate ones).
    assert len(delivered) >= 8

    # At least one of the surfaces this correction added actually reached
    # this session without being forced.
    assert delivered & _NEW_SURFACE_MAIL_IDS

    # At least one legitimate/background surface, and at least one hostile
    # one -- a session of nothing but attacks (or nothing but chatter) would
    # not demonstrate the required variety.
    hostile_present = {m for m in delivered if m in _HOSTILE_FAMILIES}
    assert hostile_present
    assert delivered - hostile_present


def test_a_long_mixed_session_can_see_two_families_worth_of_hostile_surfaces(tmp_path):
    """Not one family's entire exposure carried by a single message."""
    driver = _run_long_session(tmp_path, "long_mixed2.db", "mixed")
    delivered = _delivered_mail_ids(driver.session())
    families_seen = {_HOSTILE_FAMILIES[m] for m in delivered if m in _HOSTILE_FAMILIES}
    assert len(families_seen) >= 2


def test_a_long_phishing_focused_session_sees_both_phishing_lures(tmp_path):
    """The recurring-family acceptance test: at least two concrete instances
    from the same family, over a long enough horizon, in a session focused
    on that exact family."""
    driver = _run_long_session(tmp_path, "long_phishing.db", "phishing")
    delivered = _delivered_mail_ids(driver.session())
    phishing_lures = delivered & {"m-payroll-restructure", "m-benefits-verify"}
    assert len(phishing_lures) == 2


def test_a_long_bec_focused_session_can_reach_the_second_vendor(tmp_path):
    driver = _run_long_session(tmp_path, "long_bec.db", "bec")
    driver.act("mail.open", "m-vendor-invoice")
    driver.act("mail.open", "m-meridian-invoice")
    driver.advance(_LONG_HORIZON_MS)
    delivered = _delivered_mail_ids(driver.session())
    assert "m-invoice-amend" in delivered
    assert "m-meridian-amend" in delivered


def test_a_long_ransomware_focused_session_sees_both_lures(tmp_path):
    driver = _run_long_session(tmp_path, "long_ransomware.db", "ransomware")
    delivered = _delivered_mail_ids(driver.session())
    lures = delivered & {"m-rate-card", "m-audit-checklist"}
    assert len(lures) == 2


def test_recurrence_stays_bounded_not_infinite(tmp_path):
    """Even over a long horizon, delivery is bounded by authored
    occurrence caps and cooldowns -- not endless repetition."""
    driver = _run_long_session(tmp_path, "long_bounded.db", "mfa")
    session = driver.session()
    # cand-mfa-unsolicited (max_occurrences=1) + cand-mfa-after-compromise
    # (max_occurrences=2): at most 3 raised MFA requests total, however long
    # the session runs.
    assert _raised_prompt_count(session) <= 3
