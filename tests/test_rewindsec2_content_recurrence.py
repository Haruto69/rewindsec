"""RewindSec 2.0 Batch 4 correction: bounded, deterministic threat recurrence.

Batch 4's first cut wired the synthetic-content pipeline
(:mod:`rewindsec.content`) into exactly one *background* candidate. Review
found that live threat content -- phishing, BEC, MFA, ransomware -- was still
delivered as additional one-shot candidates rather than actually using the
pipeline for bounded recurring variation. This suite covers the correction:
one candidate per threat family now recurs (capped at two occurrences), and
its later occurrence's presentation is drawn deterministically from the
session's own ``content_variation`` stream via
:mod:`rewindsec.training.recurrence`.

Candidate selection (which candidate, when) is untouched -- still the Batch 3
engine, still drawing only from ``threat_selection``/``background``. What
changed is what happens *after* a recurring candidate is selected a second
time.
"""

from rewindsec.core.rng import (STREAM_BACKGROUND, STREAM_CONSEQUENCE,
                                STREAM_THREAT_SELECTION, STREAM_TIMING)
from rewindsec.training import catalog, eligibility
from rewindsec.training import state as engine_state
from rewindsec.workstation.bootstrap import NS_DECISIONS, NS_MAIL
from tests.training_helpers import fresh_session
from tests.workstation_helpers import Driver, build_service, message, sqlite_uri, walk

RECURRING_CANDIDATES = {
    "phishing": ("cand-phish-benefits-lure", "m-benefits-verify",
                "m-benefits-verify-o2"),
    "bec": ("cand-bec2-account-change", "m-meridian-amend",
           "m-meridian-amend-o2"),
    "ransomware": ("cand-ransom-audit-checklist", "m-audit-checklist",
                  "m-audit-checklist-o2"),
}


def driver_for(tmp_path, name="recurrence.db", session_id="ws-recurrence"):
    service, _ = build_service(sqlite_uri(tmp_path, name), ids=[session_id])
    return Driver.start(service, focus="mixed", mode="simulation")


# ---------------------------------------------------------------------------
# Catalogue shape
# ---------------------------------------------------------------------------

def test_one_recurring_candidate_per_threat_family_is_registered():
    for family, (candidate_id, _, _) in RECURRING_CANDIDATES.items():
        candidate = catalog.by_id(candidate_id)
        assert candidate is not None
        assert candidate.family == family
        assert candidate.max_occurrences == 2
        assert candidate.cooldown_ms > 0
        assert "content_variation" in candidate.streams
        # A recurring candidate must not be locked forever after its first
        # occurrence -- see rewindsec.training.families.* for why.
        assert candidate.delivers_mail is None

    mfa_candidate = catalog.by_id("cand-mfa-after-compromise")
    assert mfa_candidate.max_occurrences == 2
    assert "content_variation" in mfa_candidate.streams


# ---------------------------------------------------------------------------
# Distinct concrete surfaces, per family
# ---------------------------------------------------------------------------

def test_phishing_recurring_candidate_produces_two_distinct_surfaces(tmp_path):
    candidate_id, first_id, second_id = RECURRING_CANDIDATES["phishing"]
    driver = driver_for(tmp_path)
    driver.force(candidate_id)
    driver.force(candidate_id)

    first = message(driver.snapshot(), first_id)
    second = message(driver.snapshot(), second_id)
    assert first is not None and second is not None
    assert first["id"] != second["id"]
    assert first["subject"] != second["subject"]
    assert second["subject"] in (
        "Reminder: your benefits selections are still unconfirmed",
        "Second notice — confirm your benefits enrolment today")
    # The look-alike destination is unchanged: the same lure, not a second
    # independent one.
    assert first["links"][0]["text"] == second["links"][0]["text"]


def test_bec_recurring_candidate_stays_coherent_with_the_account_of_record(tmp_path):
    candidate_id, first_id, second_id = RECURRING_CANDIDATES["bec"]
    driver = driver_for(tmp_path)
    driver.act("mail.open", "m-meridian-invoice")  # satisfy the OBSERVED gate
    driver.force(candidate_id)
    driver.force(candidate_id)

    first = message(driver.snapshot(), first_id)
    second = message(driver.snapshot(), second_id)
    assert first is not None and second is not None
    assert first["subject"] != second["subject"]
    # The financial facts a learner would check against the Directory must
    # never differ between occurrences of the same fraud.
    assert "Corvane Bank" in " ".join(first["body"])
    assert "Corvane Bank" in " ".join(second["body"])
    assert "3384" in " ".join(first["body"])
    assert "3384" in " ".join(second["body"])
    assert first["from_address"] == second["from_address"]


def test_ransomware_recurring_candidate_produces_two_distinct_safe_lures(tmp_path):
    candidate_id, first_id, second_id = RECURRING_CANDIDATES["ransomware"]
    driver = driver_for(tmp_path)
    driver.force(candidate_id)
    driver.force(candidate_id)

    first = message(driver.snapshot(), first_id)
    second = message(driver.snapshot(), second_id)
    assert first is not None and second is not None
    assert first["subject"] != second["subject"]
    assert first["attachments"][0]["name"] != second["attachments"][0]["name"]

    # Opening the second occurrence's attachment converges on the same
    # synthetic file-availability consequence model, through its own
    # decision.
    driver.act("mail.open", second_id)
    driver.act("mail.download_attachment", second_id, {"index": 0})
    driver.act("files.open", "f-dl-%s-0" % second_id)
    decisions = set(driver.session().world.get_component(NS_DECISIONS))
    assert "d-ransom3-open" in decisions


def test_mfa_recurring_candidate_produces_distinct_bounded_requests(tmp_path):
    from rewindsec.workstation.bootstrap import NS_AUTH_REQUESTS

    driver = driver_for(tmp_path)
    driver.force("cand-mfa-after-compromise")
    first_id = driver.snapshot()["authenticator"]["requests"][0]["id"]
    # The same authored prompt cannot be raised twice while one instance of
    # it is still pending -- see worldops.create_auth_request. A second,
    # later occurrence is only meaningful once the first has been resolved,
    # exactly as a real MFA-fatigue sequence plays out.
    driver.act("auth.deny", first_id)
    driver.force("cand-mfa-after-compromise")

    rows = driver.session().world.get_component(NS_AUTH_REQUESTS)
    assert len(rows) == 2
    content_ids = {row["content_variation_id"] for row in rows.values()}
    assert len(content_ids) == 2, "each occurrence must have its own stable id"


# ---------------------------------------------------------------------------
# Occurrence caps and cooldown
# ---------------------------------------------------------------------------

def test_occurrence_cap_locks_the_candidate_after_two_occurrences():
    session = fresh_session(focus="mixed")
    candidate_id = "cand-phish-benefits-lure"
    candidate = catalog.by_id(candidate_id)
    engine_state.bump_candidate(session, candidate_id)
    engine_state.bump_candidate(session, candidate_id)
    verdict = eligibility.evaluate(
        session, candidate, engine_state.family_state(session, "phishing"),
        session.now_ms, "mixed", None, False)
    assert not verdict.eligible
    assert "max_occurrences" in verdict.reasons


def test_cooldown_still_applies_between_occurrences():
    session = fresh_session(focus="mixed")
    candidate_id = "cand-ransom-audit-checklist"
    candidate = catalog.by_id(candidate_id)
    engine_state.bump_candidate(session, candidate_id)
    verdict = eligibility.evaluate(
        session, candidate, engine_state.family_state(session, "ransomware"),
        session.now_ms, "mixed", None, False)
    assert not verdict.eligible
    assert "cooldown" in verdict.reasons


# ---------------------------------------------------------------------------
# Stable, distinct occurrence identity
# ---------------------------------------------------------------------------

def test_repeated_occurrence_ids_are_distinct_but_deterministic(tmp_path):
    candidate_id, _, second_id = RECURRING_CANDIDATES["phishing"]

    def content_variation_id(db_name, session_id):
        service, _ = build_service(
            sqlite_uri(tmp_path, db_name), ids=[session_id])
        driver = Driver.start(service, focus="mixed", mode="simulation")
        driver.force(candidate_id)
        driver.force(candidate_id)
        state = driver.session().world.get(NS_MAIL, second_id)
        return state["content_variation_id"]

    # Two independent databases, the *same* session identity in each --
    # exactly the "same input, different process" case, not a resume.
    first_run = content_variation_id("occ_a.db", "ws-occ-a")
    second_run = content_variation_id("occ_b.db", "ws-occ-a")
    different_session = content_variation_id("occ_c.db", "ws-occ-b")

    assert first_run == second_run  # same session identity -> same id
    assert first_run != different_session  # different session -> different id
    assert isinstance(first_run, str) and len(first_run) == 32


# ---------------------------------------------------------------------------
# Persistence: delivered surfaces survive save/resume byte-equivalently
# ---------------------------------------------------------------------------

def test_generated_surface_survives_resume_byte_equivalently(tmp_path):
    candidate_id, _, second_id = RECURRING_CANDIDATES["ransomware"]
    uri = sqlite_uri(tmp_path, "resume_recurrence.db")
    service, _ = build_service(uri, ids=["ws-resume-recurrence"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.force(candidate_id)
    driver.force(candidate_id)
    before = message(driver.snapshot(), second_id)

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    after = message(resumed.snapshot(), second_id)

    assert before == after


# ---------------------------------------------------------------------------
# Same seed and input give the same occurrence surfaces across processes
# ---------------------------------------------------------------------------

def test_same_seed_gives_the_same_occurrence_surfaces_across_processes(tmp_path):
    candidate_id, _, second_id = RECURRING_CANDIDATES["bec"]

    def run(name):
        service, _ = build_service(sqlite_uri(tmp_path, "%s.db" % name),
                                   seed=9090, ids=["ws-same-seed"])
        driver = Driver.start(service, focus="mixed", mode="simulation")
        driver.act("mail.open", "m-meridian-invoice")
        driver.force(candidate_id)
        driver.force(candidate_id)
        return message(driver.snapshot(), second_id)

    first_process = run("process_a")
    second_process = run("process_b")
    assert first_process == second_process


# ---------------------------------------------------------------------------
# RNG isolation
# ---------------------------------------------------------------------------

def test_extra_content_variation_draws_do_not_perturb_other_streams(tmp_path):
    candidate_id = RECURRING_CANDIDATES["phishing"][0]
    driver = driver_for(tmp_path, "isolation.db")
    driver.force(candidate_id)  # occurrence 0 -- draws nothing from content_variation

    def draws():
        session = driver.session()
        return (
            session.rng.stream(STREAM_THREAT_SELECTION).draws,
            session.rng.stream(STREAM_TIMING).draws,
            session.rng.stream(STREAM_BACKGROUND).draws,
            session.rng.stream(STREAM_CONSEQUENCE).draws,
        )

    before = draws()
    driver.force(candidate_id)  # occurrence 1 -- draws from content_variation
    after = draws()
    assert before == after


# ---------------------------------------------------------------------------
# No leakage of hidden classification into the learner projection
# ---------------------------------------------------------------------------

_FORBIDDEN_KEYS = frozenset({
    "analysis", "disposition", "hostile", "is_hostile", "family",
    "archetype", "content_ref",
})
_FORBIDDEN_VALUES = frozenset({"hostile", "phishing", "ransomware", "bec"})


def test_generated_occurrences_leak_no_classification_or_archetype_metadata(tmp_path):
    driver = driver_for(tmp_path, "leakage.db")
    driver.act("mail.open", "m-meridian-invoice")
    for candidate_id, _, _ in RECURRING_CANDIDATES.values():
        driver.force(candidate_id)
        driver.force(candidate_id)
    driver.force("cand-mfa-after-compromise")
    driver.force("cand-mfa-after-compromise")

    snapshot = driver.snapshot()
    for path, value in walk(snapshot):
        key = path.rsplit(".", 1)[-1].split("[")[0]
        assert key not in _FORBIDDEN_KEYS, path
        if isinstance(value, str):
            assert value.strip().lower() not in _FORBIDDEN_VALUES, (path, value)


# ---------------------------------------------------------------------------
# A longer Mixed run carries generated variety, not only the one-shot catalogue
# ---------------------------------------------------------------------------

def test_a_longer_mixed_run_can_deliver_a_generated_second_occurrence(tmp_path):
    """Not a guarantee -- the lottery may never re-select the same candidate
    within a bounded number of pulses -- but forcing the same candidate twice,
    exactly as the engine's own lottery would if it selected it again, must
    reach the generated second occurrence and not merely redeliver the first
    message a second time."""
    driver = driver_for(tmp_path, "mixed_run.db")
    delivered_before = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    for candidate_id, first_id, second_id in RECURRING_CANDIDATES.values():
        driver.force(candidate_id)
        driver.force(candidate_id)
    delivered_after = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    generated_ids = {second for _, _, second in RECURRING_CANDIDATES.values()}
    assert generated_ids <= (delivered_after - delivered_before)
