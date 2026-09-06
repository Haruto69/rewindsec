"""RewindSec 2.0 Batch 4 correction: the content pipeline must reach runtime.

Architecture review found that Batch 4's first cut built the synthetic
content pipeline (provenance -> sanitize -> normalize -> archetype ->
generate -> bind -> catalog) but left most of it -- the mail and MFA
archetypes in particular -- unwired from the training engine, so a session's
actual breadth of delivered content had not materially grown.

This suite covers the correction: ``cand-bg-facilities-followup`` is a new,
live training candidate (the "arche-mail-document-review-request" archetype,
previously authored and tested but never selectable) that delivers a real
mail, whose subject is chosen deterministically from the ``content_variation``
stream, and whose attachment resolves to a document the pipeline's own
catalogue generated -- reaching the document viewer through the exact same
path the original invoice already used. None of this may perturb
threat-selection, timing or consequence draws, which stay on their own named
streams.
"""

from rewindsec.core.rng import (STREAM_CONSEQUENCE, STREAM_THREAT_SELECTION,
                                STREAM_TIMING)
from rewindsec.training import catalog
from rewindsec.workstation.bootstrap import file_document_fact
from tests.workstation_helpers import Driver, build_service, file_row, sqlite_uri


def driver_for(tmp_path, name="content_runtime.db"):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    return Driver.start(service, focus="mixed", mode="simulation")


def _has(driver, mail_id):
    return any(m["id"] == mail_id for m in driver.snapshot()["mail"]["messages"])


def test_the_new_candidate_is_registered_in_the_live_catalogue():
    candidate = catalog.by_id("cand-bg-facilities-followup")
    assert candidate is not None
    assert candidate.family == "background"
    assert candidate.content_ref == "m-facilities-followup"
    assert "content_variation" in candidate.streams


def test_forcing_the_candidate_delivers_a_real_mail_with_a_deterministic_subject(tmp_path):
    driver = driver_for(tmp_path)
    driver.force("cand-bg-facilities-followup")
    assert _has(driver, "m-facilities-followup")
    message = next(m for m in driver.snapshot()["mail"]["messages"]
                  if m["id"] == "m-facilities-followup")
    assert message["subject"] in (
        "Quick look before it goes out?",
        "Two minutes for a second pair of eyes?")


def test_the_subject_variant_is_stable_across_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "resume_subject.db")
    service, _ = build_service(uri, ids=["ws-content-resume"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.force("cand-bg-facilities-followup")
    first = next(m for m in driver.snapshot()["mail"]["messages"]
                if m["id"] == "m-facilities-followup")["subject"]

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    second = next(m for m in resumed.snapshot()["mail"]["messages"]
                 if m["id"] == "m-facilities-followup")["subject"]
    assert first == second


def test_the_attachment_resolves_to_a_pipeline_generated_document(tmp_path):
    driver = driver_for(tmp_path, "content_doc.db")
    driver.force("cand-bg-facilities-followup")
    driver.act("mail.open", "m-facilities-followup")
    driver.act("mail.download_attachment", "m-facilities-followup", {"index": 0})
    driver.act("files.open", "f-dl-m-facilities-followup-0")
    row = file_row(driver.snapshot(), "f-dl-m-facilities-followup-0")
    assert row["document"] is not None
    assert row["document"]["title"] == "Facilities Update — Draft"
    ledger = driver.session().ledger
    fact = ledger.get(file_document_fact("f-dl-m-facilities-followup-0"))
    assert fact.observed


def test_content_variation_draws_do_not_perturb_other_streams(tmp_path):
    """The whole point of a named stream partition: the extra draw this
    candidate's subject-variant pick makes on ``content_variation`` must not
    change the draw count on threat-selection, timing or consequence --
    those streams must consume exactly what they would have without it."""
    driver = driver_for(tmp_path, "isolation.db")

    def draws():
        session = driver.session()
        return (
            session.rng.stream(STREAM_THREAT_SELECTION).draws,
            session.rng.stream(STREAM_TIMING).draws,
            session.rng.stream(STREAM_CONSEQUENCE).draws,
        )

    before = draws()
    driver.force("cand-bg-facilities-followup")
    after = draws()
    assert before == after
