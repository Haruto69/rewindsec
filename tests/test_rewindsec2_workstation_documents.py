"""RewindSec 2.0 Batch 4: the read-only synthetic document viewer.

Covers Architecture Spec v1.1 S48-S61: content absent before open, present
after, safe rendering (no HTML/script survives as anything but literal
text), Context Ledger observation, downloaded-document integration for both
Mail and Browser (including the locked filename-collision behaviour), the
ransomware-unavailable state, and that no macro/parser/network path is ever
reached.
"""

import json

import pytest

from rewindsec.workstation.bootstrap import file_document_fact
from tests.workstation_helpers import Driver, build_service, file_row, sqlite_uri


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


def observed(driver, fact_id):
    ledger = driver.session().ledger
    return ledger.has(fact_id) and ledger.get(fact_id).observed


# ---------------------------------------------------------------------------
# Available != observed, for document content specifically
# ---------------------------------------------------------------------------

def test_document_content_is_absent_before_the_file_is_opened(driver):
    row = file_row(driver.snapshot(), "f-invoice")
    assert row is not None
    assert row["document"] is None
    assert not observed(driver, file_document_fact("f-invoice"))


def test_document_content_appears_once_the_file_is_opened(driver):
    driver.act("files.open", "f-invoice")
    row = file_row(driver.snapshot(), "f-invoice")
    assert row["document"] is not None
    assert row["document"]["title"] == "Invoice CF-20411"
    assert observed(driver, file_document_fact("f-invoice"))


def test_a_file_with_no_bound_document_never_gets_one(driver):
    driver.act("files.open", "f-scratch")
    row = file_row(driver.snapshot(), "f-scratch")
    assert row["document"] is None


# ---------------------------------------------------------------------------
# Safe rendering: structured content, JSON-safe, no HTML survives specially
# ---------------------------------------------------------------------------

def test_the_document_projection_is_plain_json_safe_structured_data(driver):
    driver.act("files.open", "f-invoice")
    row = file_row(driver.snapshot(), "f-invoice")
    document = row["document"]
    assert isinstance(document["blocks"], list)
    for block in document["blocks"]:
        assert block["type"] in ("paragraph", "heading", "key_value", "table", "list")
    # Round-trips through JSON with nothing left as an internal Python object
    # (the historical bug this guards against: a shallow dict copy of a
    # frozen ``MappingProxyType`` leaking into the response).
    json.dumps(row)


def test_a_table_document_renders_readable_rows(driver):
    driver.act("files.open", "f-headcount-model")
    row = file_row(driver.snapshot(), "f-headcount-model")
    tables = [b for b in row["document"]["blocks"] if b["type"] == "table"]
    assert tables
    assert tables[0]["headers"]
    assert tables[0]["rows"]


def test_long_document_scroll_model_is_just_more_blocks(driver):
    """The viewer has no special "too long" behaviour to test in isolation --
    a long document is simply more blocks, and the schema's own bound
    (``rewindsec.content.schema._MAX_BLOCKS``) is what keeps it finite."""
    driver.act("files.open", "f-handbook")
    row = file_row(driver.snapshot(), "f-handbook")
    assert len(row["document"]["blocks"]) >= 2


# ---------------------------------------------------------------------------
# Mail attachment downloads share the same viewer
# ---------------------------------------------------------------------------

def test_a_downloaded_mail_attachment_uses_the_same_document_viewer(driver):
    driver.deliver_until("m-vendor-invoice") if not any(
        m["id"] == "m-vendor-invoice" for m in driver.snapshot()["mail"]["messages"]
    ) else None
    driver.act("mail.open", "m-vendor-invoice")
    driver.act("mail.download_attachment", "m-vendor-invoice", {"index": 0})
    driver.act("files.open", "f-dl-m-vendor-invoice-0")
    row = file_row(driver.snapshot(), "f-dl-m-vendor-invoice-0")
    assert row["document"] is not None
    assert row["document"]["title"] == "Invoice CF-20411"


def test_the_ransomware_attachment_still_triggers_its_consequential_decision(driver):
    """Opening the malicious file is still consequential; the viewer must
    never render fabricated content standing in for it."""
    from rewindsec.workstation.bootstrap import NS_DECISIONS

    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    row = file_row(driver.snapshot(), "f-dl-m-rate-card-0")
    assert row["document"] is None
    assert "d-ransom-open" in driver.session().world.get_component(NS_DECISIONS)


# ---------------------------------------------------------------------------
# Browser downloads share the same viewer
# ---------------------------------------------------------------------------

def test_a_browser_downloaded_document_uses_the_same_viewer(driver):
    url = "intranet.northbridge.example/it/maintenance"
    driver.act("browser.navigate", params={"url": url})
    driver.act("browser.download", params={"url": url, "resource": "res-access-guide"})
    snapshot = driver.snapshot()
    downloaded = [f for f in snapshot["files"]["files"]
                 if f["name"] == "Remote_Access_Guide.pdf"]
    assert downloaded
    file_id = downloaded[0]["id"]
    driver.act("files.open", file_id)
    row = file_row(driver.snapshot(), file_id)
    assert row["document"] is not None
    assert row["document"]["title"] == "Remote Access Guide"


# ---------------------------------------------------------------------------
# Filename collisions still resolve to the same underlying content
# ---------------------------------------------------------------------------

def test_a_locked_filename_collision_still_opens_the_same_document(driver):
    """``report.pdf`` already exists as ``f-invoice``; downloading the same
    invoice from mail lands under a numbered name, but it is a *different*
    file id pointing at the *same* synthetic document."""
    driver.act("mail.open", "m-vendor-invoice") if any(
        m["id"] == "m-vendor-invoice" for m in driver.snapshot()["mail"]["messages"]
    ) else driver.deliver_until("m-vendor-invoice")
    driver.act("mail.download_attachment", "m-vendor-invoice", {"index": 0})
    files = driver.snapshot()["files"]["files"]
    invoices = [f for f in files if "Invoice_CF-20411" in f["name"]]
    assert len(invoices) == 2  # the pre-placed f-invoice, plus the download
    names = {f["name"] for f in invoices}
    assert "Invoice_CF-20411.pdf" in names
    assert any(n != "Invoice_CF-20411.pdf" for n in names)  # "(1)" variant

    for entry in invoices:
        driver.act("files.open", entry["id"])
        row = file_row(driver.snapshot(), entry["id"])
        assert row["document"]["title"] == "Invoice CF-20411"


# ---------------------------------------------------------------------------
# Unavailable (ransomware-affected) files
# ---------------------------------------------------------------------------

def test_an_unavailable_file_shows_no_document_even_if_bound(tmp_path):
    """Runs the real ransomware chain far enough that ``f-headcount-model``
    (a file this batch bound to a structured document) actually becomes
    unavailable, then confirms opening it shows no content."""
    service, _ = build_service(sqlite_uri(tmp_path, "unavailable.db"))
    driver = Driver.start(service, focus="ransomware", mode="simulation")
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")  # triggers the incident
    driver.advance(20000)  # past s-file-1, which affects f-headcount-model

    row_before = file_row(driver.snapshot(), "f-headcount-model")
    assert row_before["state"] == "unavailable"

    driver.act("files.open", "f-headcount-model")
    row = file_row(driver.snapshot(), "f-headcount-model")
    assert row["document"] is None
    assert row["state"] == "unavailable"


def test_no_iframe_object_embed_script_or_network_reference_anywhere_in_catalog():
    """A blunt but decisive safety check over the whole document catalogue:
    none of the forbidden HTML surfaces or a live URL ever appears, because
    the sanitizer that built every block would have refused it."""
    from rewindsec.content.catalog import all_documents

    banned = ("<iframe", "<object", "<embed", "<script", "javascript:", "http://", "https://")
    for document in all_documents():
        blob = json.dumps(document.to_projection()).lower()
        for token in banned:
            assert token not in blob, (document.document_id, token)
