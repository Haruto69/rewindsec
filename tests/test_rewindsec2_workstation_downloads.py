"""Downloading a file never lands on top of one the learner already has.

The synthetic Files app is a folder the learner reads evidence out of: which
invoice arrived, when, from whom. A download that silently replaced a file of
the same name would destroy exactly that evidence, and a second row with an
identical name would be just as bad -- two ``Invoice_CF-20411.pdf`` in
Downloads is a folder nobody can reason about.

So a download that would collide is kept alongside the original under the
numbered name every desktop file manager uses, and that name is decided in one
place: :func:`rewindsec.workstation.worldops.resolve_download_name`, on the
server, from world state alone.

Nothing here touches the host filesystem, and nothing in the code path under
test could: the whole "folder" is a component in the persisted world.
"""

import io
import os
import re

import pytest

from rewindsec.workstation.bootstrap import NS_FILES, file_fact
from rewindsec.workstation.errors import StaleRevisionConflict
from rewindsec.workstation.worldops import resolve_download_name
from tests.workstation_helpers import (Driver, build_service, file_row,
                                       sqlite_uri)

DOWNLOADS = "loc-downloads"

#: Two authored messages carry an attachment whose filename is already in the
#: learner's Downloads folder from the start of the session. That is not a
#: contrivance for this suite -- it is the ordinary case, and it is what used
#: to produce two identically named rows.
VENDOR_INVOICE = ("m-vendor-invoice", "f-invoice", "Invoice_CF-20411.pdf")
OPS_AGENDA = ("m-ops-agenda", "f-agenda", "Ops_Review_Agenda.pdf")


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


def place(session, name, location=DOWNLOADS, deleted=False, file_id=None):
    """Put a synthetic file in a folder, the way seeding or a download would."""
    identifier = file_id or ("f-placed-%d" % len(
        session.world.get_component(NS_FILES)))
    session.mutate_world(NS_FILES, identifier, {
        "location": location, "name": name, "display_name": None,
        "kind": "document", "size": "1 KB", "modified": "Today 09:00",
        "state": "normal", "note": "", "owner": None, "source": None,
        "preview": [], "order": 0, "macro": False, "origin_mail": None,
        "deleted": deleted,
    })
    return identifier


def names(snapshot, location=DOWNLOADS):
    return [entry["name"] for entry in snapshot["files"]["files"]
            if entry["location"] == location]


# ===========================================================================
# The algorithm
# ===========================================================================

def test_a_free_name_is_used_unchanged(driver):
    session = driver.session()
    assert resolve_download_name(session, DOWNLOADS, "report.pdf") == "report.pdf"


def test_one_collision_becomes_one(driver):
    session = driver.session()
    place(session, "report.pdf")
    assert resolve_download_name(
        session, DOWNLOADS, "report.pdf") == "report (1).pdf"


def test_more_collisions_take_the_next_free_number(driver):
    session = driver.session()
    place(session, "report.pdf")
    place(session, "report (1).pdf")
    place(session, "report (2).pdf")
    assert resolve_download_name(
        session, DOWNLOADS, "report.pdf") == "report (3).pdf"


def test_a_gap_in_the_numbering_is_filled(driver):
    """The rule is "first free", not "one more than the highest"."""
    session = driver.session()
    place(session, "report.pdf")
    place(session, "report (2).pdf")
    assert resolve_download_name(
        session, DOWNLOADS, "report.pdf") == "report (1).pdf"


def test_a_name_without_an_extension_keeps_none(driver):
    session = driver.session()
    place(session, "notes")
    assert resolve_download_name(session, DOWNLOADS, "notes") == "notes (1)"


def test_only_the_last_dot_is_an_extension(driver):
    session = driver.session()
    place(session, "archive.tar.gz")
    assert resolve_download_name(
        session, DOWNLOADS, "archive.tar.gz") == "archive.tar (1).gz"


def test_a_leading_dot_is_part_of_the_name(driver):
    session = driver.session()
    place(session, ".profile")
    assert resolve_download_name(session, DOWNLOADS, ".profile") == ".profile (1)"


def test_a_collision_is_case_insensitive(driver):
    """A learner looking at the folder sees one file, so the server does too."""
    session = driver.session()
    place(session, "Report.PDF")
    assert resolve_download_name(
        session, DOWNLOADS, "report.pdf") == "report (1).pdf"

    place(session, "REPORT (1).pdf")
    assert resolve_download_name(
        session, DOWNLOADS, "report.pdf") == "report (2).pdf"


def test_the_same_name_in_another_folder_is_not_a_collision(driver):
    session = driver.session()
    place(session, "report.pdf", location="loc-shared")
    assert resolve_download_name(session, DOWNLOADS, "report.pdf") == "report.pdf"


def test_a_deleted_file_holds_no_name(driver):
    """It is not in the Files app, so the learner cannot see why it would."""
    session = driver.session()
    place(session, "report.pdf", deleted=True)
    assert resolve_download_name(session, DOWNLOADS, "report.pdf") == "report.pdf"


def test_resolving_a_name_changes_nothing(driver):
    """It answers a question about the world; it does not touch it."""
    session = driver.session()
    place(session, "report.pdf")
    before = session.capture_state()
    for _ in range(5):
        resolve_download_name(session, DOWNLOADS, "report.pdf")
    assert session.capture_state() == before


def test_the_same_world_always_resolves_the_same_name(tmp_path):
    """No randomness, no clock, no ambient state: two runs, one answer."""
    resolved = []
    for index in range(2):
        service, _ = build_service(sqlite_uri(tmp_path, "run-%d.db" % index))
        session = Driver.start(service, focus="mixed",
                               mode="simulation").session()
        place(session, "report.pdf")
        place(session, "report (1).pdf")
        resolved.append(resolve_download_name(session, DOWNLOADS, "report.pdf"))
    assert resolved[0] == resolved[1] == "report (2).pdf"


# ===========================================================================
# The mail attachment path
# ===========================================================================

def test_a_download_that_does_not_collide_keeps_its_name(driver):
    """The macro workbook has a name nothing else in Downloads has."""
    driver.deliver_until("m-rate-card")
    result = driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    entry = file_row(result.snapshot, "f-dl-m-rate-card-0")
    assert entry["name"] == "Calderwood_Rates_Q4.xlsm"


def test_a_colliding_attachment_is_kept_alongside_the_original(driver):
    mail_id, seeded_id, filename = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    before = names(driver.snapshot())
    assert filename in before

    result = driver.act("mail.download_attachment", mail_id, {"index": 0})

    # The original is untouched, and the download is next to it.
    assert file_row(result.snapshot, seeded_id)["name"] == filename
    downloaded = file_row(result.snapshot, "f-dl-%s-0" % mail_id)
    assert downloaded["name"] == "Invoice_CF-20411 (1).pdf"
    assert downloaded["location"] == DOWNLOADS
    assert len(names(result.snapshot)) == len(before) + 1


def test_no_two_files_in_a_folder_ever_share_a_name(driver):
    """The property the whole change exists to hold."""
    for mail_id, _, _ in (VENDOR_INVOICE, OPS_AGENDA):
        driver.deliver_until(mail_id)
        driver.act("mail.download_attachment", mail_id, {"index": 0})
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})

    folder = [name.lower() for name in names(driver.snapshot())]
    assert len(folder) == len(set(folder)), folder


def test_the_notification_names_the_file_that_was_actually_saved(driver):
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    result = driver.act("mail.download_attachment", mail_id, {"index": 0})
    latest = result.snapshot["notifications"][0]
    assert "Invoice_CF-20411 (1).pdf" in latest["body"]


def test_the_context_fact_records_the_resolved_name(driver):
    """Audit data and the Files app must not tell two different stories."""
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    driver.act("mail.download_attachment", mail_id, {"index": 0})
    session = driver.session()
    entry = session.ledger.get(file_fact("f-dl-%s-0" % mail_id))
    assert entry.value["name"] == "Invoice_CF-20411 (1).pdf"


def test_the_world_mutation_records_the_resolved_name(driver):
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    driver.act("mail.download_attachment", mail_id, {"index": 0})
    session = driver.session()
    written = [m for m in session.world.mutations()
               if m.key == "f-dl-%s-0" % mail_id]
    assert written
    assert written[-1].new_value["name"] == "Invoice_CF-20411 (1).pdf"


def test_downloading_the_same_attachment_twice_still_makes_one_file(driver):
    """A retry is not a second download, and must not mint a ``(1)``."""
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    driver.act("mail.download_attachment", mail_id, {"index": 0})
    before = names(driver.snapshot())
    for _ in range(3):
        driver.act("mail.download_attachment", mail_id, {"index": 0})
    assert names(driver.snapshot()) == before


def test_a_stale_submission_creates_nothing(driver):
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    stale = driver.revision - 1
    before = names(driver.snapshot())
    with pytest.raises(StaleRevisionConflict):
        driver.act("mail.download_attachment", mail_id, {"index": 0},
                   revision=stale)
    assert names(driver.snapshot()) == before


def test_a_rejected_download_leaves_no_partial_file(driver):
    """A bad attachment index is refused before anything is written."""
    from rewindsec.workstation.errors import UnknownTargetError

    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    before = driver.session().capture_state()
    with pytest.raises(UnknownTargetError):
        driver.act("mail.download_attachment", mail_id, {"index": 7})
    assert driver.session().capture_state() == before


# ===========================================================================
# The browser
# ===========================================================================

def test_the_browser_download_goes_through_the_same_door(driver):
    """Batch 3 added a browser download. It reuses the one resolver.

    Batch 2 asserted there was no such action, which was true and is no longer
    the point: the guarantee was never "the browser cannot download", it was
    "there is exactly one place a downloaded file enters the world, and it
    decides the name". That is the assertion now, and it is a stronger one,
    because there are two callers to keep honest instead of one.
    """
    from rewindsec.workstation.actions import ACTION_SPECS

    assert "browser.download" in ACTION_SPECS
    spec = ACTION_SPECS["browser.download"]
    # The client names a page and a resource id. There is no parameter through
    # which it could name a filename, a path or something to fetch.
    assert sorted(spec.params) == ["resource", "url"]
    assert not any(key in spec.params for key in ("name", "filename", "path"))

    source = io.open("rewindsec/workstation/service.py", encoding="utf-8").read()
    # Two callers -- mail and browser -- and one function they both go through.
    assert source.count("worldops.add_downloaded_file(") == 2
    resolver = io.open("rewindsec/workstation/worldops.py",
                       encoding="utf-8").read()
    assert resolver.count("def resolve_download_name(") == 1


def test_a_browser_download_and_a_mail_download_collide_identically(driver):
    """Same folder, same name, same resolver -- so the same numbered result.

    The maintenance page offers the same guide the service desk attaches.
    Downloading both must leave two files, the second numbered, exactly as two
    mail attachments of the same name would.
    """
    driver.deliver_until("m-it-attachment")
    driver.act("mail.download_attachment", "m-it-attachment", {"index": 0})
    driver.act("browser.download", params={
        "url": "intranet.northbridge.example/it/maintenance",
        "resource": "res-access-guide"})

    names = sorted(row["name"] for row in driver.snapshot()["files"]["files"]
                   if row["location"] == "loc-downloads"
                   and row["name"].startswith("Remote_Access_Guide"))
    assert names == ["Remote_Access_Guide (1).pdf", "Remote_Access_Guide.pdf"]


# ===========================================================================
# Persistence, and the host filesystem
# ===========================================================================

def test_the_resolved_name_survives_a_refresh(driver):
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    driver.act("mail.download_attachment", mail_id, {"index": 0})
    first = file_row(driver.snapshot(), "f-dl-%s-0" % mail_id)["name"]
    for _ in range(3):
        assert file_row(driver.snapshot(),
                        "f-dl-%s-0" % mail_id)["name"] == first


def test_the_resolved_name_survives_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "resume.db")
    service, _ = build_service(uri, ids=["ws-download"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)
    driver.act("mail.download_attachment", mail_id, {"index": 0})

    rebuilt, repository = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id, driver.learner_ref)
    entry = file_row(resumed.snapshot(), "f-dl-%s-0" % mail_id)
    assert entry["name"] == "Invoice_CF-20411 (1).pdf"
    # And re-resolving against the restored world would not renumber it.
    session = repository.load(driver.session_id)
    assert resolve_download_name(
        session, DOWNLOADS, "Invoice_CF-20411.pdf") == "Invoice_CF-20411 (2).pdf"


def test_downloading_writes_nothing_to_the_host_filesystem(tmp_path):
    """The folder is a component in the world. There is no folder."""
    uri = sqlite_uri(tmp_path, "hostfs.db")
    service, _ = build_service(uri)
    driver = Driver.start(service, focus="mixed", mode="simulation")
    mail_id, _, _ = VENDOR_INVOICE
    driver.deliver_until(mail_id)

    before = sorted(os.listdir(str(tmp_path)))
    cwd_before = sorted(os.listdir("."))
    driver.act("mail.download_attachment", mail_id, {"index": 0})
    # The database is the only file anything here may create.
    assert sorted(os.listdir(str(tmp_path))) == before
    assert sorted(os.listdir(".")) == cwd_before
    assert not os.path.exists("Invoice_CF-20411 (1).pdf")


def test_the_download_path_cannot_reach_a_filesystem_at_all(driver):
    """Static, so it holds for code paths a test never happens to walk."""
    forbidden = re.compile(
        r"\b(?:import\s+(?:os|io|shutil|pathlib|tempfile|glob)\b"
        r"|from\s+(?:os|io|shutil|pathlib|tempfile|glob)\s+import"
        r"|open\s*\()")
    for path in ("rewindsec/workstation/worldops.py",
                 "rewindsec/workstation/service.py"):
        source = io.open(path, encoding="utf-8").read()
        assert not forbidden.search(source), path
