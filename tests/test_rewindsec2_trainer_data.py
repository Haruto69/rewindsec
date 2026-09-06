"""Batch 5 trainer projections and analytics: real, or honestly unavailable.

Two properties, and the second is the one that matters most for a research
project: every figure the console shows is derived from persisted RewindSec
2.0 data, and a figure that *cannot* be derived is shown as unavailable rather
than estimated. A fabricated percentage on a trainer screen is worse than an
empty card, because nobody can tell the two apart by looking.

The suite also holds the structural rule that the production trainer surface
no longer reads ``rewindsec/prototype/trainer_fixtures.py``.
"""

import ast
import io
import pathlib

import pytest

from rewindsec.management import analytics
from rewindsec.management import projection as trainer_view
from rewindsec.management.records import ASSESSMENT_STATUSES

from tests.management_helpers import LEARNER, build, sqlite_uri
from tests.workstation_helpers import Driver

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

SCORED_MAILS = ("m-payroll-restructure", "m-rate-card", "m-invoice-amend")


def populated(tmp_path, run_a_session=True):
    """A roster, a group, an assessment, and optionally one played attempt."""
    management, workstation, sessions = build(sqlite_uri(tmp_path))
    student = management.ensure_student_for_learner_ref(LEARNER)
    group = management.create_group("Operations A")
    management.add_member(group.group_id, student.student_id)
    assessment = management.create_assessment("Q3 judgement", "mixed", 2,
                                              status="open", max_attempts=2)
    management.assign(assessment.assessment_id, "group", group.group_id)
    attempt = None
    if run_a_session:
        attempt, _ = management.start_attempt(LEARNER,
                                              assessment.assessment_id)
        driver = Driver(workstation, attempt.session_id, LEARNER)
        for mail_id in SCORED_MAILS[:2]:
            driver.deliver_until(mail_id)
        driver.act("mail.open", target=SCORED_MAILS[0])
        # Both, because the assessment requires two. Resolving one and
        # ending would now be an attempt that terminated early rather than a
        # completed one -- which is the corrected rule, not an accident.
        driver.act("mail.report", target=SCORED_MAILS[0])
        driver.act("mail.report", target=SCORED_MAILS[1])
        workstation.end_session(attempt.session_id, LEARNER)
        management.sync_attempt(attempt)
    return management, workstation, sessions, student, group, assessment, attempt


# ===========================================================================
# The dashboard reads persisted data
# ===========================================================================

def test_the_dashboard_counts_come_from_stored_rows(tmp_path):
    management, _ws, _sessions, _student, _group, _assessment, _attempt = \
        populated(tmp_path)
    view = trainer_view.dashboard(management)

    cards = {card["id"]: card for card in view["cards"]}
    assert cards["students"]["value"] == "1"
    assert cards["sessions"]["value"] == "1"
    assert cards["assessments_open"]["value"] == "1"
    assert cards["attempts_outstanding"]["value"] == "0"
    assert view["session_total"] == 1


def test_an_empty_deployment_shows_zeroes_and_no_invented_history(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    view = trainer_view.dashboard(management)

    assert view["sessions"] == []
    assert view["outstanding"] == []
    assert {card["value"] for card in view["cards"]} == {"0"}
    for metric in view["metrics"]:
        assert metric["available"] is False
        assert metric["value"] is None
        assert metric["display"] == "—"
        assert metric["unavailable_reason"]


def test_a_session_row_carries_the_stored_facts_not_a_guess(tmp_path):
    management, _ws, sessions, student, _group, assessment, attempt = \
        populated(tmp_path)
    view = trainer_view.dashboard(management)
    row = view["sessions"][0]

    stored = sessions.load(attempt.session_id)
    assert row["session_id"] == attempt.session_id
    assert row["student_id"] == student.student_id
    assert row["focus"] == stored.focus.value
    assert row["mode"] == stored.mode.value == "assessment"
    assert row["status"] == stored.status.value == "completed"
    assert row["assessment_name"] == assessment.name
    assert row["attempt_number"] == 1
    assert row["started"], "an administrative timestamp is recorded"


def test_the_derived_profile_is_derived_and_versioned(tmp_path):
    """The trainer may see the scaffolding profile and cannot set it."""
    assert trainer_view.profile_label("practice").startswith("High scaffolding")
    assert trainer_view.profile_label("simulation").startswith(
        "Standard scaffolding")
    assert trainer_view.profile_label("assessment").startswith(
        "Minimal scaffolding")
    for mode in ("practice", "simulation", "assessment"):
        assert "training-engine/v1" in trainer_view.profile_label(mode)
    assert trainer_view.profile_label("not-a-mode") is None


def test_outstanding_attempts_report_scored_interaction_progress(tmp_path):
    management, _ws, _sessions, _student, _group, assessment, _done = \
        populated(tmp_path)
    running, created = management.start_attempt(LEARNER,
                                                assessment.assessment_id)
    assert created is True

    view = trainer_view.dashboard(management)
    assert len(view["outstanding"]) == 1
    entry = view["outstanding"][0]
    assert entry["attempt_id"] == running.attempt_id
    assert entry["attempt_number"] == 2
    assert entry["progress"]["required"] == 2
    assert entry["progress"]["completed"] == 0


# ===========================================================================
# Student, group and assessment screens
# ===========================================================================

def test_student_detail_shows_real_provenance_and_history(tmp_path):
    management, _ws, _sessions, student, group, assessment, attempt = \
        populated(tmp_path)
    detail = trainer_view.student_detail(management, student.student_id)

    assert detail["student"].student_id == student.student_id
    assert [g.group_id for g in detail["groups"]] == [group.group_id]
    assert len(detail["assignments"]) == 1
    assert detail["assignments"][0]["source"] == "group"
    assert detail["assignments"][0]["assessment_name"] == assessment.name
    assert len(detail["sessions"]) == 1
    assert len(detail["attempts"]) == 1
    assert detail["attempts"][0]["attempt_id"] == attempt.attempt_id
    assert detail["attempts"][0]["rubric_version"] == "rewindsec-rubric/v1"


def test_student_detail_is_none_for_an_unknown_student(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    assert trainer_view.student_detail(management, "stu-nobody") is None
    assert trainer_view.group_detail(management, "grp-nothing") is None


def test_group_detail_lists_members_and_what_the_group_carries(tmp_path):
    management, _ws, _sessions, student, group, assessment, _attempt = \
        populated(tmp_path)
    detail = trainer_view.group_detail(management, group.group_id)

    assert [row["student"].student_id for row in detail["members"]] \
        == [student.student_id]
    assert [row["assessment"].assessment_id for row in detail["assessments"]] \
        == [assessment.assessment_id]
    assert student.student_id not in {s.student_id
                                      for s in detail["candidates"]}


def test_group_overlap_is_computed_from_real_membership(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe")
    ops = management.create_group("Operations A")
    finance = management.create_group("Finance payments")
    management.add_member(ops.group_id, alice.student_id)
    management.add_member(finance.group_id, alice.student_id)

    detail = trainer_view.group_detail(management, ops.group_id)
    assert [entry["group"].group_id for entry in detail["overlaps"]] \
        == [finance.group_id]
    assert detail["overlaps"][0]["shared"] == ["Alice Doe"]


def test_assessment_overview_counts_real_attempts(tmp_path):
    management, _ws, _sessions, _student, group, assessment, _attempt = \
        populated(tmp_path)
    overview = trainer_view.assessments_overview(management)
    row = overview["rows"][0]

    assert row["assessment"].assessment_id == assessment.assessment_id
    assert [entry["group"].group_id for entry in row["groups"]] \
        == [group.group_id]
    assert row["students"] == []
    assert row["attempts_total"] == 1
    assert row["attempts_completed"] == 1
    assert row["attempts_active"] == 0


def test_every_assessment_status_renders_a_known_chip(tmp_path):
    """The template branches on exactly the statuses the record allows."""
    source = io.open(REPO_ROOT / "templates" / "prototype"
                     / "trainer_assessments.html", encoding="utf-8").read()
    for status in ASSESSMENT_STATUSES:
        assert "'%s'" % status in source, status


# ===========================================================================
# Analytics: real denominators, honest empty states
# ===========================================================================

def test_every_metric_states_its_own_denominator_and_version(tmp_path):
    management, _ws, _sessions, _student, _group, _assessment, _attempt = \
        populated(tmp_path)
    metrics = trainer_view.dashboard(management)["metrics"]

    assert {metric["id"] for metric in metrics} \
        == {row[0] for row in analytics.METRIC_DEFINITIONS}
    for metric in metrics:
        assert metric["metric_version"] == analytics.METRIC_SET_VERSION
        assert metric["denominator_label"], metric["id"]
        assert metric["definition"], metric["id"]
        assert metric["interpretation"] == analytics.INTERPRETATION_LIMIT
        assert isinstance(metric["numerator"], int)
        assert isinstance(metric["denominator"], int)
        assert metric["numerator"] <= metric["denominator"] \
            or metric["denominator"] == 0, metric["id"]


def test_a_metric_with_no_opportunities_is_unavailable_not_zero(tmp_path):
    """"Nobody ever had the chance" and "everybody failed" are different."""
    management, _ws, _sessions, _student, _group, _assessment, _attempt = \
        populated(tmp_path)
    metrics = {metric["id"]: metric
               for metric in trainer_view.dashboard(management)["metrics"]}

    # No incident opened in this run, so containment has no denominator.
    containment = metrics["incident_containment"]
    assert containment["denominator"] == 0
    assert containment["available"] is False
    assert containment["value"] is None
    assert containment["display"] == "—"


def test_a_metric_with_real_opportunities_reports_a_real_fraction(tmp_path):
    management, _ws, _sessions, _student, _group, _assessment, _attempt = \
        populated(tmp_path)
    metrics = {metric["id"]: metric
               for metric in trainer_view.dashboard(management)["metrics"]}

    evidence = metrics["relevant_evidence_use"]
    assert evidence["denominator"] >= 1, "one decision was recorded"
    assert evidence["available"] is True
    assert 0 <= evidence["value"] <= 100
    assert evidence["display"].endswith("%")


def test_metric_values_use_integer_rounding_only():
    """No floating point anywhere in a displayed figure."""
    metric = analytics.Metric(
        metric_id="x", label="X", definition="d", denominator_label="n",
        numerator=1, denominator=3)
    assert metric.value == 33
    assert isinstance(metric.value, int)
    metric = analytics.Metric(
        metric_id="x", label="X", definition="d", denominator_label="n",
        numerator=1, denominator=2)
    assert metric.value == 50


def test_aggregating_nothing_produces_no_number_at_all():
    metrics = analytics.aggregate([])
    assert metrics, "the metric set still exists"
    for metric in metrics:
        assert metric.available is False
        assert metric.value is None
        assert metric.unavailable_reason == "No session analysed yet."


def test_session_facts_are_pure_and_repeatable(tmp_path):
    management, _ws, sessions, _student, _group, _assessment, attempt = \
        populated(tmp_path)
    session = sessions.load(attempt.session_id)
    first = analytics.session_facts(session)
    second = analytics.session_facts(session)
    assert first == second
    assert first["opportunities_presented"] >= 2
    # Two, because ``populated`` now resolves the assessment's full
    # required-interaction count rather than stopping one short.
    assert first["opportunities_resolved"] == 2
    assert first["scored"] is True


def test_analytics_make_no_claim_about_human_learning():
    text = analytics.INTERPRETATION_LIMIT.lower()
    assert "not a measure of competence" in text
    for claim in ("improved", "proves", "demonstrates that the learner"):
        assert claim not in text


# ===========================================================================
# The production trainer surface no longer reads fixtures
# ===========================================================================

TRAINER_PRODUCTION_MODULES = (
    "rewindsec/prototype/trainer_api.py",
    "rewindsec/management/projection.py",
    "rewindsec/management/service.py",
    "rewindsec/management/analytics.py",
)


@pytest.mark.parametrize("relative", TRAINER_PRODUCTION_MODULES)
def test_no_production_trainer_module_imports_the_fixtures(relative):
    tree = ast.parse(io.open(REPO_ROOT / relative, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "trainer_fixtures" not in node.module, relative
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert "trainer_fixtures" not in alias.name, relative


def test_the_trainer_routes_render_from_the_management_projection():
    """The routes hand the templates a projection, not a fixture snapshot."""
    source = io.open(REPO_ROOT / "rewindsec" / "prototype" / "routes.py",
                     encoding="utf-8").read()
    tree = ast.parse(source)
    trainer_functions = [node for node in ast.walk(tree)
                         if isinstance(node, ast.FunctionDef)
                         and node.name.startswith("trainer_")
                         and node.name != "trainer_page"]
    assert len(trainer_functions) == 6, [f.name for f in trainer_functions]
    for function in trainer_functions:
        body = ast.dump(function)
        assert "trainer_view" in body, function.name
        assert "fixtures" not in body, function.name


@pytest.mark.parametrize("name", (
    "trainer_dashboard.html", "trainer_students.html", "trainer_student.html",
    "trainer_groups.html", "trainer_group.html", "trainer_assessments.html"))
def test_no_trainer_template_reads_the_fixture_snapshot(name):
    """``snapshot`` was the fixture document; the templates read ``view``."""
    source = io.open(REPO_ROOT / "templates" / "prototype" / name,
                     encoding="utf-8").read()
    assert "snapshot." not in source, name
    assert "demonstration data" not in source.lower(), name


def test_no_trainer_template_presents_a_hardcoded_measurement():
    """No percentage is written into a template as a literal figure.

    Everything inside ``{{ }}``, ``{% %}`` and ``{# #}`` is stripped first: an
    expression is rendered from the projection, and a ``{% if score < 55 %}``
    threshold decides which colour a real number is drawn in rather than being
    a number itself. What is left is the prose a reader sees, and there must
    be no measurement in it.
    """
    import re
    for path in (REPO_ROOT / "templates" / "prototype").glob("trainer_*.html"):
        source = path.read_text(encoding="utf-8")
        prose = re.sub(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", "", source,
                       flags=re.S)
        assert not re.search(r"\d{1,3}\s?%", prose), path.name


# ===========================================================================
# The corrected over-suspicion metrics (Batch 5 correction)
# ===========================================================================
#
# Version 1 published one figure labelled as a false-positive report rate
# whose numerator was "reported something genuine **or** disconnected with
# nothing to contain", over a denominator of every session analysed. Those
# are two different operational behaviours and no reading of the resulting
# percentage was true. They are now two metrics with two denominators.

def _definition(metric_id):
    return {row[0]: row for row in analytics.METRIC_DEFINITIONS}[metric_id]


def test_reporting_and_disconnecting_are_two_metrics_now():
    ids = [row[0] for row in analytics.METRIC_DEFINITIONS]
    assert "false_positive_reports" in ids
    assert "unnecessary_isolation" in ids


def test_the_report_metric_counts_reports_and_nothing_else():
    definition = _definition("false_positive_reports")
    label, meaning, denominator = definition[1], definition[2], definition[3]
    assert "report" in label.lower()
    assert "disconnect" not in meaning.lower()
    assert "isolat" not in meaning.lower()
    # Its denominator is sessions that could have contributed to it.
    assert "genuine" in denominator.lower()


def test_the_disconnection_metric_is_named_for_what_it_counts():
    metric_id, label, meaning, denominator, _unit = _definition(
        "unnecessary_isolation")
    assert "disconnect" in label.lower() or "disconnect" in meaning.lower()
    # It counts a containment action. The definition may *mention* reporting
    # to say it is not that -- what it must not do is count it.
    assert "counted separately from reporting" in meaning
    assert "sessions analysed" in denominator.lower()


def test_the_two_metrics_do_not_share_a_denominator(tmp_path):
    """A session that delivered only hostile mail offered nothing to
    over-report, and diluting the rate with it would be inventing a
    denominator."""
    facts = {
        "evidence_decisions": 0, "evidence_decisions_informed": 0,
        "verify_opportunities": 0, "verify_resolved": 0,
        "credential_opportunity": False, "credential_submitted": False,
        "unsafe_open_opportunities": 0, "unsafe_opens": 0,
        "mfa_hostile_prompts": 0, "mfa_hostile_denied": 0,
        "opportunities_presented": 0, "opportunities_resolved": 0,
        "incident_opened": False, "incident_contained": False,
        "recovery_opportunities": 0, "recovery_used": 0,
        "scored": True, "overall": 50,
        "benign_mail_delivered": False,
        "reported_legitimate": False,
        "isolated_without_incident": True,
    }
    metrics = {m.metric_id: m for m in analytics.aggregate([facts])}

    assert metrics["unnecessary_isolation"].denominator == 1
    assert metrics["unnecessary_isolation"].numerator == 1
    assert metrics["unnecessary_isolation"].value == 100
    # No benign mail was delivered, so there is nothing to divide by.
    assert metrics["false_positive_reports"].denominator == 0
    assert metrics["false_positive_reports"].available is False
    assert metrics["false_positive_reports"].value is None


def test_a_zero_denominator_stays_unavailable_and_is_never_zero():
    metrics = {m.metric_id: m for m in analytics.aggregate([])}
    for metric_id in ("false_positive_reports", "unnecessary_isolation"):
        metric = metrics[metric_id]
        assert metric.available is False
        assert metric.value is None
        assert metric.to_state()["display"] == "—"
        assert metric.unavailable_reason


def test_a_reported_genuine_message_moves_only_the_report_metric(tmp_path):
    management, workstation, sessions = build(sqlite_uri(tmp_path))
    session_id = workstation.start_session(LEARNER, "mixed", "simulation")
    driver = Driver(workstation, session_id, LEARNER)
    # An authored benign message: reporting it is over-suspicion, not
    # containment.
    driver.deliver_until("m-ops-agenda")
    driver.act("mail.report", target="m-ops-agenda")
    workstation.end_session(session_id, LEARNER)

    facts = analytics.session_facts(sessions.load(session_id))
    assert facts["benign_mail_delivered"] is True
    assert facts["reported_legitimate"] is True
    assert facts["isolated_without_incident"] is False

    metrics = {m.metric_id: m for m in analytics.aggregate([facts])}
    assert metrics["false_positive_reports"].numerator == 1
    assert metrics["false_positive_reports"].denominator == 1
    assert metrics["unnecessary_isolation"].numerator == 0


def test_the_metric_set_version_moved_with_the_definitions():
    """A figure recorded under the old blended definition must never be
    silently compared with one recorded under these."""
    assert analytics.METRIC_SET_VERSION == "rewindsec-trainer-metrics/v2"
