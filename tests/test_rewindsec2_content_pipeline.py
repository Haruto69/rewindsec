"""RewindSec 2.0 Batch 4: the safe synthetic content pipeline.

Covers the full chain -- source/provenance -> sanitize -> normalize ->
archetype -> generate -> bind -> runtime catalogue -- and the adversarial
cases Architecture Spec v1.1 S74-S76 ask for: the sanitizer fails closed on
every unsafe shape, every generatable source has reviewed/sanitized
provenance, unreviewed material cannot enter generation, and generation is
deterministic and does not perturb anything else.
"""

import pytest

from rewindsec.content import bind, provenance
from rewindsec.content.archetypes import DOCUMENT_ARCHETYPES, MAIL_ARCHETYPES
from rewindsec.content.catalog import DOCUMENT_BY_ID, all_documents
from rewindsec.content.generate import GenerationError, choose_variant, derive_content_id
from rewindsec.content.normalize import (NormalizationError, normalize_document_feature,
                                         normalize_mail_feature)
from rewindsec.content.provenance import ProvenanceRecord
from rewindsec.content.sanitize import SanitizationError, sanitize_text
from rewindsec.content.schema import DocumentSchemaError, SyntheticDocument, paragraph
from rewindsec.workstation.content import documents as ws_documents
from rewindsec.workstation.content import world as workplace

# ---------------------------------------------------------------------------
# Sanitizer: fail closed on every unsafe shape
# ---------------------------------------------------------------------------

UNSAFE_STRINGS = [
    "Visit https://real-attacker-domain.example.com now",
    "contact me at real.person@gmail.com",
    "call +1 (555) 123-4567 today",
    "<script>alert(1)</script>",
    "click here: javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "run this: eval(payload)",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "api_key: sk-abcdefghijklmnopqrstuvwx",
    "password=hunter2hunter2hunter2",
    "#!/bin/sh\nrm -rf /",
]


@pytest.mark.parametrize("text", UNSAFE_STRINGS)
def test_sanitizer_rejects_every_unsafe_shape(text):
    with pytest.raises(SanitizationError):
        sanitize_text(text)


def test_sanitizer_accepts_ordinary_synthetic_workplace_text():
    sanitize_text("Invoice CF-20411 for the August cleaning and grounds "
                  "contract is attached.")
    sanitize_text("Sender: ines.duarte@calderwood.example")  # .example is reserved


def test_sanitizer_rejects_control_characters():
    with pytest.raises(SanitizationError):
        sanitize_text("hello\x00world")


def test_sanitizer_rejects_oversize_text():
    with pytest.raises(SanitizationError):
        sanitize_text("x" * 5000, max_length=100)


def test_document_schema_uses_the_sanitizer_and_fails_closed():
    with pytest.raises(DocumentSchemaError):
        paragraph("<script>alert(1)</script>")


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def test_every_generatable_source_is_reviewed_and_sanitized():
    for record in provenance.all_sources():
        assert record.review_status == provenance.REVIEW_REVIEWED
        assert record.sanitization_status == provenance.SANITIZED
        assert record.may_generate


def test_unreviewed_source_cannot_generate():
    unreviewed = ProvenanceRecord(
        source_id="src-test-unreviewed", title="test", source_type="test",
        version="1", allowed_use="generation", limitations=(),
        review_status=provenance.REVIEW_UNREVIEWED)
    assert unreviewed.may_generate is False


def test_unsanitized_source_cannot_generate():
    unsanitized = ProvenanceRecord(
        source_id="src-test-unsanitized", title="test", source_type="test",
        version="1", allowed_use="generation", limitations=(),
        sanitization_status=provenance.UNSANITIZED)
    assert unsanitized.may_generate is False


def test_normalization_refuses_an_unknown_provenance_id():
    with pytest.raises(NormalizationError):
        normalize_mail_feature("src-does-not-exist", communication_purpose="x")


def test_normalization_refuses_an_unsupported_field():
    with pytest.raises(NormalizationError):
        normalize_document_feature(
            "src-document-archetypes-v1", document_kind="memo",
            not_a_real_field="x")


def test_normalization_runs_every_field_through_the_sanitizer():
    with pytest.raises(NormalizationError):
        normalize_mail_feature(
            "src-mail-archetypes-v1",
            communication_purpose="<script>alert(1)</script>")


def test_no_external_dataset_is_used():
    """Documents this explicitly: every provenance record's origin is
    internally authored synthetic material, never a public corpus."""
    for record in provenance.all_sources():
        assert record.origin == "internally_authored_synthetic"


# ---------------------------------------------------------------------------
# Archetypes: templates, not copies of anything real
# ---------------------------------------------------------------------------

def test_every_document_archetype_traces_to_reviewed_provenance():
    for features in DOCUMENT_ARCHETYPES.values():
        assert provenance.get(features.provenance_id).may_generate


def test_every_mail_archetype_traces_to_reviewed_provenance():
    for features in MAIL_ARCHETYPES.values():
        assert provenance.get(features.provenance_id).may_generate


# ---------------------------------------------------------------------------
# Deterministic generation
# ---------------------------------------------------------------------------

def test_content_id_is_stable_across_calls():
    first = derive_content_id("session-a", "arche-x", 0)
    second = derive_content_id("session-a", "arche-x", 0)
    assert first == second


def test_content_id_differs_by_session_archetype_or_occurrence():
    base = derive_content_id("session-a", "arche-x", 0)
    assert derive_content_id("session-b", "arche-x", 0) != base
    assert derive_content_id("session-a", "arche-y", 0) != base
    assert derive_content_id("session-a", "arche-x", 1) != base


def test_content_id_is_not_derived_from_hash():
    """``hash()`` is salted per Python process (``PYTHONHASHSEED``); this
    must not be, so it is asserted directly against a fixed, independently
    computed digest rather than merely "the same in this process"."""
    import hashlib
    expected = hashlib.sha256(
        "rewindsec2/content-generation-id/v1|s|a|0|1".encode("utf-8")
    ).hexdigest()[:32]
    assert derive_content_id("s", "a", 0) == expected


def test_generation_rejects_a_negative_occurrence():
    with pytest.raises(GenerationError):
        derive_content_id("s", "a", -1)


def test_choose_variant_is_deterministic_from_the_stream():
    from rewindsec.core.rng import SeededRandom, STREAM_CONTENT_VARIATION

    rng_a = SeededRandom(4242)
    rng_b = SeededRandom(4242)
    variants = ["one", "two", "three", "four"]
    chosen_a = choose_variant(rng_a.stream(STREAM_CONTENT_VARIATION), variants)
    chosen_b = choose_variant(rng_b.stream(STREAM_CONTENT_VARIATION), variants)
    assert chosen_a == chosen_b


def test_extra_content_variation_draws_do_not_perturb_other_streams():
    """Architecture Spec v1.1 S43: an extra draw on ``content_variation`` must
    never move a threat-selection or timing draw. Streams are derived
    independently by name, so this proves the property directly rather than
    trusting the description."""
    from rewindsec.core.rng import SeededRandom, STREAM_CONTENT_VARIATION, STREAM_TIMING

    rng = SeededRandom(777)
    timing_before = rng.stream(STREAM_TIMING).randint(1, 1000000)

    rng2 = SeededRandom(777)
    # Consume several content-variation draws first.
    variation_stream = rng2.stream(STREAM_CONTENT_VARIATION)
    for _ in range(5):
        choose_variant(variation_stream, ["a", "b", "c"])
    timing_after = rng2.stream(STREAM_TIMING).randint(1, 1000000)

    assert timing_before == timing_after


def test_choose_variant_refuses_an_empty_pool():
    from rewindsec.core.rng import SeededRandom, STREAM_CONTENT_VARIATION

    rng = SeededRandom(1)
    with pytest.raises(GenerationError):
        choose_variant(rng.stream(STREAM_CONTENT_VARIATION), [])


# ---------------------------------------------------------------------------
# Fictional organization binding
# ---------------------------------------------------------------------------

def test_binding_reads_the_one_shared_fictional_organization():
    org = bind.organization()
    assert org["name"] == workplace.ORGANIZATION["name"]


def test_binding_finds_the_known_vendor_and_finance_approver():
    assert bind.vendor() is not None
    assert bind.employee_by_role("finance") is not None


def test_bind_fields_raises_on_an_unresolved_placeholder():
    with pytest.raises(KeyError):
        bind.bind_fields("Hello {name}, from {stray}", name="Aarti")


# ---------------------------------------------------------------------------
# The runtime catalogue: no raw source text reaches it directly
# ---------------------------------------------------------------------------

def test_the_catalog_has_more_than_a_couple_of_documents():
    assert len(DOCUMENT_BY_ID) >= 5


def test_every_catalog_document_traces_to_provenance():
    for document in all_documents():
        assert document.provenance_id in provenance.SOURCES
        assert provenance.get(document.provenance_id).may_generate


def test_catalog_document_ids_are_stable_across_reimport():
    import importlib

    import rewindsec.content.catalog as catalog_module
    ids_before = sorted(DOCUMENT_BY_ID)
    reloaded = importlib.reload(catalog_module)
    assert sorted(reloaded.DOCUMENT_BY_ID) == ids_before
    importlib.reload(catalog_module)  # restore module-level identity for other tests


def test_the_invoice_document_carries_the_account_of_record():
    """The BEC-relevant fact the scoring/evidence use story depends on."""
    invoice = ws_documents.document_for_file("f-invoice")
    assert invoice is not None
    text = " ".join(
        str(cell) for block in invoice.blocks
        for pair in block.get("pairs", []) for cell in pair)
    assert "4417" in text


def test_the_ransomware_lure_attachment_has_no_bound_document():
    """The macro workbook is the ransomware trigger point; the viewer must
    never render a fabricated document body standing in for it."""
    assert ws_documents.document_for_file("f-dl-m-rate-card-0") is None


def test_a_document_projection_is_pure_json_safe_data():
    import json

    for document in all_documents():
        json.dumps(document.to_projection())  # must not raise


def test_document_blocks_are_restricted_to_the_closed_vocabulary():
    from rewindsec.content.schema import BLOCK_TYPES

    for document in all_documents():
        for block in document.blocks:
            assert block["type"] in BLOCK_TYPES
