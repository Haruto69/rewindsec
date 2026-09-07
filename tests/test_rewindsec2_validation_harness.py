"""The v2 validation harness reports real samples and explicit provenance."""

from evaluation.rewindsec2.run_validation import run


def test_harness_schema_metadata_and_sample_counts():
    result = run(samples=2, concurrent_sessions=2)
    assert result["schema_version"] == "rewindsec2-validation-result/v1"
    assert result["harness_version"] == "rewindsec2-validation-harness/v1"
    assert result["repository"]["starting_base_commit"].startswith("e0ded689")
    assert result["parameters"]["performance_samples"] == 2
    assert result["performance"]["latency"]["learner_action"]["samples"] == 2
    assert result["validations"]["repeatability"]["case_count"] == 9
    assert result["validations"]["resume"]["case_count"] == 9
    assert result["validations"]["docker_lifecycle_independence"][
        "canonical_session_unchanged"] is True
    assert result["validations"]["security_misuse"]["refused"] == 6
    assert isinstance(result["skips"], list)


def test_harness_never_labels_dirty_run_as_final_paper_evidence():
    result = run(samples=1, concurrent_sessions=1)
    if result["repository"]["working_tree_dirty"]:
        assert result["repository"]["classification"] == "engineering_precommit"
    assert all("human-effect" in limitation or "Engineering/pre-commit" in limitation
               or "penetration" in limitation
               for limitation in result["limitations"])
