import pytest
from opsec_guard.commands.audit import QUESTIONS, MAX_SCORE, _print_recommendations
from opsec_guard.utils.display import score_to_level


def test_questions_have_required_fields():
    required = {"key", "prompt", "options", "weights"}
    for q in QUESTIONS:
        assert required.issubset(q.keys()), f"Question '{q.get('key')}' missing fields"


def test_weights_match_options_count():
    for q in QUESTIONS:
        assert len(q["weights"]) == len(q["options"]), (
            f"Question '{q['key']}': weights count != options count"
        )


def test_max_score_is_positive():
    assert MAX_SCORE > 0


def test_all_weights_non_negative():
    for q in QUESTIONS:
        for w in q["weights"]:
            assert w >= 0, f"Negative weight in question '{q['key']}'"


def test_score_to_level_critical():
    assert score_to_level(80) == "critical"


def test_score_to_level_high():
    assert score_to_level(60) == "high"


def test_score_to_level_medium():
    assert score_to_level(35) == "medium"


def test_score_to_level_low():
    assert score_to_level(10) == "low"


def test_score_to_level_boundary_critical():
    assert score_to_level(75) == "critical"


def test_score_to_level_boundary_high():
    assert score_to_level(50) == "high"


def test_score_to_level_boundary_medium():
    assert score_to_level(25) == "medium"


def test_score_to_level_zero():
    assert score_to_level(0) == "low"


def test_unique_question_keys():
    keys = [q["key"] for q in QUESTIONS]
    assert len(keys) == len(set(keys)), "Duplicate question keys found"


def test_sensitive_role_question_exists():
    keys = [q["key"] for q in QUESTIONS]
    assert "sensitive_role" in keys


def test_maid_reset_frequency_question_exists():
    keys = [q["key"] for q in QUESTIONS]
    assert "maid_reset_frequency" in keys


def test_recommendations_run_without_error(capsys):
    # Simulate a high-risk answer set
    answers = {
        "maid_reset_frequency":   {"answer_index": 0, "answer_label": "Never", "score_contribution": 20},
        "ad_tracking_opt_out":    {"answer_index": 0, "answer_label": "No", "score_contribution": 15},
        "weather_apps":           {"answer_index": 0, "answer_label": "Yes, always-on", "score_contribution": 15},
        "background_location":    {"answer_index": 0, "answer_label": "5+", "score_contribution": 15},
        "free_vpn":               {"answer_index": 0, "answer_label": "Yes", "score_contribution": 12},
        "social_apps":            {"answer_index": 0, "answer_label": "Yes, location on", "score_contribution": 10},
        "wifi_scanning":          {"answer_index": 0, "answer_label": "No", "score_contribution": 5},
        "work_personal_same_device": {"answer_index": 0, "answer_label": "Yes", "score_contribution": 8},
    }
    # Should not raise
    _print_recommendations(answers, sensitive=True)
