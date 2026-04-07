import json
import pytest
from pathlib import Path
from opsec_guard.commands.report import _md_report, _generate_findings, _generate_recommendations


SAMPLE_AUDIT = {
    "timestamp": "2026-04-07T12:00:00",
    "score": 78,
    "level": "critical",
    "sensitive_role": True,
    "raw_score": 108,
    "max_score": 130,
    "answers": {
        "platform":                  {"answer_index": 0, "answer_label": "Android", "score_contribution": 0},
        "maid_reset_frequency":      {"answer_index": 0, "answer_label": "Never", "score_contribution": 20},
        "ad_tracking_opt_out":       {"answer_index": 0, "answer_label": "No", "score_contribution": 15},
        "weather_apps":              {"answer_index": 0, "answer_label": "Yes, always-on", "score_contribution": 15},
        "fitness_apps":              {"answer_index": 1, "answer_label": "During workouts", "score_contribution": 4},
        "mobile_games":              {"answer_index": 0, "answer_label": "Yes, multiple", "score_contribution": 8},
        "social_apps":               {"answer_index": 0, "answer_label": "Yes, location on", "score_contribution": 10},
        "free_vpn":                  {"answer_index": 0, "answer_label": "Yes", "score_contribution": 12},
        "background_location":       {"answer_index": 0, "answer_label": "5+", "score_contribution": 15},
        "sideloading":               {"answer_index": 2, "answer_label": "Never", "score_contribution": 0},
        "sensitive_role":            {"answer_index": 0, "answer_label": "Yes", "score_contribution": 0},
        "work_personal_same_device": {"answer_index": 0, "answer_label": "Yes", "score_contribution": 8},
        "wifi_scanning":             {"answer_index": 0, "answer_label": "No", "score_contribution": 5},
    },
}


def test_md_report_contains_score():
    md = _md_report(SAMPLE_AUDIT)
    assert "78/100" in md


def test_md_report_contains_risk_level():
    md = _md_report(SAMPLE_AUDIT)
    assert "CRITICAL" in md


def test_md_report_contains_maid_section():
    md = _md_report(SAMPLE_AUDIT)
    assert "What is a MAID?" in md


def test_md_report_contains_reset_instructions():
    md = _md_report(SAMPLE_AUDIT)
    assert "Reset advertising ID" in md or "Reset Advertising Identifier" in md


def test_md_report_contains_broker_table():
    md = _md_report(SAMPLE_AUDIT)
    assert "Babel Street" in md
    assert "Venntel" in md


def test_generate_findings_critical_score():
    findings = _generate_findings(SAMPLE_AUDIT["answers"], sensitive=True)
    assert len(findings) > 0


def test_generate_findings_sensitive_role_flagged():
    findings = _generate_findings(SAMPLE_AUDIT["answers"], sensitive=True)
    assert any("sensitive" in f.lower() or "OPSEC" in f for f in findings)


def test_generate_findings_maid_never_reset():
    findings = _generate_findings(SAMPLE_AUDIT["answers"], sensitive=False)
    assert any("reset" in f.lower() or "MAID" in f for f in findings)


def test_generate_recommendations_returns_list():
    recs = _generate_recommendations(SAMPLE_AUDIT["answers"], sensitive=True)
    assert isinstance(recs, list)
    assert len(recs) > 0


def test_generate_recommendations_each_is_tuple():
    recs = _generate_recommendations(SAMPLE_AUDIT["answers"], sensitive=True)
    for r in recs:
        assert isinstance(r, tuple)
        assert len(r) == 2


def test_generate_recommendations_opt_out_included():
    recs = _generate_recommendations(SAMPLE_AUDIT["answers"], sensitive=False)
    titles = [r[0].lower() for r in recs]
    assert any("opt-out" in t or "opt out" in t or "tracking" in t for t in titles)
