"""Tests for OpenRouter LLM diagnostics."""

from software_butcher.core.llm import diagnose_openrouter, format_diagnosis, openrouter_config


def test_openrouter_config_defaults(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    cfg = openrouter_config()
    assert cfg["api_key_set"] is False
    assert cfg["model"] == "gpt-oss-120b"


def test_diagnose_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    report = diagnose_openrouter(probe_chat=False)
    assert report["ok"] is False
    assert "OPENROUTER_API_KEY" in report["summary"]


def test_format_diagnosis_includes_checks():
    text = format_diagnosis(
        {
            "summary": "test",
            "config": {"base_url": "https://openrouter.ai/api/v1", "model": "m", "timeout_s": "30"},
            "checks": [{"name": "dns", "ok": False, "detail": "failed"}],
        }
    )
    assert "OpenRouter LLM diagnostics" in text
    assert "[FAIL] dns" in text
