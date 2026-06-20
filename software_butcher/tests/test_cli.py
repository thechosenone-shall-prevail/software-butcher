"""CLI smoke tests."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "software_butcher", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "software_butcher" in result.stdout


def test_doctor_runs():
    result = subprocess.run(
        [sys.executable, "-m", "software_butcher", "doctor"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "hexstrike" in result.stdout.lower() or "MISS" in result.stdout or "OK" in result.stdout


def test_llm_doctor_runs():
    result = subprocess.run(
        [sys.executable, "-m", "software_butcher", "llm-doctor", "--no-chat"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "OpenRouter LLM diagnostics" in result.stdout or "OpenRouter LLM diagnostics" in result.stderr
