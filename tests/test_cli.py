"""Tests for the command-line interface."""

from typer.testing import CliRunner

from threat_intel_enrichment.cli import app

runner = CliRunner()


def test_version_command() -> None:
    """The version command should display the package version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "threat-intel-enrichment 0.1.0" in result.stdout


def test_doctor_command() -> None:
    """The doctor command should report a healthy environment."""
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Environment check passed" in result.stdout
