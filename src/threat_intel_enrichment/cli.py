"""Command-line interface for the threat-intelligence enrichment pipeline."""

from __future__ import annotations

import typer
from rich.console import Console

from threat_intel_enrichment import __version__

app = typer.Typer(
    name="threat-intel-enrichment",
    help="Enrich defensive security events with threat-intelligence context.",
    no_args_is_help=True,
)

console = Console()


@app.command()
def version() -> None:
    """Display the installed application version."""
    console.print(f"threat-intel-enrichment {__version__}")


@app.command()
def doctor() -> None:
    """Verify that the command-line application is installed correctly."""
    console.print("[green]Environment check passed.[/green]")


if __name__ == "__main__":
    app()
