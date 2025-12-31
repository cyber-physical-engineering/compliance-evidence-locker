"""Compliance Evidence Locker CLI.

Commands for managing immutable audit evidence and generating compliance reports.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import typer

from ..core.control_mapper import ControlMapper
from ..core.hash_chain import EvidenceChain

app = typer.Typer(
    add_completion=False,
    help="Compliance Evidence Locker - Immutable audit evidence for FDA/HIPAA compliance",
)


@app.command()
def init(
    storage_path: Path = typer.Argument(
        ..., help="Directory to store the evidence chain"
    ),
) -> None:
    """Initialize a new evidence chain at the specified location."""
    chain = EvidenceChain(storage_path)
    typer.echo(f"✓ Evidence chain initialized at {storage_path}")
    typer.echo(f"  Genesis block hash: {chain.get_chain_hash()[:16]}...")


@app.command()
def ingest(
    storage_path: Path = typer.Argument(
        ..., help="Path to existing evidence chain"
    ),
    event_type: str = typer.Option(
        ..., "--event-type", "-t", help="Event type (e.g., POLICY_DECISION)"
    ),
    event_data: str = typer.Option(
        ..., "--data", "-d", help="Event data as JSON string"
    ),
    definitions_path: Optional[Path] = typer.Option(
        None,
        "--definitions",
        "-D",
        help="Path to control definitions directory",
    ),
) -> None:
    """Ingest a new audit event into the evidence chain."""
    # Parse event data
    try:
        data = json.loads(event_data)
    except json.JSONDecodeError as e:
        raise typer.BadParameter(f"Invalid JSON: {e}") from e

    # Load chain
    chain = EvidenceChain(storage_path)

    # Map to controls if definitions provided
    control_mappings: list[dict[str, Any]] = []
    if definitions_path:
        mapper = ControlMapper(definitions_path)
        matches = mapper.map_event(event_type, data)
        control_mappings = [
            {
                "control_id": m.control_id,
                "control_title": m.control_title,
                "evidence_type": m.evidence_type,
                "framework": m.framework,
            }
            for m in matches
        ]

    # Add evidence
    block = chain.add_evidence(
        event_type=event_type,
        event_data=data,
        control_mappings=control_mappings,
    )

    typer.echo(f"✓ Evidence block #{block.index} added")
    typer.echo(f"  Hash: {block.hash[:16]}...")
    if control_mappings:
        typer.echo(f"  Mapped to {len(control_mappings)} control(s):")
        for cm in control_mappings:
            typer.echo(f"    - {cm['control_id']}: {cm['control_title']}")


@app.command()
def verify(
    storage_path: Path = typer.Argument(
        ..., help="Path to evidence chain to verify"
    ),
) -> None:
    """Verify the integrity of an evidence chain."""
    chain = EvidenceChain(storage_path)
    is_valid, invalid_at = chain.verify_integrity()

    if is_valid:
        typer.echo(f"✓ Chain integrity verified ({len(chain.chain)} blocks)")
        typer.echo(f"  Chain tip: {chain.get_chain_hash()[:16]}...")
    else:
        typer.echo(f"✗ Chain integrity FAILED at block {invalid_at}", err=True)
        raise typer.Exit(1)


@app.command()
def status(
    storage_path: Path = typer.Argument(
        ..., help="Path to evidence chain"
    ),
) -> None:
    """Show status of an evidence chain."""
    chain = EvidenceChain(storage_path)

    typer.echo(f"Evidence Chain: {storage_path}")
    typer.echo(f"  Total blocks: {len(chain.chain)}")
    typer.echo(f"  Chain tip:    {chain.get_chain_hash()[:16]}...")

    if len(chain.chain) > 0:
        first = chain.chain[0]
        last = chain.chain[-1]
        typer.echo(f"  First block:  {first.timestamp}")
        typer.echo(f"  Last block:   {last.timestamp}")

        # Count event types
        event_types: dict[str, int] = {}
        for block in chain.chain:
            event_types[block.event_type] = event_types.get(block.event_type, 0) + 1

        typer.echo("  Event types:")
        for et, count in sorted(event_types.items()):
            typer.echo(f"    - {et}: {count}")


@app.command()
def export(
    storage_path: Path = typer.Argument(
        ..., help="Path to evidence chain"
    ),
    output: Path = typer.Option(
        Path("evidence_export.json"),
        "--output",
        "-o",
        help="Output file path",
    ),
    format_type: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, jsonl)",
    ),
) -> None:
    """Export the evidence chain to a file."""
    chain = EvidenceChain(storage_path)

    if format_type == "jsonl":
        with open(output, "w") as f:
            for block in chain.chain:
                f.write(json.dumps(block.to_dict()) + "\n")
    else:
        export_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "chain_hash": chain.get_chain_hash(),
            "block_count": len(chain.chain),
            "blocks": [block.to_dict() for block in chain.chain],
        }
        with open(output, "w") as f:
            json.dump(export_data, f, indent=2)

    typer.echo(f"✓ Exported {len(chain.chain)} blocks to {output}")


@app.command()
def list_controls(
    definitions_path: Path = typer.Argument(
        ..., help="Path to control definitions directory"
    ),
) -> None:
    """List all loaded control definitions."""
    mapper = ControlMapper(definitions_path)

    for framework_name in mapper.list_frameworks():
        framework = mapper.get_framework(framework_name)
        if framework:
            typer.echo(f"\n{framework.name} ({framework.version})")
            typer.echo(f"  {framework.description}")
            typer.echo("  Controls:")
            for control in framework.controls:
                typer.echo(f"    [{control.id}] {control.title}")
                typer.echo(f"      Evidence types: {', '.join(control.evidence_types)}")


if __name__ == "__main__":
    app()

