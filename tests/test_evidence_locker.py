"""Tests for the Compliance Evidence Locker."""

from __future__ import annotations

import tempfile
from pathlib import Path

from evidence_locker.core.control_mapper import ControlMapper
from evidence_locker.core.hash_chain import EvidenceChain


def test_hash_chain_initialization():
    """Test that a new chain creates a genesis block."""
    with tempfile.TemporaryDirectory() as tmpdir:
        chain = EvidenceChain(Path(tmpdir))

        assert len(chain.chain) == 1
        assert chain.chain[0].event_type == "GENESIS"
        assert chain.chain[0].index == 0


def test_hash_chain_add_evidence():
    """Test adding evidence blocks to the chain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        chain = EvidenceChain(Path(tmpdir))

        block = chain.add_evidence(
            event_type="POLICY_DECISION",
            event_data={"decision": "ALLOW", "user": "test@example.com"},
            control_mappings=[],
        )

        assert block.index == 1
        assert block.event_type == "POLICY_DECISION"
        assert block.previous_hash == chain.chain[0].hash


def test_hash_chain_integrity():
    """Test chain integrity verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        chain = EvidenceChain(Path(tmpdir))

        chain.add_evidence(
            event_type="TEST_EVENT_1",
            event_data={"test": True},
            control_mappings=[],
        )
        chain.add_evidence(
            event_type="TEST_EVENT_2",
            event_data={"test": True},
            control_mappings=[],
        )

        is_valid, invalid_at = chain.verify_integrity()
        assert is_valid is True
        assert invalid_at is None


def test_control_mapper_loads_definitions():
    """Test that ControlMapper loads YAML definitions."""
    definitions_dir = Path(__file__).parent.parent / "control_definitions"
    mapper = ControlMapper(definitions_dir)

    assert "FDA 21 CFR Part 11" in mapper.list_frameworks()


def test_control_mapper_event_matching():
    """Test mapping events to controls."""
    definitions_dir = Path(__file__).parent.parent / "control_definitions"
    mapper = ControlMapper(definitions_dir)

    # Test wildcard matching (11.10(e) Audit Trails matches all events)
    matches = mapper.map_event("SOME_RANDOM_EVENT")
    assert any(m.control_id == "11.10(e)" for m in matches)

    # Test specific pattern matching
    matches = mapper.map_event("POLICY_DECISION")
    control_ids = [m.control_id for m in matches]
    assert "11.10(d)" in control_ids  # Access control
    assert "11.10(e)" in control_ids  # Audit trails


def test_control_mapper_condition_matching():
    """Test conditional matching based on event data."""
    definitions_dir = Path(__file__).parent.parent / "control_definitions"
    mapper = ControlMapper(definitions_dir)

    # Test with ALLOW decision
    matches = mapper.map_event(
        "POLICY_DECISION",
        {"decision": "ALLOW"},
    )
    allow_matches = [m for m in matches if m.control_id == "11.10(g)"]
    assert len(allow_matches) > 0

    # Test with BLOCK decision
    matches = mapper.map_event(
        "POLICY_DECISION",
        {"decision": "BLOCK"},
    )
    block_matches = [m for m in matches if m.control_id == "11.10(g)"]
    assert len(block_matches) > 0


def test_chain_persistence():
    """Test that chain persists across loads."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir)

        # Create chain and add block
        chain1 = EvidenceChain(path)
        chain1.add_evidence(
            event_type="PERSISTENT_TEST",
            event_data={"value": 42},
            control_mappings=[],
        )
        original_hash = chain1.get_chain_hash()

        # Load chain again
        chain2 = EvidenceChain(path)

        assert len(chain2.chain) == 2
        assert chain2.get_chain_hash() == original_hash
        assert chain2.chain[1].event_type == "PERSISTENT_TEST"



def test_edited_block_is_reported_not_crashed(tmp_path):
    import json

    from evidence_locker.core.hash_chain import ChainIntegrityError, EvidenceChain

    chain = EvidenceChain(tmp_path)
    chain.add_evidence("POLICY_DECISION", {"decision": "ALLOW"}, [])

    chain_file = tmp_path / "chain.jsonl"
    lines = chain_file.read_text().splitlines()
    block = json.loads(lines[1])
    block["event_data"]["decision"] = "DENY"
    lines[1] = json.dumps(block)
    chain_file.write_text("\n".join(lines) + "\n")

    # A normal load refuses the edited chain.
    try:
        EvidenceChain(tmp_path)
    except ChainIntegrityError as error:
        assert error.index == 1
    else:
        raise AssertionError("an edited chain loaded without error")

    # The verify path loads it anyway and names the first bad block.
    is_valid, invalid_at = EvidenceChain(tmp_path, verify_on_load=False).verify_integrity()
    assert (is_valid, invalid_at) == (False, 1)
