"""SHA-256 hash chain for audit events.

An append-only JSON Lines log. Each block carries the hash of the block before
it, so an edited block or a broken link fails verification. There is no
signature and no outside anchor, so a full rewrite is not caught.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class EvidenceBlock:
    """A single block in the evidence chain."""

    index: int
    timestamp: str
    event_type: str
    event_data: dict[str, Any]
    control_mappings: list[dict[str, Any]]
    previous_hash: str
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of block contents."""
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "event_data": self.event_data,
                "control_mappings": self.control_mappings,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "control_mappings": self.control_mappings,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


class ChainIntegrityError(ValueError):
    """Raised when a stored chain fails verification on load."""

    def __init__(self, index: int) -> None:
        super().__init__(f"Chain integrity error at block {index}")
        self.index = index


class EvidenceChain:
    """Append-only chain of audit events, one block per event."""

    GENESIS_HASH = "0" * 64

    def __init__(self, storage_path: Path, verify_on_load: bool = True) -> None:
        self.storage_path = Path(storage_path)
        self.chain: list[EvidenceBlock] = []
        self._load_or_initialize()
        if verify_on_load:
            is_valid, invalid_at = self.verify_integrity()
            if not is_valid:
                raise ChainIntegrityError(invalid_at if invalid_at is not None else 0)

    def _load_or_initialize(self) -> None:
        """Load existing chain or create genesis block."""
        chain_file = self.storage_path / "chain.jsonl"

        if chain_file.exists():
            with open(chain_file) as f:
                for line in f:
                    block_data = json.loads(line)
                    block = EvidenceBlock(
                        index=block_data["index"],
                        timestamp=block_data["timestamp"],
                        event_type=block_data["event_type"],
                        event_data=block_data["event_data"],
                        control_mappings=block_data["control_mappings"],
                        previous_hash=block_data["previous_hash"],
                    )
                    # Keep the stored hash; verify_integrity() compares it
                    # with a fresh hash of the block's contents.
                    block.hash = block_data["hash"]
                    self.chain.append(block)
        else:
            # Create genesis block
            self._create_genesis()

    def _create_genesis(self) -> None:
        """Create the genesis block."""
        genesis = EvidenceBlock(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="GENESIS",
            event_data={"message": "Evidence chain initialized"},
            control_mappings=[],
            previous_hash=self.GENESIS_HASH,
        )
        self.chain.append(genesis)
        self._persist_block(genesis)

    def add_evidence(
        self,
        event_type: str,
        event_data: dict[str, Any],
        control_mappings: list[dict[str, Any]],
    ) -> EvidenceBlock:
        """Add new evidence to the chain."""
        previous_block = self.chain[-1]

        new_block = EvidenceBlock(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            event_data=event_data,
            control_mappings=control_mappings,
            previous_hash=previous_block.hash,
        )

        self.chain.append(new_block)
        self._persist_block(new_block)

        return new_block

    def _persist_block(self, block: EvidenceBlock) -> None:
        """Append block to chain file."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        chain_file = self.storage_path / "chain.jsonl"

        with open(chain_file, "a") as f:
            f.write(json.dumps(block.to_dict()) + "\n")

    def verify_integrity(self) -> tuple[bool, Optional[int]]:
        """Verify the entire chain integrity.

        Returns:
            (is_valid, first_invalid_index)
        """
        for i, block in enumerate(self.chain):
            # Check genesis
            if i == 0:
                if block.previous_hash != self.GENESIS_HASH:
                    return False, 0
                continue

            # Check link to previous
            if block.previous_hash != self.chain[i - 1].hash:
                return False, i

            # Verify hash
            expected_hash = block._calculate_hash()
            if block.hash != expected_hash:
                return False, i

        return True, None

    def get_chain_hash(self) -> str:
        """Get the current chain tip hash."""
        return self.chain[-1].hash if self.chain else self.GENESIS_HASH
