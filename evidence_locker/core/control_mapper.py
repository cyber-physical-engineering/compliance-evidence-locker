"""ControlMapper: matches event types to control definitions.

The definitions are YAML files; the shipped one covers five controls from
21 CFR Part 11 §11.10. A match is a tag for an auditor's review, not a
compliance determination.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class ControlDefinition:
    """A single compliance control definition."""

    id: str
    title: str
    description: str
    evidence_types: list[str]
    event_mappings: list[dict[str, Any]]


@dataclass
class FrameworkDefinition:
    """A compliance framework with its controls."""

    name: str
    version: str
    description: str
    controls: list[ControlDefinition] = field(default_factory=list)


@dataclass
class ControlMatch:
    """Result of matching an event to controls."""

    control_id: str
    control_title: str
    evidence_type: str
    framework: str
    confidence: float = 1.0


class ControlMapper:
    """Maps audit events to compliance controls."""

    def __init__(self, definitions_dir: Path):
        """Initialize the mapper with control definitions.

        Args:
            definitions_dir: Path to directory containing YAML control definitions
        """
        self.definitions_dir = Path(definitions_dir)
        self.frameworks: dict[str, FrameworkDefinition] = {}
        self._load_definitions()

    def _load_definitions(self) -> None:
        """Load all YAML control definition files."""
        if not self.definitions_dir.exists():
            return

        for yaml_file in self.definitions_dir.glob("*.yaml"):
            self._load_framework(yaml_file)

    def _load_framework(self, yaml_path: Path) -> None:
        """Load a single framework definition file."""
        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        framework_info = data.get("framework", {})
        framework = FrameworkDefinition(
            name=framework_info.get("name", yaml_path.stem),
            version=framework_info.get("version", "unknown"),
            description=framework_info.get("description", ""),
        )

        for control_data in data.get("controls", []):
            control = ControlDefinition(
                id=control_data["id"],
                title=control_data.get("title", ""),
                description=control_data.get("description", ""),
                evidence_types=control_data.get("evidence_types", []),
                event_mappings=control_data.get("event_mappings", []),
            )
            framework.controls.append(control)

        self.frameworks[framework.name] = framework

    def map_event(
        self,
        event_type: str,
        event_data: Optional[dict[str, Any]] = None,
    ) -> list[ControlMatch]:
        """Map an audit event to applicable compliance controls.

        Args:
            event_type: The type/category of the event (e.g., "POLICY_DECISION")
            event_data: Optional event payload for condition matching

        Returns:
            List of matching controls with evidence types
        """
        matches: list[ControlMatch] = []
        event_data = event_data or {}

        for framework in self.frameworks.values():
            for control in framework.controls:
                for mapping in control.event_mappings:
                    pattern = mapping.get("event_pattern", "")

                    # Check pattern match
                    if not self._pattern_matches(pattern, event_type):
                        continue

                    # Check optional condition
                    condition = mapping.get("condition")
                    if condition and not self._condition_matches(condition, event_data):
                        continue

                    # We have a match
                    matches.append(
                        ControlMatch(
                            control_id=control.id,
                            control_title=control.title,
                            evidence_type=mapping.get("evidence_type", "AUDIT_LOG_ENTRY"),
                            framework=framework.name,
                        )
                    )

        return matches

    def _pattern_matches(self, pattern: str, event_type: str) -> bool:
        """Check if an event type matches a pattern (supports wildcards)."""
        if pattern == "*":
            return True

        # Convert glob-style wildcards to regex
        regex_pattern = fnmatch.translate(pattern)
        return bool(re.match(regex_pattern, event_type, re.IGNORECASE))

    def _condition_matches(self, condition: str, event_data: dict[str, Any]) -> bool:
        """Evaluate a simple condition against event data.

        Supports conditions like:
        - "decision == 'ALLOW'"
        - "severity >= 5"
        """
        # Simple equality check: field == 'value'
        eq_match = re.match(r"(\w+)\s*==\s*['\"]?(\w+)['\"]?", condition)
        if eq_match:
            field, expected = eq_match.groups()
            return str(event_data.get(field, "")).upper() == expected.upper()

        # Numeric comparison: field >= value
        cmp_match = re.match(r"(\w+)\s*(>=|<=|>|<)\s*(\d+)", condition)
        if cmp_match:
            field, op, threshold = cmp_match.groups()
            actual = event_data.get(field)
            if actual is None:
                return False
            try:
                actual_num = float(actual)
                threshold_num = float(threshold)
                if op == ">=":
                    return actual_num >= threshold_num
                elif op == "<=":
                    return actual_num <= threshold_num
                elif op == ">":
                    return actual_num > threshold_num
                elif op == "<":
                    return actual_num < threshold_num
            except (ValueError, TypeError):
                return False

        # A condition this parser cannot read counts as a match. The README names this limit.
        return True

    def get_framework(self, name: str) -> Optional[FrameworkDefinition]:
        """Get a specific framework by name."""
        return self.frameworks.get(name)

    def list_frameworks(self) -> list[str]:
        """List all loaded framework names."""
        return list(self.frameworks.keys())

    def get_controls_by_type(self, evidence_type: str) -> list[ControlDefinition]:
        """Get all controls that accept a given evidence type."""
        result: list[ControlDefinition] = []
        for framework in self.frameworks.values():
            for control in framework.controls:
                if evidence_type in control.evidence_types:
                    result.append(control)
        return result

