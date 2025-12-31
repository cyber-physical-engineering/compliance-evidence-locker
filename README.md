# Compliance Evidence Locker

**Stop manually collecting screenshots for auditors. Auto-generate FDA submission evidence in real-time.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-green.svg)](Dockerfile)

## The Problem

Every FDA inspection, every HIPAA audit, every SOC 2 assessment requires **evidence**. Today, that means:
- Screenshots of logs
- Manual attestation letters  
- Excel spreadsheets mapping controls to policies
- Frantic scrambling before audits

## The Solution

The Evidence Locker continuously ingests logs from your Trust Stack and automatically:
1. **Maps** events to compliance controls (FDA 21 CFR Part 11)
2. **Hashes** evidence into an immutable chain
3. **Exports** audit-ready proof on demand

```
┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ clinical-ai-     │     │  EVIDENCE       │     │  📄 FDA Report   │
│ gateway logs     │ ──▶ │  LOCKER         │ ──▶ │  📊 HIPAA Grid   │
│                  │     │                 │     │  📈 SOC 2 Matrix │
└──────────────────┘     └─────────────────┘     └──────────────────┘
```

## Features

- 🔐 **Immutable Evidence Chain**: SHA-256 hash chain ensures evidence integrity
- 📋 **Control Mapping**: Auto-map log events to FDA 21 CFR Part 11 requirements
- 📄 **Export**: JSON/JSONL exports for auditor review
- ✅ **Verification**: Cryptographic integrity check of the entire chain
- 🐳 **Docker Ready**: Deploy anywhere

## Quick Start

### CLI Usage

```bash
# Install
pip install -e .

# Initialize a new evidence chain
evidence-locker init ./evidence_data

# Ingest an audit event
evidence-locker ingest ./evidence_data \
  --event-type POLICY_DECISION \
  --data '{"decision": "ALLOW", "user": "admin", "resource": "patient/123"}' \
  --definitions control_definitions

# Check status
evidence-locker status ./evidence_data

# Verify integrity
evidence-locker verify ./evidence_data

# Export evidence
evidence-locker export ./evidence_data --output audit_export.json
```

### Docker Usage

```bash
# Build
docker build -t evidence-locker .

# Run
docker run --rm -v $(pwd)/evidence_data:/data evidence-locker \
  ingest /data \
  --event-type SYSTEM_STARTUP \
  --data '{"version": "1.0.0"}'
```

## Supported Frameworks

| Framework | Controls | Status |
|-----------|----------|--------|
| FDA 21 CFR Part 11 | Electronic Records | ✅ |
| HIPAA Security Rule | Administrative, Physical, Technical | 🚧 |
| SOC 2 Type II | Trust Service Criteria | 🚧 |

## Control Mapping Example

When you ingest an event, it's automatically mapped to controls defined in `control_definitions/`.

Example `POLICY_DECISION` maps to:
- **11.10(d)**: Limiting System Access
- **11.10(g)**: Authority Checks

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Related Projects

- [fhir-verifiable-credentials](../fhir-verifiable-credentials) - FHIR to VC conversion
- [sbom-trust-manager](../sbom-trust-manager) - Supply chain security

## License

Apache 2.0 - See [LICENSE](LICENSE)
