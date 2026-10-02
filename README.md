# Compliance Evidence Locker

A command-line tool that keeps audit events in a hash-chained JSON Lines file. Each event can be tagged with the 21 CFR Part 11 §11.10 controls it may support, from a YAML file you can edit. The tags are a starting point for an auditor's review, not a compliance determination.

**Status: prototype.** 8 tests pass on Python 3.9 (October 2026). The walkthrough below was run as written.

James Thornton set the architecture and requirements. The code was written with AI-assisted development in late 2025. The tests and checks were re-run in October 2026.

## What it does

- `init` creates a chain with a genesis block.
- `ingest` appends one event. With `--definitions`, it tags the event with the matching controls.
- `verify` recomputes every block hash and every link, and names the first bad block.
- `status` prints block counts, timestamps and event types.
- `export` writes the chain as JSON or JSONL.
- `list-controls` prints the controls loaded from a definitions directory.

## Quick start

```bash
pip install -e .

evidence-locker init ./evidence_data

evidence-locker ingest ./evidence_data \
  --event-type POLICY_DECISION \
  --data '{"decision": "ALLOW", "user": "admin", "resource": "patient/123"}' \
  --definitions control_definitions

evidence-locker verify ./evidence_data
evidence-locker status ./evidence_data
evidence-locker export ./evidence_data --output audit_export.json
```

What the run prints. Hash prefixes and timestamps differ per run.

```
✓ Evidence chain initialized at ./evidence_data
  Genesis block hash: ...
✓ Evidence block #1 added
  Hash: ...
  Mapped to 3 control(s):
    - 11.10(d): Limiting System Access
    - 11.10(e): Audit Trails
    - 11.10(g): Authority Checks
✓ Chain integrity verified (2 blocks)
  Chain tip: ...
Evidence Chain: ./evidence_data
  Total blocks: 2
  Chain tip:    ...
  First block:  ...
  Last block:   ...
  Event types:
    - GENESIS: 1
    - POLICY_DECISION: 1
✓ Exported 2 blocks to audit_export.json
```

Run the tests:

```bash
pip install -e ".[dev]"
pytest
```

## How the chain works

The chain is `chain.jsonl` in the storage directory, one block per line. A block holds `index`, `timestamp`, `event_type`, `event_data`, `control_mappings`, `previous_hash` and `hash`. The hash is the SHA-256 of the block's other fields serialized as sorted-key JSON. `previous_hash` is the hash of the block before; the genesis block's is 64 zeros.

The commands that read the chain (`init`, `ingest`, `status` and `export`) verify it first. If a block was edited, the command stops with `✗ Chain integrity FAILED at block N` and exit code 1. `verify` loads without that check and reports the first bad block the same way.

## What verification catches, and what it does not

An edited block fails, because its stored hash no longer matches its contents. A broken link fails, because the next block's `previous_hash` no longer matches. A full rewrite passes: someone who edits a block and recomputes every hash after it produces a chain that verifies. The file carries no signature and no outside anchor. Catching that case takes a signature, write-once storage, or a chain tip saved somewhere the writer cannot reach.

## Control tagging

`control_definitions/fda_21cfr11.yaml` defines five controls from 21 CFR Part 11 §11.10: (a) validation, (b) readable copies, (d) limiting system access, (e) audit trails and (g) authority checks. Each control lists event patterns (glob style, case-insensitive) and optional conditions such as `decision == 'ALLOW'`. A `POLICY_DECISION` event matches (d), (e) and (g).

Two things to know. A condition the parser cannot read counts as a match, so an unusual condition tags more than it should. And the other six §11.10 controls, (c), (f), (h), (i), (j) and (k), are not in the file. Add controls or frameworks by adding YAML files to the directory.

## Limits

- Tagging is pattern matching on event names. It does not judge whether an event is evidence of anything.
- No signature, key or outside anchor. A full rewrite is not caught.
- One event per command. There is no watcher, API or stream.
- Export is JSON or JSONL only.
- Only the Part 11 file exists. Nothing covers HIPAA or SOC 2.
- A Dockerfile is included. It was not re-tested in October 2026.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
