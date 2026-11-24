# oci-compute-agent-plugin-audit

**Custom portfolio tool (offline).** Audits the Oracle Cloud Agent plugin
posture of OCI Compute instances from a **synthetic JSON export** - no OCI
tenancy access, no live API calls, no credentials.

## Problem it solves

Every OCI Compute instance runs the Oracle Cloud Agent, and most platform
features people assume they have - managed bastion access, host vulnerability
scans, managed patching, log collection, OS-level metrics - are actually
per-instance **agent plugins** that can be disabled or stopped. A fleet where
half the production instances quietly have the Bastion or Vulnerability
Scanning plugin off is a real operational gap. This tool reads an export of
instances and their plugin states and flags the gaps.

## What it does

Rules evaluated per active (non-TERMINATED) instance:

| Rule | Severity | Finding |
| ---- | -------- | ------- |
| AGP001 | HIGH | Production instance with the Bastion plugin disabled (no managed just-in-time SSH via OCI Bastion) |
| AGP002 | HIGH (prod) / MEDIUM (dev) | Vulnerability Scanning plugin disabled (invisible to OCI Vulnerability Scanning Service host scans) |
| AGP003 | MEDIUM | OS Management Service Agent disabled (no managed patching / package inventory via OS Management Hub) |
| AGP004 | MEDIUM | Custom Logs Monitoring plugin disabled (Logging agent configurations cannot collect logs) |
| AGP005 | LOW | Compute Instance Monitoring plugin disabled (Monitoring loses OS-level metrics) |
| AGP006 | LOW | Plugin enabled but reporting a non-RUNNING status |

Exit codes: `0` clean, `1` only MEDIUM/LOW findings, `2` HIGH findings
present, `3` malformed export.

## Run it

```bash
python -m agent_audit.cli samples/instances_messy.json   # exits 2, 11 findings
python -m agent_audit.cli samples/instances_clean.json   # exits 0
```

## Test it

```bash
python -m unittest discover -s tests -v   # 24 tests
```

CI (`.github/workflows/ci.yml`) runs the tests on Python 3.10/3.11/3.12 and
re-runs both demo exports, asserting the messy export exits 2 and the clean
export exits 0.

## Honest limits

- **Offline / synthetic data.** The export format in `samples/` is invented
  for this tool; nothing here talks to OCI. To use it on a real fleet you
  would build the same JSON from `oci compute instance get` and
  `oci compute instance list-plugins` output (not included).
- TERMINATED instances are skipped by design.
- `terraform/main.tf` is a **template only** showing how an instance with the
  audited agent plugins would be declared; it has **not** been plan/apply
  validated against a live tenancy.

## Layout

```
agent_audit/    model.py (export loading), rules.py (AGP001-AGP006), cli.py
samples/        messy + clean synthetic exports
tests/          24 unittest tests (model, rules, CLI)
terraform/      template-only instance + agent plugin config
```
