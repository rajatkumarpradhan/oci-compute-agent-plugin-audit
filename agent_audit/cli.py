"""Command line entry point: audit an offline instance agent plugin export."""

from __future__ import annotations

import argparse
import sys

from .model import ExportError, load_export
from .rules import exit_code, run_all


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-plugin-audit",
        description="Offline posture audit of OCI Compute instance agent "
                    "plugins (synthetic export).",
    )
    parser.add_argument("export", help="path to a JSON export of instances")
    args = parser.parse_args(argv)
    try:
        instances = load_export(args.export)
    except ExportError as exc:
        print(f"export error: {exc}", file=sys.stderr)
        return 3
    active = [i for i in instances if i.is_active()]
    findings = run_all(instances)
    prod = sum(1 for i in active if i.is_production())
    print(f"Compute agent plugin audit - {len(active)} active instance(s) "
          f"({prod} production), {len(findings)} finding(s)")
    for f in findings:
        print(f"[{f.severity:6}] {f.rule} instance={f.target}")
        print(f"        {f.detail}")
    code = exit_code(findings)
    if code == 0:
        print("RESULT: clean, no findings  (exit code 0)")
    else:
        high = sum(1 for f in findings if f.severity == "HIGH")
        print(f"RESULT: {high} HIGH / {len(findings)} total findings present "
              f" (exit code {code})")
    return code


if __name__ == "__main__":
    sys.exit(main())
