#!/usr/bin/env python3
"""
ModelGuard CLI. Scan model artifacts for code-execution payloads without loading
them. Optionally verify integrity against a manifest of known-good SHA-256 hashes.

    python scan.py samples/              # scan a directory
    python scan.py samples/malicious.pkl # scan one file
    python scan.py samples/ --manifest manifest.json

Exit code is non-zero if any artifact is flagged critical -> use it as a CI gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from modelguard.scan import scan_file


def gather(path: Path):
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.suffix in (".pkl", ".pt", ".bin", ".pth"))
    return [path]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--manifest", type=Path, help="JSON {filename: sha256} of trusted artifacts")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text()) if args.manifest and args.manifest.exists() else {}
    flagged = 0

    for f in gather(args.path):
        findings, sha = scan_file(f)
        crit = [x for x in findings if x.severity == "critical"]
        integ = ""
        if manifest:
            expected = manifest.get(f.name)
            integ = " ✓ integrity" if expected == sha else " ✗ INTEGRITY MISMATCH"
            if expected and expected != sha:
                crit.append(True)

        if crit:
            flagged += 1
            print(f"🔴 {f}  sha256={sha[:12]}…{integ}")
            for x in findings:
                if x.severity == "critical":
                    print(f"     [{x.opcode}] {x.detail}")
        else:
            print(f"🟢 {f}  sha256={sha[:12]}…{integ}  — no code-execution payload")

    print(f"\n{flagged} artifact(s) flagged.")
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
