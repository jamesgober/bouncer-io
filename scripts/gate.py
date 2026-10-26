#!/usr/bin/env python3
"""The instruction-count regression gate.

Reads a Callgrind output file, takes the inclusive instruction count of every
`gate_*` function in benches/gate.rs, and compares it with
benches/gate-baseline.txt. A count more than 5% over its baseline fails.

    python3 scripts/gate.py callgrind.out [--write]

`--write` replaces the baseline with this run's counts (after a deliberate
change, reviewed in the diff).
"""

import re
import subprocess
import sys
from pathlib import Path

LIMIT = 1.05
BASELINE = Path(__file__).resolve().parent.parent / "benches" / "gate-baseline.txt"


def counts(out_file):
    text = subprocess.run(
        ["callgrind_annotate", "--inclusive=yes", "--threshold=100", out_file],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found = {}
    for line in text.splitlines():
        m = re.match(r"\s*([\d,]+)\s.*\b(gate_[a-z_]+)\b", line)
        if m:
            name = m.group(2)
            value = int(m.group(1).replace(",", ""))
            found[name] = max(found.get(name, 0), value)
    return found


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    now = counts(sys.argv[1])
    if not now:
        sys.exit("no gate_* functions in the Callgrind output")
    for name in sorted(now):
        print(f"{name:<24} {now[name]:>14,}")
    if "--write" in sys.argv:
        BASELINE.write_text("".join(f"{k} {now[k]}\n" for k in sorted(now)))
        print(f"wrote {BASELINE}")
        return
    if not BASELINE.exists():
        print("no baseline yet: these counts are the first one")
        return
    base = {}
    for line in BASELINE.read_text().splitlines():
        if line.strip():
            k, v = line.split()
            base[k] = int(v)
    failed = False
    for name, value in sorted(now.items()):
        if name not in base:
            print(f"{name}: new, no baseline")
            continue
        ratio = value / base[name]
        mark = "ok"
        if ratio > LIMIT:
            mark = "REGRESSION"
            failed = True
        print(f"{name:<24} {ratio:6.3f} x baseline  {mark}")
    if failed:
        sys.exit(f"instruction count more than {int((LIMIT - 1) * 100)}% over the baseline")


if __name__ == "__main__":
    main()
