#!/usr/bin/env python3
"""gate-identity -- are the delegated gate composites byte-identical to canonical?

Two trees carry every delegated gate on purpose: security-orchestration's
`remediation/gates/` (canonical, what signature replay runs) and this
repository's `.github/actions/<action>/` (what every consumer's CI runs at its
pin). gatelib resolves whichever it finds and reports a mirror that has fallen
behind as a NOTE, which is a line in a report nobody re-reads. This script turns
the comparison into an exit code.

WHERE A RED IS CORRECT, AND WHERE IT IS NOT. This repository's own self-check
runs it BLOCKING: a pull request here that edits a composite script without the
same bytes already being canonical is refused, which is the one place the
wrong-direction edit could happen. The fleet's signature-replay job runs it
ADVISORY (`--advisory`: same findings as `::warning::`, exit 0). A blocking
comparison of two mains there would deadlock the canonical-first ordering that
gatelib's own comment sanctions: a security-orchestration pull request changing
a gate runs its own replay against shared-workflows main, which cannot carry
bytes that do not exist until that pull request merges -- so the change could
never land, and neither could the re-copy that depends on it.

The pairs are read from `gatelib.SHARED_ACTIONS` / `SHARED_ACTION_ASSETS` in the
canonical checkout, so a gate registered there is covered here on the same
commit and this script cannot drift from the map it enforces. A gate registered
AHEAD of its action is skipped and said out loud: until the directory exists
there is nothing upstream for any consumer to run. An action directory that
EXISTS but lacks one of the gate's files is not skipped -- that is the
incomplete-action state gatelib exits 2 on in every replay host, named here
instead of waited for. Comparing nothing at all is a failure, not a pass.

usage:
    gate-identity.py --actions <.github/actions dir> --gates <remediation/gates dir>
                     --signatures <remediation/signatures dir> [--advisory]

Exit 0 = identical (or --advisory). 1 = drift, incomplete action, or nothing
compared. 2 = the trees or gatelib could not be read at all.
"""

from __future__ import annotations

import argparse
import filecmp
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="delegated gate byte identity")
    parser.add_argument("--actions", required=True, help="the .github/actions directory")
    parser.add_argument("--gates", required=True, help="canonical remediation/gates directory")
    parser.add_argument("--signatures", required=True, help="remediation/signatures directory (for gatelib)")
    parser.add_argument("--advisory", action="store_true", help="report as ::warning:: and exit 0")
    args = parser.parse_args()

    level = "warning" if args.advisory else "error"

    for label, path in (("--actions", args.actions), ("--gates", args.gates), ("--signatures", args.signatures)):
        if not os.path.isdir(path):
            print(
                f"::error::{label} {path!r} is not a directory. The comparison would pass having "
                "compared nothing; that is the vacuous green the gates exist to refuse."
            )
            return 2

    sys.path.insert(0, os.path.abspath(args.signatures))
    try:
        import gatelib  # noqa: E402  -- resolved from --signatures, deliberately
    except Exception as exc:  # noqa: BLE001 -- any import failure is could-not-run
        print(f"::error::gatelib could not be imported from {args.signatures}: {exc}")
        return 2

    compared = 0
    drifted: list[str] = []
    absent: list[str] = []
    for gate, action in sorted(gatelib.SHARED_ACTIONS.items()):
        action_dir = os.path.join(args.actions, action)
        if not os.path.isdir(action_dir):
            print(
                f"skipped: {gate} is registered for the '{action}' action, which does not exist "
                "here yet -- no consumer can be running it, so there is nothing to compare."
            )
            continue
        for rel in gatelib.gate_files(gate):
            here = os.path.join(action_dir, rel)
            there = os.path.join(args.gates, rel)
            if not os.path.isfile(there):
                absent.append(f"{there} (the canonical copy of {gate}'s {rel})")
                continue
            if not os.path.isfile(here):
                absent.append(f"{here} (the '{action}' action ships {gate} without {rel})")
                continue
            compared += 1
            if not filecmp.cmp(here, there, shallow=False):
                drifted.append(f"{here} differs from {there}")

    print(f"compared {compared} file(s) across {len(gatelib.SHARED_ACTIONS)} registered gate(s)")

    for line in absent:
        print(
            f"::{level}::a delegated gate is incomplete: {line} is missing. gatelib treats a "
            "present-but-incomplete action as could-not-run (exit 2) in every replay host at once; "
            "ship the missing file or unregister the gate."
        )
    for line in drifted:
        print(
            f"::{level}::{line}. These two copies are required to be byte-identical: gatelib runs "
            "whichever one it finds, so the same class can be answered two ways. Fix it in "
            "security-orchestration's remediation/gates/ first, then re-copy into the action."
        )
    if compared == 0:
        print(
            f"::{level}::no delegated gate file was compared. Every gate in gatelib.SHARED_ACTIONS "
            "resolved to an action directory that is not here, so this check is enforcing nothing."
        )

    failed = bool(absent or drifted) or compared == 0
    if failed and not args.advisory:
        return 1
    if failed:
        print("advisory mode: findings above are warnings; the blocking check is shared-workflows' own self-check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
