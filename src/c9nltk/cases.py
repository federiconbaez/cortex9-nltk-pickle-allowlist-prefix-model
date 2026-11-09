"""Fixture loading and evaluation shared by tests and scripts/gen_results.py."""
from __future__ import annotations

from pathlib import Path

from . import opstream, policy

ROOT = Path(__file__).resolve().parents[2]
BUILDERS = {
    "stack_global": opstream.build_stack_global,
    "global": opstream.build_global,
    "memo": opstream.build_memo,
}


def read_tsv(path: Path) -> list:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            out.append(line.split("\t"))
    return out


def load_cases() -> list:
    keys = ("id", "cls", "config", "encoding", "module", "name",
            "hand_pre", "hand_post")
    rows = read_tsv(ROOT / "fixtures/cases.tsv")
    return [dict(zip(keys, r, strict=True)) for r in rows]


def symbols() -> dict:
    return policy.load_symbols(ROOT / "fixtures/symbols.tsv")


def evaluate(case: dict, syms: dict) -> dict:
    """Build the inert opcode stream, extract its globals statically, and
    apply the pre and post policies to every extracted name."""
    data = BUILDERS[case["encoding"]](case["module"], case["name"])
    found = opstream.extract_globals(data)
    row = {"id": case["id"], "cls": case["cls"], "config": case["config"],
           "encoding": case["encoding"], "module": case["module"],
           "name": case["name"], "bytes": len(data),
           "extracted": "ok" if found == [(case["module"], case["name"])]
           else "MISMATCH"}
    for ver in ("pre", "post"):
        label, rule = policy.decide(ver, case["config"], case["module"],
                                    case["name"], syms)
        row[ver] = label
        row[ver + "_rule"] = rule
        row[ver + "_sink"] = policy.sink_reached(label, case["module"],
                                                 case["name"], syms)
    return row
