#!/usr/bin/env python3
"""Regenerate results/ deterministically: python scripts/gen_results.py OUT."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from c9nltk import cases

COLS = ("id", "cls", "config", "encoding", "module", "name", "bytes",
        "extracted", "pre", "pre_rule", "pre_sink", "post", "post_rule",
        "post_sink")


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    syms = cases.symbols()
    rows = sorted((cases.evaluate(c, syms) for c in cases.load_cases()),
                  key=lambda r: r["id"])
    lines = [",".join(COLS)] + [",".join(str(r[c]) for c in COLS) for r in rows]
    (out / "cases.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    summ = ["class,n,pre_allowed,post_allowed,pre_sinks,post_sinks"]
    for cls in ("pos", "neg", "compat"):
        sel = [r for r in rows if r["cls"] == cls]
        summ.append(",".join(str(x) for x in (
            cls, len(sel),
            sum(r["pre"].startswith("ALLOW") for r in sel),
            sum(r["post"].startswith("ALLOW") for r in sel),
            sum(r["pre_sink"] != "-" for r in sel),
            sum(r["post_sink"] != "-" for r in sel))))
    (out / "summary.csv").write_text("\n".join(summ) + "\n", encoding="utf-8")
    sums = []
    for name in ("cases.csv", "summary.csv"):
        h = hashlib.sha256((out / name).read_bytes()).hexdigest()
        sums.append(f"{h}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen_results.py OUTDIR")
    main(Path(sys.argv[1]))
