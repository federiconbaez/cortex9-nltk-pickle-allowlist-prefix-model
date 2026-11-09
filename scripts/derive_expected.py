#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written again from the saved diff (CVE-2026-79657_nltk_c3e37113742a.diff),
only the GHSA-x99w part: the dotted-name guard (GHSA-4489) is left out,
without importing src/. Each version is a list of (rule, predicate) pairs
evaluated in order; the first match wins. Sinks come from
fixtures/symbols.tsv.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DENY = ("os nt posix subprocess sys socket shutil signal pty popen2 commands "
        "ctypes importlib runpy builtins webbrowser pdb bdb code codeop "
        "multiprocessing asyncio threading pickle numpy.f2py numpy.ctypeslib "
        "numpy.distutils numpy.testing nltk.tokenize.repp nltk.internals").split()
DENIED_G = {("numpy", x) for x in ("load loadtxt fromfile fromregex genfromtxt "
            "save savez savez_compressed savetxt memmap DataSource "
            "vectorize").split()} | {("pandas", "read_pickle")}
SAFE = {("builtins", x) for x in
        "int float complex bool str bytes list tuple dict set frozenset".split()}

PUNKT_EXACT = {("nltk.tokenize.punkt", c) for c in (
    "PunktSentenceTokenizer PunktParameters PunktLanguageVars PunktToken "
    "PunktTrainer PunktBaseClass PunktTokenizer").split()} | {
    ("nltk.probability", "FreqDist"), ("collections", "defaultdict"),
    ("builtins", "int")}
MODEL_EXACT = {("collections", "defaultdict"), ("collections", "OrderedDict"),
               ("builtins", "int"), ("builtins", "float")}

# config -> {version: (modules, exact)}
CFG = {
    "punkt": {"pre": (["nltk.tokenize.punkt", "nltk.tokenize"], set()),
              "post": ([], PUNKT_EXACT)},
    "model": {"pre": (["numpy", "scipy", "sklearn"], set()),
              "post": (["numpy", "scipy", "sklearn"], MODEL_EXACT)},
    "misconfig_os": {"pre": (["os"], set()), "post": (["os"], set())},
    "misconfig_eval": {"pre": ([], {("builtins", "eval")}),
                       "post": ([], {("builtins", "eval")})},
}


def under(mod, roots):
    for r in roots:
        if mod == r or mod[:len(r) + 1] == r + ".":
            return True
    return False


def resolve(mod, name, syms):
    s = syms.get((mod, name))
    if s is None:
        return "ALLOW_UNRESOLVED"
    kind, tmod, tq, _sink = s
    if kind == "module":
        return "REJECT_MODULE_OBJECT"
    if (tmod, tq) not in SAFE and under(tmod, DENY):
        return "REJECT_REEXPORT_DENIED"
    if (tmod, tq) in DENIED_G:
        return "REJECT_DENIED_RESOLVED"
    return "ALLOW"


def pre(cfg, mod, name, syms):
    mods, exact = CFG[cfg]["pre"]
    return "ALLOW" if (mod, name) in exact or under(mod, mods) \
        else "REJECT_NOT_ALLOWLISTED"


def post(cfg, mod, name, syms):
    mods, exact = CFG[cfg]["post"]
    rules = [
        ("REJECT_DUNDER", lambda: len(name) >= 4 and name[:2] == "__"
         and name[-2:] == "__"),
        ("REJECT_DENIED_GLOBAL", lambda: (mod, name) in DENIED_G),
    ]
    for label, pred in rules:
        if pred():
            return label
    if (mod, name) in exact:
        if under(mod, DENY) and (mod, name) not in SAFE:
            return "REJECT_ALLOWED_BUT_DENIED_MODULE"
        return resolve(mod, name, syms)
    if under(mod, DENY):
        return "REJECT_DENIED_MODULE"
    if under(mod, mods):
        return resolve(mod, name, syms)
    return "REJECT_NOT_ALLOWLISTED"


def rows(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            yield line.split("\t")


def main():
    syms = {(r[0], r[1]): tuple(r[2:]) for r in rows(ROOT / "fixtures/symbols.tsv")}
    out = ["id\tversion\tlabel\tsink"]
    for r in rows(ROOT / "fixtures/cases.tsv"):
        cid, _cls, cfg, _enc, mod, name = r[:6]
        for ver, fn in (("pre", pre), ("post", post)):
            label = fn(cfg, mod, name, syms)
            sink = "-"
            if label.startswith("ALLOW") and (mod, name) in syms:
                sink = syms[(mod, name)][3]
            out.append(f"{cid}\t{ver}\t{label}\t{sink}")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
