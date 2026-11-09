"""Name-only model of AllowlistUnpickler.find_class before and after c3e3711.

Nothing is imported or resolved: a global is a pair of strings. The
post-resolution checks of ``_resolve`` use a hand-written symbol table
(``fixtures/symbols.tsv``) instead of ``getattr``. Every constant below is
copied from the saved diff ``CVE-2026-79657_nltk_c3e37113742a.diff``; the
``DIFF_*`` comments give its line numbers (``cat -n``).
"""
from __future__ import annotations

from dataclasses import dataclass

# DIFF L62-93 (+): _DENIED_MODULE_PREFIXES
DENIED_MODULE_PREFIXES = (
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil", "signal",
    "pty", "popen2", "commands", "ctypes", "importlib", "runpy", "builtins",
    "webbrowser", "pdb", "bdb", "code", "codeop", "multiprocessing",
    "asyncio", "threading", "pickle", "numpy.f2py", "numpy.ctypeslib",
    "numpy.distutils", "numpy.testing", "nltk.tokenize.repp",
    "nltk.internals",
)

# DIFF L101-117 (+): _DENIED_GLOBALS
DENIED_GLOBALS = frozenset({
    ("numpy", "load"), ("numpy", "loadtxt"), ("numpy", "fromfile"),
    ("numpy", "fromregex"), ("numpy", "genfromtxt"), ("numpy", "save"),
    ("numpy", "savez"), ("numpy", "savez_compressed"), ("numpy", "savetxt"),
    ("numpy", "memmap"), ("numpy", "DataSource"), ("numpy", "vectorize"),
    ("pandas", "read_pickle"),
})

# DIFF L252-266 (+): _SAFE_DENIED_GLOBALS
SAFE_DENIED_GLOBALS = frozenset(
    ("builtins", n) for n in (
        "int", "float", "complex", "bool", "str", "bytes", "list", "tuple",
        "dict", "set", "frozenset",
    )
)


@dataclass(frozen=True)
class Config:
    name: str
    allowed_modules: tuple = ()
    allowed_globals: tuple = ()
    diff_lines: str = ""


# Caller configurations, before (pre) and after (post) the fix.
CONFIGS = {
    # DIFF L440 (-): _PUNKT_ALLOWED_MODULES; L475 (-) passes it as modules.
    ("punkt", "pre"): Config("punkt", ("nltk.tokenize.punkt", "nltk.tokenize"),
                             (), "L440,L475"),
    # DIFF L448-460 (+), L476 (+): exact pairs only.
    ("punkt", "post"): Config("punkt", (), (
        ("nltk.tokenize.punkt", "PunktSentenceTokenizer"),
        ("nltk.tokenize.punkt", "PunktParameters"),
        ("nltk.tokenize.punkt", "PunktLanguageVars"),
        ("nltk.tokenize.punkt", "PunktToken"),
        ("nltk.tokenize.punkt", "PunktTrainer"),
        ("nltk.tokenize.punkt", "PunktBaseClass"),
        ("nltk.tokenize.punkt", "PunktTokenizer"),
        ("nltk.probability", "FreqDist"),
        ("collections", "defaultdict"),
        ("builtins", "int"),
    ), "L448-460,L476"),
    # DIFF L15 (context) and L30 (-): transitionparser model, modules only.
    ("model", "pre"): Config("model", ("numpy", "scipy", "sklearn"), (),
                             "L15,L30"),
    # DIFF L15, L17-22 (+), L31-35 (+).
    ("model", "post"): Config("model", ("numpy", "scipy", "sklearn"), (
        ("collections", "defaultdict"), ("collections", "OrderedDict"),
        ("builtins", "int"), ("builtins", "float"),
    ), "L15,L17-22,L31-35"),
    # DIFF L343 / L346: a caller that (mistakenly) allows os or builtins.eval.
    ("misconfig_os", "pre"): Config("misconfig_os", ("os",), (), "L343"),
    ("misconfig_os", "post"): Config("misconfig_os", ("os",), (), "L343"),
    ("misconfig_eval", "pre"): Config("misconfig_eval", (),
                                      (("builtins", "eval"),), "L346"),
    ("misconfig_eval", "post"): Config("misconfig_eval", (),
                                       (("builtins", "eval"),), "L346"),
}


@dataclass(frozen=True)
class Symbol:
    """Hand-written stand-in for the object find_class would resolve."""

    kind: str          # class | function | module
    true_module: str
    true_qualname: str
    sink: str          # "-" or a short sink description


def _prefix(module: str, names) -> bool:
    return any(module == n or module.startswith(n + ".") for n in names)


def module_denied(module: str) -> bool:
    # DIFF L156-160 (+): exact module or prefix + "."
    return _prefix(module, DENIED_MODULE_PREFIXES)


def decide_pre(cfg: Config, module: str, name: str) -> tuple[str, str]:
    """DIFF L201-202 (-): allowlist checked on the module string only."""
    if (module, name) in set(cfg.allowed_globals) or _prefix(
            module, cfg.allowed_modules):
        return "ALLOW", "L201-202"
    return "REJECT_NOT_ALLOWLISTED", "L243-245"


def _resolve_post(module, name, symbols):
    """DIFF L168-198 (+): checks on the resolved object (symbol table)."""
    sym = symbols.get((module, name))
    if sym is None:
        return "ALLOW_UNRESOLVED", "L176"
    if sym.kind == "module":
        return "REJECT_MODULE_OBJECT", "L177-181"
    key = (sym.true_module, sym.true_qualname)
    if key not in SAFE_DENIED_GLOBALS and module_denied(sym.true_module):
        return "REJECT_REEXPORT_DENIED", "L186-191"
    if key in DENIED_GLOBALS:
        return "REJECT_DENIED_RESOLVED", "L192-197"
    return "ALLOW", "L198"


def decide_post(cfg: Config, module: str, name: str,
                symbols=None) -> tuple[str, str]:
    """DIFF L203-245 (+): the four guards, then the allowlists."""
    symbols = symbols or {}
    if "." in name:
        return "REJECT_DOTTED", "L205-209"
    if name.startswith("__") and name.endswith("__"):
        return "REJECT_DUNDER", "L213-216"
    if (module, name) in DENIED_GLOBALS:
        return "REJECT_DENIED_GLOBAL", "L219-223"
    if (module, name) in set(cfg.allowed_globals):
        if module_denied(module) and (module, name) not in SAFE_DENIED_GLOBALS:
            return "REJECT_ALLOWED_BUT_DENIED_MODULE", "L227-234"
        return _resolve_post(module, name, symbols)
    if module_denied(module):
        return "REJECT_DENIED_MODULE", "L236-240"
    if _prefix(module, cfg.allowed_modules):
        return _resolve_post(module, name, symbols)
    return "REJECT_NOT_ALLOWLISTED", "L243-245"


def decide(version: str, config: str, module: str, name: str,
           symbols=None) -> tuple[str, str]:
    cfg = CONFIGS[(config, version)]
    if version == "pre":
        return decide_pre(cfg, module, name)
    return decide_post(cfg, module, name, symbols)


def sink_reached(label: str, module: str, name: str, symbols) -> str:
    """A sink counts as reached only if the global is allowed and the
    symbol table marks it as a sink. Nothing is ever called."""
    if not label.startswith("ALLOW"):
        return "-"
    sym = symbols.get((module, name))
    return sym.sink if sym else "-"


def load_symbols(path) -> dict:
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
            mod, nm, kind, tmod, tq, sink = line.rstrip("\n").split("\t")
            out[(mod, nm)] = Symbol(kind, tmod, tq, sink)
    return out
