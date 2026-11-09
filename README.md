# cortex9-nltk-pickle-allowlist-prefix-model

Offline, inert model of **CVE-2026-79657** (GHSA-x99w-6fgc-pmfw, CWE-502 /
CWE-693): NLTK's `AllowlistUnpickler` trusted whole module **prefixes**
(`nltk.tokenize`, `numpy`, ...), so a pickle could name an in-namespace gadget
such as `nltk.tokenize.repp.ReppTokenizer._execute` (subprocess) or
`numpy.f2py.crackfortran.myeval` (eval). The fix, commit
`c3e37113742a1ebeeb4f2ca58941f320f98805ea` (NLTK 3.10.3), adds exact
`(module, qualname)` allowlists, a denylist of module prefixes and globals,
and rejects dunder names.

**Scope.** The same commit also rejects dotted names (diff L203-209). Its
comments attribute that guard to a separate advisory, GHSA-4489 (L140, L204,
L208, L286), so it is a separate change, **out of scope** here and not
modelled. Only the CVE-2026-79657 / GHSA-x99w part is modelled.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What runs and what never runs

- `src/c9nltk/opstream.py` reads a pickle **statically** with
  `pickletools.genops` and a symbolic stack, and returns the
  `(module, name)` pairs it names. `pickle.loads`, `pickle.Unpickler`,
  `find_class`, `eval`, `exec` and imports of the named modules are never
  used; `tests/test_adversarial.py` checks this on the AST and with mocks.
- `src/c9nltk/policy.py` applies the `find_class` decision **before**
  (`pre`, diff lines L201-202) and **after** the fix (`post`, L210-245) to
  those strings. The post-resolution checks of `_resolve` (L168-198) use a
  hand-written symbol table (`fixtures/symbols.tsv`) instead of `getattr`.
- No NLTK, numpy or sklearn is installed or imported. Fixture pickles carry
  the inert argument `"x"`.

## Differential evidence

Every row of `results/cases.csv` names the rule that decided it, as a line
range of the saved diff `CVE-2026-79657_nltk_c3e37113742a.diff` (see
[SOURCES.md](SOURCES.md)).

| Class | n | pre allowed | post allowed | pre: named sink reachable | post: sink reachable |
|---|---|---|---|---|---|
| pos (gadgets) | 10 | 10 | 0 | 8 | 0 |
| neg (legitimate, unchanged) | 6 | 6 | 6 | 0 | 0 |
| compat (legitimate, newly allowed) | 4 | 0 | 4 | 0 | 0 |

Examples: `ReppTokenizer._execute` under the Punkt list: pre `ALLOW`
(prefix `nltk.tokenize`, L440), post `REJECT_DENIED_MODULE` (L236-240,
`nltk.tokenize.repp` is a denied module prefix).
`numpy.f2py.crackfortran.myeval` under the transition-parser list: pre
`ALLOW` (prefix `numpy`, L15), post `REJECT_DENIED_MODULE` (L236-240).
`numpy.load`: post `REJECT_DENIED_GLOBAL` (L219-223).

`compat` rows (`collections.defaultdict`, `builtins.int`,
`nltk.probability.FreqDist` under the Punkt list) are rejected by the pre
prefix list and allowed by the post exact list. That is a model observation
about the allowlists, **not verified** against real Punkt pickles.

## Run

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/gen_results.py /tmp/r && diff -r results /tmp/r
PYTHONPATH=src python3 -m c9nltk model <hex-of-a-pickle>
```

`fixtures/expected.tsv` is produced by `scripts/derive_expected.py`, a
second implementation written from the diff without importing `src/`. The
hand labels in `fixtures/cases.tsv`, the model and that derivation must
all agree. Python 3.10+ standard library only.

A model is not a finding. See [LIMITATIONS.md](LIMITATIONS.md).
License: Apache-2.0.
