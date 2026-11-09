# Limitations

- **Names, not objects.** The model decides on `(module, name)` strings.
  Nothing is imported or resolved, so it cannot say whether a name exists
  in a given NLTK, numpy or sklearn version.
- **Symbol table.** `_resolve` (diff L168-198) inspects the real object
  (`__module__`, `__qualname__`, module type). Here those come from
  `fixtures/symbols.tsv`, written by hand. Names without an entry end as
  `ALLOW_UNRESOLVED`: the modelled guards passed, the resolution step is not
  modelled. Sink notes in that table come from comments and tests in the
  saved diff, not from running the gadgets.
- **Dotted names: out of scope.** The dotted-name guard of the same commit
  (diff L203-209) is attributed by the diff's comments to GHSA-4489 (L140,
  L204, L208, L286), a separate change, and is **not modelled**. The post
  model therefore returns `ALLOW_UNRESOLVED` for e.g. `sklearn` +
  `os.system`; that says nothing about real NLTK 3.10.3, where that guard
  exists. In CPython, `find_class` follows dotted names only for protocol
  >= 4; not modelled either.
- **Attribution by theme.** The dunder guard (L210-216), the exact denied
  globals check (L217-223) and the `_resolve` checks (L168-198) carry no
  explicit advisory tag in the diff; they are attributed to GHSA-x99w here by
  theme (namespace gadgets), not by an explicit statement. The module
  denylist, the allowed-but-denied guard and the backstop do say
  "GHSA-x99w" (L61, L144, L225, L239).
- **Static extractor.** `opstream.extract_globals` follows strings through
  the stack and memo. A `STACK_GLOBAL` whose operands it cannot follow is
  reported as `Unknown` (fail closed), not guessed. It is not a complete
  pickle VM.
- **Not verified:** the full list of gadgets under `numpy`, `scipy` or
  `sklearn`; other loaders in NLTK; whether real Punkt pickles carry
  `collections.defaultdict` / `builtins.int` / `FreqDist` (the `compat`
  rows).
- **Advisory text.** The GHSA body says "Patched versions: Not yet patched"
  and "Current source v3.10.0-rc2" (written at report time) while its
  structured data says `<= 3.10.2` / `3.10.3`. This repo uses the
  structured data. The commit also cites a second advisory, "GHSA-4489",
  for the dotted-name guard; its full ID and any CVE for it are not in the
  saved sources and are not claimed here.
- This is not a finding and not an exploit: no pickle is ever loaded.
  Nothing is attributed beyond the commit and advisory in SOURCES.md.
