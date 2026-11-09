# Limitations

- **Names, not objects.** The model decides on `(module, name)` strings.
  Nothing is imported or resolved, so it cannot say whether a name exists
  in a given NLTK, numpy or sklearn version.
- **Symbol table.** `_resolve` (diff L168-198) inspects the real object
  (`__module__`, `__qualname__`, module type). Here those come from
  `fixtures/symbols.tsv`, written by hand. Names without an entry end as
  `ALLOW_UNRESOLVED`: the four guards passed, the resolution step is not
  modelled. Sink notes in that table come from comments and tests in the
  saved diff, not from running the gadgets.
- **Dotted names.** In CPython, `find_class` follows dotted names only for
  protocol >= 4. The pre policy here returns `ALLOW` for any dotted name the
  allowlist accepts; whether resolution then succeeds is not modelled.
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
