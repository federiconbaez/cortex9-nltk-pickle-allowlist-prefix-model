# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only on 2026-11-09. SHA-256 re-verified against
`sources/cve2026/SHA256SUMS` when this repo was built.

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| Fix commit c3e37113742a1ebeeb4f2ca58941f320f98805ea (2026-08-11, "fix(security): close AllowlistUnpickler namespace + dotted-name pickle RCE (CWE-502)") as `diffs/CVE-2026-79657_nltk_c3e37113742a.diff` | https://github.com/nltk/nltk/commit/c3e37113742a1ebeeb4f2ca58941f320f98805ea | every constant and rule in `src/c9nltk/policy.py`; line numbers `Lnnn` are `cat -n` lines of this file | 6a9b328f995b90c9a6e88153bebd2698664696f224c2364c3e95aa6f7d5e29b1 |
| GHSA-x99w-6fgc-pmfw (`ghsa_rec/CVE-2026-79657.json`) | https://github.com/nltk/nltk/security/advisories/GHSA-x99w-6fgc-pmfw | affected `<= 3.10.2`, patched `3.10.3`, CWE-502/CWE-693, gadget names | 5138366211f2d114b5e51a419e3daacb31b730f71c514800168b1cf8c7c7c5ca |
| NVD CVE-2026-79657 (`nvd/CVE-2026-79657.json`, status Analyzed) | https://nvd.nist.gov/vuln/detail/CVE-2026-79657 | the CVE ID exists and links the commit | 514e22d09019a0d3616aebf6e4f2f325f0cef3658a6ced4583a55d045184ca9f |

`fixtures/diff_excerpt.txt` is lines 62-117 of the diff with the leading
`+` removed; a test checks the model's denylists against it.

No source contained instructions addressed to a tool or agent (grep for
injection phrases and invisible Unicode over the three files).
