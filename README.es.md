# cortex9-nltk-pickle-allowlist-prefix-model

Modelo offline e inerte de **CVE-2026-79657** (GHSA-x99w-6fgc-pmfw, CWE-502 /
CWE-693): el `AllowlistUnpickler` de NLTK confiaba en **prefijos** de módulo
enteros (`nltk.tokenize`, `numpy`, ...), así que un pickle podía nombrar un
gadget dentro del espacio permitido, como
`nltk.tokenize.repp.ReppTokenizer._execute` (subprocess) o
`numpy.f2py.crackfortran.myeval` (eval). El fix, commit
`c3e37113742a1ebeeb4f2ca58941f320f98805ea` (NLTK 3.10.3), agrega listas
exactas `(módulo, qualname)`, una denylist de prefijos y de globals, y
rechaza nombres dunder.

**Alcance.** El mismo commit también rechaza nombres con punto (L203-209 del
diff). Sus comentarios atribuyen esa guarda a otro advisory, GHSA-4489 (L140,
L204, L208, L286): es un cambio aparte, **fuera de alcance** y no modelado.
Solo se modela la parte de CVE-2026-79657 / GHSA-x99w.

Inglés: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Qué se ejecuta y qué nunca

- `src/c9nltk/opstream.py` lee el pickle de forma **estática** con
  `pickletools.genops` y una pila simbólica, y devuelve los pares
  `(módulo, nombre)` que nombra. Nunca usa `pickle.loads`,
  `pickle.Unpickler`, `find_class`, `eval`, `exec` ni importa los módulos
  nombrados; `tests/test_adversarial.py` lo comprueba sobre el AST y con mocks.
- `src/c9nltk/policy.py` aplica la decisión de `find_class` **antes**
  (`pre`, líneas L201-202 del diff) y **después** del fix (`post`, L210-245)
  sobre esas cadenas. Los chequeos posteriores a la resolución de `_resolve`
  (L168-198) usan una tabla de símbolos escrita a mano
  (`fixtures/symbols.tsv`) en lugar de `getattr`.
- No se instala ni se importa NLTK, numpy ni sklearn. Los pickles de las
  fixtures llevan el argumento inerte `"x"`.

## Evidencia diferencial

Cada fila de `results/cases.csv` nombra la regla que la decidió, como rango
de líneas del diff guardado (ver [SOURCES.md](SOURCES.md)).

| Clase | n | pre permite | post permite | pre: sink alcanzable | post: sink alcanzable |
|---|---|---|---|---|---|
| pos (gadgets) | 10 | 10 | 0 | 8 | 0 |
| neg (legítimos, sin cambio) | 6 | 6 | 6 | 0 | 0 |
| compat (legítimos, ahora permitidos) | 4 | 0 | 4 | 0 | 0 |

Las filas `compat` (`collections.defaultdict`, `builtins.int`,
`nltk.probability.FreqDist` con la lista de Punkt) las rechaza la lista de
prefijos pre y las permite la lista exacta post. Es una observación del
modelo sobre las listas, **no verificada** contra pickles reales de Punkt.

## Uso

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

`fixtures/expected.tsv` lo genera `scripts/derive_expected.py`, una segunda
implementación escrita desde el diff sin importar `src/`. Las etiquetas a
mano de `fixtures/cases.tsv`, el modelo y esa derivación tienen que
coincidir. Solo biblioteca estándar de Python 3.10+.

Un modelo no es un hallazgo. Ver [LIMITATIONS.md](LIMITATIONS.md).
Licencia: Apache-2.0.
