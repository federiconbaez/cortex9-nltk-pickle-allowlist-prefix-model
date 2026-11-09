# Guía práctica (8 niveles)

Ejercicios **offline** sobre listas de permitidos de pickle. Ningún pickle
se carga: solo se leen los opcodes y se decide sobre nombres. Úsalos en tu
propia máquina o en tu propio laboratorio (por ejemplo, una VM de práctica
tuya); nunca contra sistemas de terceros. Cada respuesta está en
`tests/test_practice.py` (`test_level_N`).

Ayuda: `PYTHONPATH=src python3 -m c9nltk <config> <hex>`; el hex sale de
`opstream.build_stack_global(módulo, nombre).hex()`.

**Básico**

1. **Leer opcodes sin cargar.** ¿Qué par `(módulo, nombre)` extrae
   `extract_globals` de un pickle que nombra `PunktParameters`?
   ¿Por qué `pickletools.genops` no ejecuta nada?
2. **Prefijo frente a lista exacta.** `PunktParameters` con la lista de
   Punkt: ¿qué deciden pre y post? (ambos `ALLOW`)

**Intermedio**

3. **Gadget dentro del espacio permitido.** `numpy.f2py.crackfortran.myeval`
   con la lista del transition parser. (pre `ALLOW`, post
   `REJECT_DENIED_MODULE`, L236-240)
4. **Gadget por qualname.** `nltk.tokenize.repp` + `ReppTokenizer._execute`
   con la lista de Punkt. ¿Qué lo frena en el post? (`REJECT_DENIED_MODULE`,
   L236-240; la guarda de nombres con punto es de GHSA-4489 y queda fuera de
   alcance)
5. **Sink en el mismo módulo.** `numpy.load`: el módulo `numpy` está
   permitido. (post `REJECT_DENIED_GLOBAL`, L219-223)

**Avanzado**

6. **Defensa en profundidad.** Un llamador que por error permite
   `("builtins", "eval")` exacto. (post `REJECT_ALLOWED_BUT_DENIED_MODULE`,
   L227-234)
7. **El costo de compatibilidad.** `collections.defaultdict` con la lista de
   Punkt: pre lo rechaza, post lo permite. ¿Qué dice eso de los pickles
   reales de Punkt? (observación **no verificada**)
8. **Reexportes.** Agrega a una tabla de símbolos un `numpy.alias` que
   resuelve a `os.system`. ¿Qué regla de `_resolve` lo frena?
   (`REJECT_REEXPORT_DENIED`, L186-191)

Más allá: agrega un caso a `fixtures/cases.tsv` con tus etiquetas a mano,
regenera `fixtures/expected.tsv` con `scripts/derive_expected.py` y comprueba
que el modelo, tu etiqueta y la derivación coinciden.
