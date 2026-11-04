# Revisión de seguridad — Gatekeeper 0.9.2 (ronda 5)

**Fecha:** 2026-10-29/30 · **Autor/a:** Claude (Anthropic) · **Commit:** `394a167`

---

## Verificación de los parches

NUEVO-3, NUEVO-5 y NUEVO-6 (rondas 3 y 4) están **realmente cerrados**:

- `python .audit/PACK-REVISOR/ejecutar_pocs.py` completo: **48 pasan, 1
  falla** (el hallazgo nuevo de abajo), **0 regresiones**.
- `ruff`, `mypy --strict`, `bandit`: limpios.
- `pytest`: **3037 passed, 25 skipped**, sin fallos.
- Revisé el diff de `rules.py` línea por línea, no solo el resultado de los
  tests: recalculé a mano **todos** los literales octales nuevos de `ssrf`
  (incluidas las formas de entero-octal-único que no había probado antes,
  `025177524776` etc.) y los nueve dan la IP correcta. Buen trabajo en ese
  parche — cubristeis más formas de las que yo había pedido.

Esta ronda busqué por tres frentes nuevos: falsos positivos del propio
parche de NUEVO-3 (nadie lo había comprobado todavía), coste de ReDoS del
regex ampliado, y manipulación del método HTTP (*override headers*, verbos
en minúsculas).

---

## Hallazgo nuevo

### NUEVO-7 — El parche de NUEVO-3 bloquea código Python/JS legítimo y extremadamente común

**Gravedad:** Media-Alta (no es un bypass, es sobre-bloqueo con alcance muy amplio) · **Vector:** cualquier valor reflejado o aceptado que contenga código fuente como dato

**Qué pasa**

Para cerrar NUEVO-3, el patrón de XSS DOM se amplió para reconocer
`self`, `parent`, `frames` y `globalThis` como identificadores peligrosos,
además de `document`/`window`/`top`/`eval`. El problema: **`self.` es
posiblemente la secuencia de dos palabras más común que existe en código
Python orientado a objetos** — toda clase que define `__init__` y guarda un
atributo de instancia la usa (`self.nombre = x`, `self.id`,
`self.assertEqual(...)` en cualquier test unitario de `unittest`). Y
`parent.postMessage(...)` es, precisamente, el patrón **estándar y
documentado por MDN** para comunicación legítima entre `iframe`s — lo
contrario de un ataque.

**Impacto (medido)**

Contra una app que simplemente muestra un fragmento de código como texto
(un visor de *tracebacks*, una herramienta de soporte, un editor
educativo, un *pastebin*, un sistema de revisión de código — cualquier
backend que trate código como dato, no como algo a ejecutar):

```
def test_suma(self):
    self.assertEqual(suma(2,2), 4)                    -> 403

class Usuario:
    def __init__(self):
        self.nombre = ''
        self.id = None                                 -> 403

window.addEventListener('message', (e) => {
  if (e.source === parent) handle(e);
});                                                      -> 403

if (frames.length > 0) { console.log('ok'); }           -> 403
```

Ninguno de estos cuatro fragmentos contiene nada remotamente parecido a un
intento de ataque.

**Por qué lo puntúo tan alto como un bypass, aunque sea lo contrario**

Es importante no tratar esto como "solo molesto". Un falso positivo de
esta frecuencia (una secuencia de dos palabras que aparece en una fracción
enorme de todo el código Python escrito) hace que el middleware sea
**literalmente inviable** para una categoría entera de aplicaciones
legítimas — y, dado el contexto en el que estás construyendo esto
(formación en desarrollo, herramientas educativas), es exactamente el tipo
de aplicación que más probablemente lo adopte. Un WAF que un desarrollador
tiene que desactivar a las dos horas de probarlo porque bloquea su propio
código no protege nada: simplemente deja de usarse.

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python .audit/PACK-REVISOR/ejecutar_pocs.py r5_fp_self_parent
```

**Corrección propuesta**

El proyecto ya tiene el patrón correcto para este problema: cuando
amplió `self` dentro de NUEVO-3, le puso una exclusión `(?!_)` para no
pillar `self._privado` (atributos "privados" por convención de Python).
Hace falta la misma idea, pero más amplia: `self.` seguido de un
identificador que no empiece por mayúscula ni corresponda a una API
sensible conocida no debería dispararse solo. Dos caminos concretos:

1. **Quitar `self` de la lista genérica** y tratarlo aparte: solo marcar
   `self.document`/`self.window`/`self.eval` (el caso real de XSS DOM
   relevante — un *framework* de componentes donde `self` referencia al
   objeto global), no cualquier `self.algo`.
2. O, más simple y más alineado con cómo ya tratáis `$gt`/`$lt` en
   `nosql`: **retirar `self`, `parent` y `frames` de esta ronda de
   ampliación** y dejar solo `document`/`window`/`top`/`globalThis`/`eval`
   con las formas de corchetes y *optional chaining* — que es lo que de
   verdad motivó NUEVO-3 y donde la tasa de falsos positivos en código
   legítimo es mucho menor (nadie escribe `document.algo` ni
   `window.algo` por rutina en backend).

Antes de decidir cuál, corrédlo contra vuestro propio corpus de benignos
(`tests/corpus/benign.txt` y el retenido) — si ya tenéis fragmentos de
código Python/JS ahí, esto debería haber aparecido en
`evaluate.py --check` o `evaluate_heldout.py --check`. Si no aparece, vale
la pena añadir snippets de código real (no solo texto en prosa) a esos
corpus, porque es justo el tipo de contenido que un escenario educativo
como el vuestro va a recibir constantemente.

**Estado:** cerrado ✅ (retirados `self`, `parent` y `frames` de la lista genérica de `xss[6]`, conservando `document`, `window`, `globalThis`, `top`, `location` y `eval`/`setTimeout`/`setInterval` por punto, corchetes u *optional chaining*; añadidos fragmentos de código Python/JS benigno al corpus de desarrollo `corpus/benign.json` y tests de regresión en `tests/test_rules.py`)

---

## Lo que esta ronda comprobó y descartó

- **Manipulación del método HTTP**: cabeceras `X-HTTP-Method-Override`,
  `X-Method-Override`, `X-HTTP-Method`, y verbos en minúscula
  (`post`/`Post`). Ninguna cambia el veredicto — el middleware siempre
  evalúa el método ASGI real, no lo que diga una cabecera.
- **ReDoS en el regex de XSS ampliado**: más alternancia no significa
  automáticamente más riesgo. Medí 150-380 ms con entradas hostiles de
  0,5-1,6 MB (`self.` repetido medio millón de veces, *optional-chaining*
  anidado 300.000 veces) — más lento que antes del parche, pero sigue
  siendo lineal con el tamaño, no exponencial, y muy por debajo de
  `max_inspection_ms` (1000 ms) con el `max_body_size` por defecto (256
  KiB). No es un hallazgo, es una nota: si seguís ampliando este patrón,
  vale la pena vigilar el coste, no solo la cobertura.

---

## Veredicto

No doy una puntuación nueva esta ronda porque el hallazgo que encontré no
es del mismo tipo que los anteriores — es sobre-bloqueo, no un bypass — y
mezclarlo en la misma escala de 1 a 100 que vengo usando (pensada para
"cuánto se cuela") daría una cifra que no compararía bien con las rondas
previas. Lo que sí digo con claridad: **NUEVO-7 es, en términos prácticos,
más urgente que cualquiera de los hallazgos de seguridad pura que he
encontrado hasta ahora**, porque afecta a si la herramienta es usable en
absoluto para una parte realista de sus usuarios objetivo.
