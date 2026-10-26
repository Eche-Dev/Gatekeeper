# AGENTS.md

Cómo se trabaja en este repositorio. No es documentación del **producto**
(eso está en `docs/`): es el método con el que se toca el código, y las reglas
que han salido de equivocarse.

El proyecto es **Gatekeeper**, un middleware ASGI de seguridad para FastAPI y
Starlette. El paquete vive en `gatekeeper-v0.3/gatekeeper/`.

## La regla que manda: verificar, no creer

Un informe, una auditoría o una hipótesis **no son evidencia**. Antes de
escribir una línea de código:

1. **Reproduce** el caso contra el código real. Un falso negativo que no se
   reproduce no existe; un hallazgo de una IA hay que confirmarlo.
2. **Mide** el alcance: cuántas detecciones dependen **solo** de la firma que
   vas a tocar. Sin ese número, cualquier endurecimiento es una apuesta.
3. **Escribe el test primero**, que falla, y luego el arreglo.
4. **Mide después**: corpus propio, corpus retenido, corpus externo de CRS
   payload a payload. Si algo se pierde, el arreglo no vale.

En `.audit/` queda la evidencia reproducible de cada fase (scripts, volcados
antes/después y los informes de medición). No es código del paquete: no se
publica ni se importa.

## Las reglas del proyecto

- **Los falsos positivos se documentan, no se esconden.** Un límite que se
  acepta va en el corpus con `known_fp` y su motivo, y sale en el informe.
  "0 falsos positivos" sin lista de límites es propaganda, no una medida.
- **El corpus retenido se mide, no se ajusta.** `corpus/heldout_*` existe para
  decir la verdad: si un fallo del corpus retenido "se arregla" con una firma
  escrita para él, el corpus deja de servir para nada. El corpus de
  desarrollo (`corpus/attacks.json`, `corpus/benign.json`) sí se puede usar
  para ajustar.
- **Nada de fail-open donde el atacante pueda colarse.** Agotar un presupuesto a
  propósito para que el payload quede sin inspeccionar sería un bypass: los
  presupuestos fallan cerrados (413).
- **El log nunca lleva valores.** Solo la regla, el campo (su nombre, saneado
  y acotado) y el patrón. El nombre del campo lo elige el atacante.
- **Los cambios de comportamiento se documentan** en las notas de versión, con
  la lista de lo que deja de detectarse. Un WAF que cambia de comportamiento
  en silencio es un WAF que rompe a alguien sin avisarle.
- **Sin cambios de API pública en una minor.** Si hace falta, es una major.
- **Los secretos no se registran, no se imprimen y no se piden.** Ni en el
  log, ni en un issue, ni en un test.

## Cómo se trabaja

- **Idioma**: los comentarios, la documentación, los mensajes de commit y
  los nombres de los tests van en **español**. Los identificadores del código
  (funciones, clases, variables) van en **inglés**: el código se lee en
  cualquier parte del mundo.
- **Commits**: en español, descriptivos, con el *qué* y el *por qué*. El
  mensaje va en un fichero (`git commit -F`), no en la línea de comandos.
- **Ramas**: `objetivo100` lleva el trabajo en curso; `main` es lo publicado.
- **Una fase, un PR**: la doc y el código van juntos, pero en commits
  separados si son cosas distintas.

## Comandos

Desde `gatekeeper-v0.3/gatekeeper/`:

```bash
pip install -e ".[dev,servers]"

pytest -q --timeout=300                    # la suite (2749 tests)
pytest --cov=gatekeeper --cov-fail-under=90 -q   # cobertura (umbral 90 %)
ruff check .                               # estilo
mypy                                       # tipos estrictos (src/gatekeeper)
bandit -r src -q                           # análisis estático de seguridad
python tools/check_docs.py                 # la doc dice la verdad
python tools/evaluate.py --check           # detección y FP (propio + CRS)
python tools/evaluate_heldout.py --check   # generalización (corpus retenido)
python tools/evaluate_cross.py --check     # modo cruzado
python tools/import_crs.py --check         # procedencia del corpus externo
python -m mkdocs build --strict            # la web se construye sin avisos
python benchmarks/latency.py               # coste por petición
```

## Qué no se toca sin motivo

- **El pre filtro** (`src/gatekeeper/rules.py`): es una OR de literales por
  familia. Si una firma nueva no tiene su literal en la lista, la familia se
  descarta entera. `tests/test_prefilter.py` lo vigila.
- **Los cuantificadores**: `\s*` en vez de `\s{0,16}` es un DoS esperando. Hay
  un test de fuzzing que lo caza.
- **El `+` de un query string**: se traduce a espacio **una sola vez**
  (primera ronda de `decode`). Si se vuelve a aplicar en cada ronda, el
  operador de MySQL se pierde y `sleep(10%2B6)` deja de detectarse.
- **El orden de las rondas de decodificación**: cada ronda deshace lo que
  hizo la anterior. Cambiarlo cambia qué se detecta.

## El plan de 100 puntos

`PLAN-VERIFICADO-100.md` es la lista de fases del proyecto, con su
puntuación y su estado. Cuando se cierra una fase: se actualiza el plan, el
CHANGELOG, el ROADMAP y la puntuación.
