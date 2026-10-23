# Hoja de ruta: llevar Gatekeeper a 100/100 de preparación

## Propósito y alcance

Esta hoja convierte la auditoría de preparación en tareas verificables para llevar
Gatekeeper a **20/20 en cada dimensión evaluada**. La puntuación mide calidad del
producto, facilidad de uso y evidencia disponible; **no significa protección
perfecta ni garantiza que una aplicación sea segura**.

Gatekeeper debe presentarse como una capa adicional para FastAPI/Starlette. No se
debe anunciar como sustituto de validación de entradas, consultas parametrizadas,
un WAF de borde ni un motor compatible con OWASP CRS.

La evaluación inicial se hizo sobre el merge del PR #18, commit
`e14bbd11e74ba0fdea6e1d49832b9a45e06f2748`. Antes de iniciar cada fase, actualizar
el checkout y confirmar el commit efectivo de `main`.

## Estado de continuación — 2026-10-23

**Base verificada:** `main` en `a725cc5` (PR #22), igual a `origin/main`.
El CI de GitHub para ese commit terminó correctamente (run
[39987161952](https://github.com/Eche-Dev/Gatekeeper/actions/runs/39987161952)).

**Hitos integrados:** PR #20 añadió el cruce opt-in entre query y body. PR #22
añadió `corpus/cross.json`, su evaluador separado y una guarda en CI. El modo
cruzado detectó 7/7 ataques divididos y bloqueó 0/15 casos benignos del corpus
de desarrollo. Es una muestra pequeña, no retenida ni representativa de tráfico
real; no se mezcla con las métricas de escaneo individual ni demuestra ausencia
de falsos positivos en producción. `inspect_cross_carrier` sigue desactivado por
defecto.

**Verificación local en Windows, Python 3.14.8:** `ruff check .`, `mypy`,
`bandit -r src -q`, `python tools/evaluate.py --check`,
`python tools/evaluate_cross.py --check`, `python tools/import_crs.py --check`,
`mkdocs build --strict`, `python -m build` y `twine check dist/*` pasaron.
`pytest --cov=gatekeeper --cov-fail-under=90`: 2066 tests pasaron, cobertura
total 95,57%. La matriz CI de Python 3.10–3.13 pasa en GitHub; localmente solo
se ejecutó Python 3.14.8.

**Revisión de verificación (2026-10-23, posterior a esa entrada).** Se volvió a
ejecutar todo el conjunto sobre `a725cc5` y se contrastó cada casilla con el
código, no con el README. Resultado: todo lo anterior se reproduce. Además:

- Se detectó y corrigió un bug real: `examples/gatekeeper.yaml` no era YAML
  válido (`redis_prefix: gatekeeper:rl:` sin comillas rompía el parser). El
  ejemplo que el plan exige que sea copiable no se podía cargar.
- Se añadió `tests/test_limites_body_ratelimit.py` (11 tests) y
  `tests/test_docs_examples.py` (20 tests): los primeros cubren los límites de
  confianza del body y del rate limit que el plan pedía; los segundos hacen que
  los ejemplos de la documentación se ejecuten en CI (van dentro de la corrida
  de `pytest`, que el workflow ya invoca).
- Total tras los cambios: **2097 tests, 95,85% de cobertura**, ruff/mypy/bandit
  limpios, corpus y cruce en verde, wheel construido e instalado en un venv
  limpio con los extras `redis` y `yaml`.
- Pendiente real detectado: el código y los tests están en mucho mejor estado
  que lo que el plan reconocía, pero siguen sin existir la guía rápida
  copiable, la guía de despliegue por topología, la evaluación retenida y la
  revisión de seguridad independiente. Ver las casillas de las secciones 2, 4
  y 5.

**Segunda revisión (2026-10-24, rama `feat/plan-verificacion-y-limites`).**
Cerradas las dos casillas de documentación que quedaban: la guía rápida
copiable (`docs/inicio-rapido.md`) y la guía de despliegue por topología
(`docs/despliegue.md`), más la cadena de confianza de proxies de la sección 4.

Lo relevante del método: **lo que las guías prometen está verificado por
tests**, no solo escrito. `tests/test_inicio_rapido.py` ejecuta la app que
define la guía y comprueba los códigos de respuesta (200 normal, 403 ataque);
`tests/test_despliegue.py` fija las afirmaciones de seguridad de la guía
(el límite en memoria se multiplica con los workers, `allow_paths` exime de
inspección pero no del rate limit, el peer no confiable hace que el XFF se
ignore). Si el middleware cambia, la guía deja de ser cierta y falla el
pipeline.

También se corrigió en el camino un fallo de CI que solo se veía en el
pipeline: `tests/test_docs_examples.py` ejecutaba ejemplos de FastAPI sin que
FastAPI estuviera en el extra `dev` (el paquete solo depende de Starlette).
En local pasaba porque el entorno global lo tenía instalado. Ahora FastAPI está
en el extra `dev` y, si faltara, los ejemplos que lo necesitan se omiten con
un motivo explícito.

Total: **2115 tests, 95,99% de cobertura** en Python 3.14.8 y **95,85%** en
3.10.22; ruff, mypy y bandit limpios; corpus y cruce en verde; CI con los 6
jobs en verde sobre `c55e253`.

**Tercera revisión (2026-10-24, rama `feat/plan-verificacion-y-limites`).**
Cerrada la casilla de rate limiting con Redis real. Al probar contra un Redis
de verdad (no contra `fakeredis`, que simula el servidor) aparecieron **dos
bugs que afectan a producción**:

1. **Redis < 6 no funcionaba, y fallaba en silencio.** El cliente `redis-py`
   moderno (8.x) hace handshake RESP3 por defecto, y un Redis 5.x o 6.0 no lo
   entiende (`unknown command HELLO`). La petición fallaba y, como la política
   por defecto es `rate_fail_open=True`, **todas pasaban sin rate limit y sin
   que nada lo indicara**. El extra `[redis]` promete `redis>=5.0`, así que el
   rango prometido no funcionaba. Ahora Gatekeeper fuerza RESP2.
2. **`Retry-After` devolvía un segundo de más** (61 en una ventana de 60 s), y
   además el backend en memoria y el script Lua de Redis **no coincidían**
   entre sí, de modo que cambiar de backend cambiaba la respuesta. Ahora
   ambos devuelven lo mismo, y es lo correcto según la especificación HTTP.

Ambos estaban fuera del alcance de lo que `fakeredis` podía detectar: por eso
el plan pedía "Redis real" y no "más tests con el doble de pruebas".

La nueva suite (`tests/test_redis_real.py`, 13 tests) comprueba lo que la
guía de despliegue promete: que el límite es **global entre workers** (50
clientes contra la misma IP se admiten exactamente los 10 del límite), que el
contador **sobrevive a un reinicio** del proceso, que las IPs distintas no se
pisan, y que Redis caído da 503 con fail-closed y se audita con fail-open. Sin
Redis disponible los tests se omiten con un motivo claro, así que la suite
también pasa en una instalación mínima.

Total: **2128 tests, 95,87% de cobertura** en Python 3.14.8 y 3.10.22; ruff,
mypy y bandit limpios; CI con **7 jobs** en verde (los 4 de Python, `redis`,
`package` y `audit`).

**Puntuaciones:** los valores de partida de cada dimensión que aparecen abajo
son los de la auditoría inicial sobre PR #18; aún no se ha hecho una
reevaluación formal con esta rúbrica. No deben interpretarse como puntuaciones
actuales ni subirse únicamente por el número de tests o reglas.

**Cuarta revisión (2026-10-24, rama `feat/plan-verificacion-y-limites`).**
Cerrada la casilla del corpus retenido de la sección 3. Es la entrega con más
contenido de esta ronda, porque el corpus retenido no solo mide: **encontró
fallos que el corpus de desarrollo no podía ver**.

Se escribió un corpus de 109 ataques y 90 peticiones legítimas **sin mirar las
firmas de las reglas**, y pasó tres cosas:

1. **14 detecciones que fallaban** (13 firmas nuevas + `...//` que se escapaba
   del path traversal). Todas corregidas midiendo: **+13** detecciones en el
   retenido, **+0** falsos positivos en el corpus de desarrollo y en los
   negativos de CRS. Como efecto colateral, la detección sobre CRS sube del
   40,4% al **41,0%** (465/1135).
2. **Un falso positivo real sobre tráfico legítimo**: la regla que busca
   volcados con fecha (`\d{4}/\d{2}/\d{2}/`) saltaba con cualquier ruta con
   fecha, incluidos los **slugs de blog** (`/blog/2026/01/15/titulo`). Eso
   habría bloqueado artículos legítimos en cualquier blog. El corpus de
   desarrollo no lo tenía porque no tenía ni un caso con fecha en la ruta.
3. **Un fallo de las firmas nuevas que ningún corpus corto detectaba**: el pre
   filtro de familias solo se aplica a partir de 128 caracteres, así que las
   firmas nuevas **funcionaban en los corpus cortos y desaparecían en los
   largos**. Añadidos los literales que faltaban y una regresión que mete cada
   payload detrás de 200 caracteres de relleno.

Además, el test que comprueba que el retenido no se solape con el desarrollo
encontró que **28 payloads eran idénticos byte a byte** (los había escrito
siguiendo las técnicas canónicas, que son las mismas). Se sustituyeron por
variantes distintas: sin eso, el corpus retenido habría medido memoria y no
generalización, que es justo lo que debe evitar.

Resultado final: **2339 tests**, corpus retenido en **103/109 (94,5%)** con
**0** falsos positivos sin documentar, y cuatro evaluadores en CI (desarrollo,
retenido, cruzado y procedencia de CRS).

**Puntuaciones:** los valores de partida de cada dimensión que aparecen abajo
son los de la auditoría inicial sobre PR #18; aún no se ha hecho una


## Prioridad inmediata

Las tareas inmediatas de la auditoría original ya se completaron en la PR #20:

- [x] **Conectar y probar el cruce entre query y body.** Integrado en el
  middleware como opción opt-in; pruebas verifican bloqueo, exclusiones, modo
  monitor y ausencia del payload en logs.
- [x] **Regenerar las métricas desde el evaluador** y sincronizar README,
  documentación e informe. La evaluación sigue siendo solo del modo individual.
- [x] **Corregir la documentación del límite del body.** 413 cuando el tamaño
  declarado o el stream leído exceden `max_body_size`; la falta de
  `Content-Length` por sí sola no causa rechazo.
- [x] **Registrar evidencia reproducible de validación.** Los comandos y
  resultados locales están en la descripción de la PR #20, que quedó integrada.

**Siguiente tarea recomendada:** mejorar la facilidad de integración: publicar
una guía rápida copiable y una guía de configuración segura para proxy/Redis
por topología. Los ejemplos ya se ejecutan en CI desde la revisión del
2026-10-23. Después, ampliar las pruebas operativas (Redis real con varios
workers, límites de memoria y volumen, servidores de producción). La evaluación
retenida y el tráfico benigno autorizado siguen siendo necesarios antes de una
conclusión de preparación para release. No activar el modo cruzado por defecto ni
subir las puntuaciones sin cumplir la evidencia de cada dimensión.

## Cómo verificar el estado (comandos)

Todo lo que este plan afirma como comprobado se reproduce con estos comandos,
desde `gatekeeper-v0.3/gatekeeper`:

```bash
pip install -e ".[dev]"

ruff check .                          # lint
mypy                                 # tipos (strict, contra 3.10)
bandit -r src -q                     # seguridad estática
pytest --cov=gatekeeper --cov-fail-under=90   # suite + cobertura
python tools/evaluate.py --check     # corpus propio + CRS (guarda de regresión)
python tools/evaluate_heldout.py --check  # corpus retenido (generalización)
python tools/evaluate_cross.py --check  # corpus del modo cruzado
python tools/import_crs.py --check   # procedencia del corpus externo
python tools/check_redis.py          # el Redis configurado responde (extra [redis])
python tools/measure_rules.py        # efecto de un cambio de reglas sobre los 4 corpus
mkdocs build --strict                # documentación
python -m build && twine check dist/*  # paquete
```

Las pruebas contra Redis **real** (`tests/test_redis_real.py`) necesitan un
Redis accesible. En local:

```bash
docker run -d --name gk-redis -p 6379:6379 redis:7.2-alpine
GATEKEEPER_REDIS_URL=redis://127.0.0.1:6379/0 pytest tests/test_redis_real.py -v
```

Si no hay Redis, esos tests se **omiten** con un motivo claro y el resto de la
suite pasa igual.

Las cifras que este plan da como verdaderas (`159/159` en el corpus propio,
`103/109` en el retenido, `465/1135` y `11/232` en CRS, `7/7` y `0/15` en el
modo cruzado) salen de `python tools/evaluate.py --json`,
`python tools/evaluate_heldout.py --json` y
`python tools/evaluate_cross.py --json`, no de números escritos a mano.


## 1. Pruebas y calidad del código — 18/20 → 20/20

### Qué significa obtener 20/20

- La suite requerida por CI pasa en todas las versiones de Python soportadas.
- Los comportamientos de seguridad y los fallos operativos están cubiertos por
  pruebas de integración, no solo por pruebas unitarias de regex.
- Los cambios de reglas se evalúan contra casos de ataque y tráfico benigno, con
  umbrales explícitos para falsos positivos y regresiones.
- La instalación construida desde el paquete funciona en un entorno limpio.
- Hay una revisión de seguridad enfocada en límites de confianza, parsing,
  almacenamiento distribuido y manejo del body antes de una versión estable.

### Trabajo

- [x] Mantener Ruff, mypy, Bandit, cobertura y tests de corpus como checks
  obligatorios en CI.
- [x] Añadir pruebas ASGI de extremo a extremo para query, path, headers, body,
  respuestas 403/413/429/503, `monitor_only` y cabeceras de seguridad.
- [x] Probar body por streaming sin `Content-Length`, límite exacto, límite
  excedido, desconexión del cliente y tipos de contenido no inspeccionados.
  Cubierto en `tests/test_limites_body_ratelimit.py` (límite exacto inclusivo,
  fragmentado, `Content-Length` ausente o mentiroso, `http.disconnect`,
  multipart y binario). Falta aún la prueba contra un servidor real.
- [x] Probar rate limiting con concurrencia, múltiples workers usando Redis,
  caída/timeout de Redis y los modos fail-open y fail-closed.
  Hecho contra un **Redis real** (`tests/test_redis_real.py`, 13 tests), con un
  job de CI que levanta `redis:7.2-alpine`. Se comprueba que el límite es
  global entre workers (50 workers, misma IP: se admiten exactamente los 10
  del límite), que el contador sobrevive a un reinicio del proceso, que las IPs
  distintas no se pisan, que Redis caído da 503 con fail-closed y se audita con
  fail-open, y que el script Lua se ejecuta de verdad. Sin Redis disponible,
  los tests se omiten con un motivo claro.

- [x] Añadir regresiones para IP directa, `X-Forwarded-For` confiable y no
  confiable, CIDR de proxies y cabeceras manipuladas desde clientes externos.
- [ ] Ejecutar pruebas de fuzzing y límites de tiempo/memoria para entradas
  grandes y patrones configurables. Documentar que las regex del usuario pueden
  tener riesgos distintos de las reglas integradas.
  Parcial: `tests/test_fuzz.py` cubre propiedades con Hypothesis sobre las
  funciones puras, pero no hay límites de tiempo/memoria ni fuzzing de las regex
  de usuario.
- [x] Probar el artefacto wheel/sdist en un entorno virtual limpio y verificar
  instalación, importación, extras opcionales y metadatos.
  Verificado en local (venv limpio: instalación, `import gatekeeper`, extras
  `redis` y `yaml`, metadatos) y en CI por el job `package`. Falta la
  instalación desde PyPI, que exige publicar antes.
- [ ] Añadir una revisión de seguridad independiente antes de declarar una
  versión estable; resolver o aceptar de forma explícita cada hallazgo.


### Evidencia de cierre

- CI verde para todos los runtimes soportados y publicación de artefactos
  verificada.
- Pruebas nuevas que cubren las rutas de integración y fallos enumerados arriba.
- Cobertura mínima del proyecto mantenida; no usar cobertura como único indicador
  de seguridad.
- Informe de revisión de seguridad con hallazgos resueltos o aceptados.

## 2. Facilidad de integración ASGI — 14/20 → 20/20

### Qué significa obtener 20/20

Un desarrollador puede instalar Gatekeeper, añadirlo a una aplicación, escoger
una configuración adecuada para su despliegue y verificar que está funcionando
sin tener que adivinar cómo confiar en proxies, configurar Redis o depurar
bloqueos.

### Trabajo

- [ ] Publicar e instalar la versión desde PyPI, una vez comprobados nombre,
  disponibilidad, metadatos, wheel y sdist.
- [x] Mantener ejemplos mínimos y probados para FastAPI y Starlette, incluyendo
  instalación, middleware, reglas propias, modo monitor y Redis.
  Los ejemplos existen y se ejecutan de verdad: `tests/test_docs_examples.py`
  los incluye en la corrida de `pytest`, que CI ejecuta (`pytest --cov=gatekeeper
  --cov-fail-under=90`), así que un ejemplo roto tumba el pipeline.
- [x] Añadir una guía rápida copiable que valide una petición permitida y una
  bloqueada localmente.
  Hecho en `docs/inicio-rapido.md`: instalar, añadir el middleware, y los dos
  comandos `curl` que verifican 200 (petición normal) y 403 (ataque), con qué
  revisar si el ataque pasa. Los dos códigos de respuesta están **verificados
  por tests** (`tests/test_inicio_rapido.py`), no solo escritos: si el
  middleware deja de dar 403, la guía deja de ser cierta y falla el pipeline.
- [x] Documentar ejemplos de despliegue de un proceso, varios workers, Docker y
  proxy inverso; explicar qué valores cambian según el entorno.
  Hecho en `docs/despliegue.md`: una sección por topología (un proceso, varios
  workers, Docker/Kubernetes, proxy inverso), una matriz de decisión y un
  checklist de producción. Las afirmaciones de seguridad que hace (el límite
  en memoria se multiplica con los workers, el XFF se ignora si el peer no es
  de confianza, `allow_paths` exime de inspección pero no de rate limit) están
  fijadas por tests en `tests/test_despliegue.py`.
- [x] Explicar con claridad cómo configurar IP del cliente y proxies confiables.
  No recomendar confiar en `X-Forwarded-For` sin limitar quién puede enviarlo.
  Hecho en `docs/despliegue.md`: por qué el XFF se lee de derecha a izquierda,
  la tabla de `trusted_proxies` por topología y por qué activar `trust_proxy`
  sin `trusted_proxy_cidrs` con la app accesible sin proxy es un agujero.

- [x] Proporcionar configuraciones de ejemplo conservadora y distribuida, sin
  ocultar las diferencias entre rate limit en memoria y Redis.
  `examples/gatekeeper.yaml` cubre ambas (corregido y validado por tests) y
  `docs/uso.md` explicita la diferencia memoria/Redis por workers.
- [x] Documentar códigos de respuesta, eventos de log, límites de inspección y
  cómo diagnosticar falsos positivos.
  `docs/api.md` (códigos), `docs/uso.md` (auditoría y `gatekeeper report`),
  `docs/amenazas.md` (qué se inspecciona y qué no).
- [ ] Mantener compatibilidad comprobada con versiones soportadas de Python,
  FastAPI y Starlette; documentar la matriz probada.
  CI prueba Python 3.10–3.13 y `docs/seguridad.md` lista versiones, pero no hay
  una matriz explícita de FastAPI/Starlette probada.
- [ ] Definir política de compatibilidad de API y versionado semántico.
  El CHANGELOG declara SemVer, pero no hay política escrita de deprecaciones.


### Evidencia de cierre

- Todos los ejemplos de documentación se ejecutan en CI.
- Una persona nueva puede seguir la guía rápida desde un entorno limpio.
- Matriz de versiones publicada y validada por pruebas.
- Sin parámetros críticos de proxy o Redis cuyo riesgo quede implícito.

## 3. Cobertura de detección demostrada — 7/20 → 20/20

### Qué significa obtener 20/20

No significa detectar el 100% de ataques posibles ni alcanzar un porcentaje
arbitrario de OWASP CRS. Significa que el alcance está definido, las métricas son
reproducibles, los límites se reconocen y hay evidencia de comportamiento en los
tipos de entrada realmente inspeccionados.

### Trabajo

- [x] Mantener corpus propio con procedencia, etiquetas, ejemplos benignos y
  explicación de falsos positivos y negativos aceptados.
- [x] Separar corpus de desarrollo y corpus de evaluación retenido para reducir
  el riesgo de ajustar reglas solo a los mismos ejemplos que luego se publican
  como evidencia.
  Hecho: `corpus/heldout_attacks.json` (109 ataques) y
  `corpus/heldout_benign.json` (90 benignos) son un corpus **retenido**,
  escrito una vez sin mirar las firmas de las reglas y desde entonces solo
  medido. Resultado: **103/109 (94,5%)** de detección y **0** falsos positivos
  sin documentar. El evaluador (`tools/evaluate_heldout.py`) tiene su propia
  guarda en CI, y `tests/test_heldout.py` fija las cifras, comprueba que todo
  límite esté documentado con su motivo y que el corpus no se solape con el de
  desarrollo.
- [x] Publicar métricas por familia: precisión/recall o, cuando los datos no
  permitan estimarlos con rigor, conteos, denominadores y límites claros.
- [x] Publicar el alcance exacto CRS: familias incluidas, exclusiones, negativos,
  falsos positivos y commit de origen. No comparar ese porcentaje con la
  cobertura de un WAF completo.
- [x] Asegurar que las métricas publicadas del modo individual se regeneran
  desde el evaluador y coinciden en README, documentación e informe. La
  evaluación cruzada es separada y no se incluye en esas cifras.
- [x] Añadir una evaluación separada del modo cruzado, con ataques divididos,
  casos benignos, denominadores explícitos y guarda en CI. El corpus actual es
  solo de desarrollo y no sustituye una evaluación retenida ni tráfico real.
- [ ] Añadir casos reales anonimizados, recopilados con autorización, para
  observar falsos positivos en modo monitor antes de activar bloqueos.
- [ ] Probar entradas de query, path, headers y body; incluir codificación,
  normalización, tipos de contenido y combinaciones entre campos cuando se
  anuncie detección combinada.
  Parcial: hay tests de los cuatro transportadores y de codificación, y el
  corpus retenido cubre los cuatro con codificación y bypass. Falta la
  **combinación de campos** cuando se anuncie detección combinada: el modo
  cruzado tiene su corpus, pero sigue siendo de desarrollo y sin retenida.
- [x] Mantener el criterio de cero falsos positivos **no documentados** en el
  corpus propio (159 ataques y 81 benignos; `evaluate.py --check` pasó en esta
  verificación).
- [x] Establecer umbrales de regresión por corpus, con justificación y proceso
  para actualizar el corpus sin ocultar deterioros.

### Evidencia de cierre

- Un comando genera el informe completo y produce resultados deterministas.
- Las cifras de todos los documentos coinciden con el informe generado.
- La detección combinada anunciada tiene una prueba que pasa a través del
  middleware real.
- Se informa de limitaciones y casos no detectados; no se formula una promesa de
  protección total ni se usa un único porcentaje como resumen de seguridad.

## 4. Operación y compatibilidad con despliegues — 8/20 → 20/20

### Qué significa obtener 20/20

El operador entiende qué sucede ante cada fallo, cómo se calcula la IP, qué
datos se procesan y registran, y cómo desplegar el middleware en una topología
real sin confiar accidentalmente en el cliente.

### Trabajo

- [ ] Documentar y probar el comportamiento de cada backend de rate limit,
  incluyendo reinicios, concurrencia, workers y indisponibilidad de Redis.
  Ahora **sí**: los dos backends se prueban contra un Redis real (reinicios,
  concurrencia, workers, indisponibilidad) y contra el backend en memoria.
  Falta la prueba con **varios procesos de Python** reales (hoy son varios
  clientes en el mismo proceso, que es lo mismo para Redis pero no demuestra
  el reparto entre procesos del sistema operativo).

- [x] Elegir y explicar el comportamiento recomendado ante fallo del backend:
  fail-open o fail-closed, según el riesgo de la aplicación.
  `docs/uso.md` y `docs/seguridad.md` lo explican y el middleware implementa
  ambos caminos; los dos tienen test.
- [x] Aclarar la cadena de confianza de proxies, CIDR permitidos y comportamiento
  cuando el peer no es confiable.
  Hecho en `docs/despliegue.md` (sección "Detrás de un proxy inverso"), con
  la configuración mínima, el ejemplo de nginx, la tabla de `trusted_proxies`
  por topología y la explicación de por qué el XFF se lee de derecha a
  izquierda. Verificado por `tests/test_despliegue.py`: el peer no confiable
  hace que el XFF se ignore, el peer de confianza permite bloquear y limitar
  por la IP real, y una cadena inconsistente no adivina.

- [ ] Verificar límites de memoria y consumo con cuerpos grandes, cuerpos
  fragmentados y entradas de gran volumen.
  Parcial: `max_body_size` corta el body acumulado y hay test de body
  fragmentado, pero no hay medición de memoria ni prueba de volumen alto.
- [x] Documentar qué tipos de body no se inspeccionan, incluidos multipart y
  contenido binario, y cuáles son las consecuencias.
  `docs/amenazas.md` lo documenta y ahora hay tests que fijan ese
  comportamiento (multipart y binario no se inspeccionan).
- [x] Confirmar que los logs nunca incluyen payloads sensibles y documentar qué
  metadatos sí se registran, retención y recomendaciones de acceso.
  Hay test que comprueba que la auditoría no lleva el payload; se documenta
  qué metadatos se registran. La recomendación de retención y acceso es
  explícita en `docs/seguridad.md`.
- [ ] Definir métricas/observabilidad de bloqueos, límites, errores de Redis,
  respuestas 413 y modo monitor, sin exponer datos sensibles.
  Falta: hay eventos de auditoría, pero no un catálogo de métricas ni
  Prometheus/OTel.
- [ ] Probar la interacción con aplicaciones ASGI comunes y servidores de
  producción soportados; documentar topologías comprobadas.
- [ ] Proporcionar un procedimiento de despliegue gradual: monitor, revisión de
  alertas, ajuste y activación de bloqueo, con instrucciones de reversión.


### Evidencia de cierre

- Pruebas de integración y carga reproducibles para las topologías documentadas.
- Guía operativa con decisiones ante fallo, proxy, logs, límites y rollback.
- Sin afirmaciones de soporte para configuraciones que no se hayan probado.

## 5. Documentación y preparación de publicación — 8/20 → 20/20

### Qué significa obtener 20/20

El paquete tiene un canal oficial de instalación y actualización, documentación
consistente, un historial de cambios y una política clara de soporte y reporte
responsable de vulnerabilidades.

### Trabajo

- [x] Sincronizar README, docs, informe del corpus, changelog, metadatos del
  paquete y notas de release.
  Verificado: las cifras (159/159, 465/1135 = 41,0%, 11/232 = 4,7%) coinciden
  en README raíz, README del paquete, `docs/index.md`, `docs/deteccion.md`,
  `docs/amenazas.md` y `corpus/REPORT.md`, y se regeneran desde el evaluador.
  `ARTICLE.md` conserva las cifras de su momento (es un artículo histórico, no
  una referencia actual). El CHANGELOG "Sin publicar" recogía la detección
  cruzada pero no su evaluación: corregido.
- [x] Verificar el nombre del proyecto, número de versión, licencia, URL,
  clasificadores de Python y extras publicados.
  `gatekeeper-asgi` 0.3.1, MIT (SPDX, PEP 639), `requires-python >=3.10`,
  extras `yaml`/`redis`/`dev`. Verificado con `twine check` y con el metadato
  instalado en un venv limpio. Falta comprobar que el nombre esté libre en
  PyPI antes de publicar.
- [ ] Publicar en PyPI con un proceso de release reproducible y revisar el
  artefacto instalado desde PyPI en un entorno limpio.
  El workflow `publicar.yml` con Trusted Publishing ya está escrito, pero el
  proyecto todavía no existe en PyPI: requiere el alta manual que el propio
  workflow documenta.
- [ ] Etiquetar versiones y mantener notas de migración para cambios de API,
  configuración, reglas y defaults.
  El CHANGELOG sigue SemVer y hay notas por versión; falta publicar tags y
  documentar el proceso de migración.
- [ ] Publicar una matriz explícita de compatibilidad y una lista de limitaciones
  conocidas.
- [ ] Revisar la guía de instalación y quickstart desde cero; comprobar comandos
  y enlaces.
  Parcial: los ejemplos de código se ejecutan ahora en CI
  (`tests/test_docs_examples.py`), pero no hay guía rápida "copiar y pegar" y
  los enlaces externos no se comprueban automáticamente.
- [x] Mantener SECURITY.md con canal privado de reporte, alcance, tiempos de
  respuesta razonables y proceso de divulgación.
  Existe `SECURITY.md` en la raíz y en el paquete, con canal y alcance.
- [ ] Definir política de soporte: versiones mantenidas, compatibilidad y cómo
  reportar errores o falsos positivos.
  Falta la política explícita de versiones mantenidas.
- [ ] Retirar o identificar claramente scripts temporales, reportes de análisis

  puntuales y artefactos que puedan confundirse con una interfaz estable.

### Evidencia de cierre

- Release etiquetada e instalable desde el canal anunciado.
- Documentación coherente, enlaces revisados y ejemplos ejecutables.
- Proceso de seguridad y soporte visible para usuarios.

## Secuencia recomendada

1. **Confiabilidad inmediata — completada en PR #20:** conectar la detección
   query/body como opt-in, corregir el 413 documentado, regenerar las métricas y
   sincronizar la documentación.
2. **Medición inicial del cruce — completada en PR #22:** evaluación separada
   para el modo opt-in, con ataques divididos y peticiones benignas; resultados
   con denominadores explícitos y sin mezclarlos con el escaneo individual. La
   muestra no es retenida ni representa tráfico real; ampliar esa evidencia
   sigue pendiente.
3. **Confianza operacional — completada parcialmente (2026-10-23):** los límites
   de confianza del body (límite exacto, fragmentado, `Content-Length`
   mentiroso, desconexión) y la política de fallo de Redis (fail-open y
   fail-closed) ya tienen test, y los ejemplos de la documentación se ejecutan
   en CI. Falta Redis real con varios workers, límites de memoria/volumen y
   la interacción con servidores de producción.
4. **Producto utilizable — completada (2026-10-24):** guía rápida copiable
   (`docs/inicio-rapido.md`) y guía de despliegue por topología
   (`docs/despliegue.md`), con los valores que cambian por topología y la
   cadena de confianza de proxies. Ambas páginas tienen tests que comprueban
   que lo que prometen es lo que el middleware hace.
5. **Evidencia de detección y release:** crear evaluación retenida, validar
   tráfico benigno autorizado y reportar límites; completar revisión de
   seguridad, paquete limpio, versión etiquetada, publicación y política de
   soporte.
6. **Confianza operacional pendiente:** Redis real con varios workers (hoy se
   usa `fakeredis`, que no reproduce el reparto entre procesos), límites de
   memoria y volumen, e interacción con servidores de producción.



## Regla para asignar la puntuación final

No subir una dimensión a 20/20 solo porque hay más tests, más reglas o más
documentación. Cada puntuación requiere cumplir sus criterios de cierre con
evidencia reproducible. Si una capacidad no existe o no se ha validado, se debe
marcar como pendiente y no presentarla como completa.
