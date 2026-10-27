# Auditoría de seguridad y calidad — Gatekeeper / `gatekeeper-asgi` 0.4.0

**Fecha:** 25 de octubre de 2026
**Alcance:** código del repo (`gatekeeper-v0.3/gatekeeper/`), suite de tests, estáticos, empaquetado, documentación local, ficha de PyPI y las 13 páginas del sitio publicado en GitHub Pages.
**Método:** lectura de código + pruebas de ataque reales contra la aplicación ASGI (no solo lectura de tests) + medición de coste con procesos aislados y timeout duro + verificación de las afirmaciones del informe previo, una por una.
**Estado del repo al auditar:** rama `main`, `HEAD 744fbc7`, working tree limpio salvo el parche sin aplicar `fix-redos-comentarios-sql.patch` (untracked).

> **No se ha modificado ningún archivo del proyecto.** Todo el trabajo de prueba se ha hecho en copias aisladas bajo `.audit/`.

---

## 1. Veredicto

**73/100.** El proyecto está muy por encima de la media en rigor de medición, tests y supply chain, pero **hoy no es recomendable para producción**: hay un **DoS sin autenticación, de una sola petición, en un paquete de seguridad ya publicado en PyPI**.

La buena noticia: el parche que te dejaron (`fix-redos-comentarios-sql.patch`) **es legítimo y funciona** — lo he verificado de forma independiente, con tests, con los tres corpus y midiendo el coste. No lo apliqué en tu repo; te dejo el análisis y el comando.

La mala noticia: **parcheado sigue sin ser apto para producción**, porque siguen abiertos el bypass total de WebSocket, la fuga del payload al log, el escape de terminal del CLI y el crecimiento sin tope del rate limiter.

---

## 2. Puntuación

| Área | Nota | Comentario |
|---|---:|---|
| Seguridad del propio código (DoS, bypasses) | **12/20** | Un DoS crítico abierto + 4 bypasses de superficie + 4 fugas/abusos de recursos |
| Calidad de detección y reglas | **15/20** | 100 % propio, 94,5 % retenido, 41,0 % CRS con FP publicados. 6 FN y 3 FP reales |
| Tests, CI y tipado | **13/15** | 2457 tests, cobertura 95 %, hypothesis, mypy estricto, bandit, 4 versiones de Python, Redis real. Falta el test de complejidad temporal |
| Documentación | **9/15** | Estructura y honestidad excelentes, pero con afirmaciones técnicas **falsas** y web publicada obsoleta |
| Publicación y supply chain | **10/10** | Trusted Publishing, provenance verificado en PyPI, actions fijadas por SHA, `pip-audit` |
| Estructura y mantenibilidad | **5/10** | `v0.1/v0.2/v0.3` en la raíz, sdist de 423 KB con demo/corpus/docs, sin `AGENTS.md` |
| Método de medición y honestidad | **9/10** | "Qué mide (no qué promete)", corpus retenido con 94,5 % en vez de 100 %, FP documentados |
| **TOTAL** | **73/100** | Con el parche aplicado: **≈79**. Con las 5 correcciones prioritarias: **≈88** |

---

## 3. Lo que está muy bien (esto no lo change, es tu ventaja competitiva)

1. **Rigor metodológico de primer nivel.** `README.md:54` — *"Qué mide (no qué promises)"*. El corpus retenido publica **94,5 %** en lugar de 100 %, los falsos positivos están enumerados **con su id y su motivo** (`corpus/REPORT.md`), y `SECURITY_REVIEW.md:9-14` declara explícitamente que la revisión **no es independiente**. Muy pocos proyectos de este tamaño hacen eso.
2. **Las cifras son reproducibles.** Las he reejecutado: `attacks_total 159`, `attacks_detected 159`, `benign_total 81`, `benign_flagged 5` (los 5 documentados), CRS `41,0 %` detección / `4,7 %` FP. Coinciden **exactamente** con lo publicado.
3. **Supply chain de nivel profesional.** Verificado en la ficha de PyPI: *"Full provenance"* en wheel y sdist, firmado por GitHub Actions con entrada en el transparency log de Sigstore. Trusted Publishing sin token, acciones fijadas por SHA completo, `pip install --only-binary ":all:"` para el toolchain, job `pip-audit` con venv limpio, Redis real y multiproceso en CI, `mkdocs build --strict`.
4. **Calidad de código alta.** `ruff` limpio, `mypy` estricto sin un solo error, `bandit` sin hallazgos, `py.typed` correcto, cobertura **95 %** con `rules.py` al 100 %, `body.py` 98 %, `middleware.py` 97 %.
5. **2457 tests pasan** (1 skipped) más 10 del parche. Rapidísimo: 69 s con `pytest-randomly` activo.
6. **El `X-Forwarded-For` está bien resuelto.** Lo he atacado: con `trust_proxy=True` y proxies de confianza, el cliente puede rotar el XFF sin saltarse el límite; si el peer no es de confianza, el XFF se ignora. `blocked_ips` con CIDR funciona detrás de proxy. 18/18 controles de configuración y proxy correctos.
7. **`allow_paths` no es un trampolín.** `paths.py:19` rechaza rutas con `..`, `\` o codificación residual antes de aplicar los globs. `allow_paths` exime de inspección pero **no** de rate limit (y esto sí está bien documentado en `README.md:198`).
8. **Fallo al arrancar, no en producción.** `config.py:157-176` valida backend, `max_body_size`, CIDRs, IPs y reglas: la configuración inválida revienta al importar, no a las 3 de la mañana.
9. **Límites de punteros JSON** (`MAX_POINTER_DEPTH`, `MAX_POINTER_CHILDREN`) ya existentes: el parser no se desbunda con JSON anidado. El problema es la atribución, no la seguridad (ver M-3).

---

## 4. Hallazgos verificados

### 🔴 CRÍTICO — C-1 · DoS cuadrático sin autenticación (ya publicado en PyPI)

**Dónde:** `src/gatekeeper/rules.py:521` → `re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)`.
**Por qué:** por cada `/*` sin cierre, el motor recorre el resto del texto hasta el final. Es **O(n²)**, y `re` no suelta el GIL, así que **bloquea el event loop completo**.

**Medición (proceso aislado, timeout duro, `scan()` con `/?q=` + payload):**

| Bytes | Segundos | × tamaño | × tiempo |
|---:|---:|---:|---:|
| 8.000 | 0,084 | – | – |
| 16.000 | 0,333 | 2,00 | **3,97** |
| 32.000 | 1,351 | 2,00 | **4,06** |
| 64.000 | 5,509 | 2,00 | **4,08** |
| 128.000 | **23,587** | 2,00 | **4,28** |

Duplicar el tamaño multiplica el tiempo ×4 → curva cuadrática limpia.

**De extremo a extremo (una sola petición HTTP):**

| Bytes del body | Segundos | Estado HTTP |
|---:|---:|---:|
| 7.998 | 0,142 | **200** |
| 15.999 | 0,336 | **200** |
| 31.998 | 1,340 | **200** |
| 63.999 | **5,535** | **200** |

Lo peor: **la petición devuelve 200**. El ataque no se bloquea, simplemente congela el servidor. Con el `max_body_size` por defecto de 1 MiB, la extrapolación (×64 respecto a 128 KB) da **≈1.510 s ≈ 25 minutos de event loop bloqueado por una sola petición sin autenticar**. En un servidor con 2 workers, 2 peticiones matan el servicio.

**Reproducir:** `POST /` con `content-type: text/plain` y 64 KB de `/*a` repetido.

**Impacto:** un atacante sin credenciales puede tumbar cualquier despliegue que use Gatekeeper. Y como es un **paquete de seguridad ya publicado** (0.4.0, hoy), es candidato a **GitHub Security Advisory** (GHSA) y a CVE.

**Nota de honestidad:** el parche que te entregaron **no lo he revisado con el código en producción**; lo he ejecutado y medido en copia aislada (§6). El resto del informe anterior lo he **reproducido o refutado** (§5).

---

### 🟠 ALTO

#### A-1 · WebSocket: sin inspección, **sin rate limit**, y sin documentar

`src/gatekeeper/middleware.py:175` → `if scope["type"] != "http": await self.app(...)`. Sale antes de todo.

**Reproducido:** con `rate_limit=1`, **6/6 conexiones WebSocket aceptadas**; el handshake con `?q=union%20select%20password%20from%20users` se acepta sin inspección. Tampoco se aplican cabeceras de seguridad.

**Y no está documentado:** la palabra "WebSocket" **no aparece en ninguna de las 13 páginas de `docs/`** ni en la web publicada. Para un usuario que lee *"Qué cubre"*, Gatekeeper parece cubrir todo el tráfico. `SECURITY.md:41` solo dice "Ataques HTTP automatizados".

**Arreglo:** o inspeccionar y limitar WS (recomendado: handshake + primeros frames), o declarar explícitamente el hueco en `docs/amenazas.md`, `README.md` y `SECURITY.md`.

#### A-2 · `application/octet-stream` se salta la inspección

`src/gatekeeper/body.py:20-44`. **Reproducido:** un JSON con SQLi enviado como `application/octet-stream` pasa con **200**. Una app que use `await request.json()` lo parsea igual. El texto plano sí se inspecciona (control: 403).

**Arreglo:** *sniff* del primer byte (`{`, `[`) cuando el content-type no es concluyente.

#### A-3 · Multipart sin inspeccionar (documentado, pero es la superficie más atacada)

`body.py:40` excluye `multipart/form-data`. **Reproducido:** `filename=../../etc/passwd` y un campo con SQLi pasan con **200**.

Está documentado (`SECURITY.md:53`, `README.md:190`), lo cual es honesto, pero sigue siendo un bypass real: un atacante que controle un campo de un formulario usa tu WAF como tunnel.

#### A-4 · El rate limiter no tiene tope de claves → 245 MB por 300.000 IPs

`src/gatekeeper/ratelimit.py` — `MemoryBackend._hits` es un dict sin límite; `_prune` (línea ~103) solo elimina claves **viejas**, cada 1000 llamadas.

**Medido:** 300.000 IPs distintas → **245,8 MB** de RAM (**859 bytes por IP**, sobre todo por crear un `deque` por clave) y O(n) en cada poda.

**Arreglo:** tope máximo de claves (con política LRU), y agrupar IPv6 por /64.

---

### 🟡 MEDIO

#### M-1 · La promesa "nunca se registra el contenido del payload" es **FALSA**

Documentado en `SECURITY.md:68-71`, `docs/seguridad.md:69-70`, `README.md:51` y `docs/trafico-real.md:17-19`.

**Reproducido — el payload completo SÍ llega al log:**

| Caso | `field` registrado | ¿Payload en el log? |
|---|---|---|
| form-urlencoded, payload en el **nombre** del parámetro | `/union select password from users` | **SÍ** |
| JSON con el payload en la **clave** | `/UNION SELECT password FROM users` | **SÍ** |
| form-urlencoded, payload en el valor | `/q` | no |
| JSON normal | `/q` | no |
| text/plain | `` | no |

La causa: `body.py` construye el puntero como `"/" + nombre_del_parámetro`, y ese nombre es **texto del atacante**. Con `application/x-www-form-urlencoded`, un cuerpo sin `=` se interpreta como un parámetro cuyo *nombre* es el cuerpo entero.

**Consecuencia:** si documentas "el log nunca lleva el payload" para justificar mandar logs a un tercero o a un SIEM, **eso ya no es cierto**. Además, ese texto acaba impreso en la terminal del operador (ver M-2).

#### M-2 · Escape de terminal en `gatekeeper report`

**Reproducido en los dos formatos que acepta el CLI:**

- **JSON**: el log escapa el ESC como `\u001b`, pero `cli.py:98-99` hace `json.loads` y **decodifica** `\u001b` a un ESC real, y lo mete en el informe sin sanear → el byte ESC llega a la terminal. Un atacante puede reescribir el título de la ventana del operador o injectar secuencias de color.
- **Log de acceso genérico**: los bytes de control llegan **intactos**, sin pasar por ningún escape.

**Arreglo:** sanear con una función tipo `str.translate` sobre el rango C0 + ESC antes de imprimir, y aplicar el mismo control al escribir en el log.

#### M-3 · Puntero JSON roto a partir de 64 niveles → falso positivo y `exclude_fields` inoperante

`body.py:203` `_child_pointer()`: al llegar al límite, **sustituye** `segmentos[1]` por `"…"` pero **nunca añade el segmento actual**. El puntero resultante termina en el antepasado, no en el campo que saltó.

**Reproducido:** JSON con 80 niveles → el puntero real (`/payload`) **no aparece**; y `exclude_fields=["payload"]` **no casa** → falso positivo que el usuario no puede silenciar. No es un bypass, pero rompe la herramienta de tuning.

#### M-4 · Dos patrones SQLi viven en la familia `sensitive_files`

`rules.py:246` y `:249` — `union\s+all` y `or\s+['\"]?(?:\{|\[|and|between|like|in|json)` están en `sensitive_files`, no en `sqli`.

**Reproducido:** con `disabled_rules=["sqli"]`, `union all select 1` **se sigue detectando** y se reporta como `rule: "sensitive_files"`. Quien construya allowlists por nombre de regla se lleva una sorpresa. Además, el patrón `\.(?:sql|bak|old|orig|save|swp)\s*$` está **duplicado** dentro de la misma familia.

#### M-5 · `rl_backend_unavailable` no existe: el evento real es `rate_backend_error`

`src/gatekeeper/middleware.py:195` emite `rate_backend_error`, y el catálogo autoritativo `corpus/events.json:62` también. Pero está documentado con el nombre equivocado en **5 ficheros / 6 sitios**: `docs/api.md:103`, `docs/despliegue.md:74`, `docs/uso.md:51`, `docs/uso.md:169`, `docs/seguridad.md:43` (solo `docs/operacion.md:18` usa el nombre correcto).

**Consecuencia:** una alerta de on-call construida sobre el nombre documentado **nunca dispara**. Falla en silencio, que es lo peor en monitoring.

#### M-6 · HSTS se envía también en `http://`, contra lo que dice la doc

`docs/uso.md:177-179` afirma que HSTS *"solo se sirve sobre HTTPS (se omite en `http://`)"*. **Verificado empíricamente:** con una petición `http://` real, la respuesta incluye `Strict-Transport-Security`. En `middleware.py` no hay ninguna comprobación de esquema. Un navegador que recibe HSTS por HTTP fija el origen a HTTPS y te rompe el desarrollo local — justo el escenario que la doc dice evitar.

#### M-7 · `custom_rules=` no existe en el middleware (ejemplo que revienta)

`docs/amenazas.md:105-108` documenta `GatekeeperMiddleware(app, custom_rules={...})`. La firma real es `(self, app, config=None)` → **`TypeError`**. `custom_rules` es un campo de `Config`, y acepta `regex` en string o lista de dicts `{name, pattern}`, no objetos `re.Pattern`.

Lo mismo con `Config.validate()`, documentado en `docs/api.md:92` y **no existe** en `config.py`.

---

### 🔵 BAJO

- **B-1 · Falsos negativos de detección (6).** Reproducidos: `' or ''=` (tautología con comillas vacías), booleano ciego `substring(version(),1,1)=5`, `http://2130706433/admin` (IP decimal) y `http://0x7f000001/admin` (hex) en SSRF, y `foo\nrm -rf /` en cmdi (sin `;`/`|`). `docs/amenazas.md:39` afirma que **la IP de loopback en decimal sí es sospechosa**: es falso.
- **B-2 · Falsos positivos (3).** `<script>` en prosa → `xss`; `sleep(8 hours)` en prosa → `sqli`; `el sindicalismo unido union workers` → `sqli`. (El caso `"1=1 in math"` que mencionaba el informe previo **no se reproduce**: no se detecta.)
- **B-3 · `docs/api.md:27,29` — los cuerpos de error documentados no son los reales.** `429` real: `{"detail": "Too Many Requests"}` (doc dice `"rate limit exceeded"`); `503` real: `{"detail": "Service Unavailable"}` (doc dice `"rate_limit_backend_unavailable"`). `413` sí es correcto.
- **B-4 · La web publicada y el repo siguen diciendo que el paquete no está en PyPI.** `docs/inicio-rapido.md:6-8` ("Todavía no está en PyPI"), `SECURITY.md:16-18`, `docs/instalacion.md:3-5`, `README.md:23` — y `docs/instalacion.md` **no tiene sección "Desde PyPI"**. Pero 0.4.0 está publicado (verificado con attestation). Contradice `RELEASE_NOTES_0.4.0.md:3` ("Primera versión publicada en PyPI").
- **B-5 · `SECURITY.md:7-9` — tabla de versiones obsoleta:** `| 0.3.x | Activa |` siendo la activa **0.4.0**. Además 0.1.x/0.2.x nunca existieron en PyPI.
- **B-6 · Enlaces rotos en la ficha de PyPI.** El README usa enlaces **relativos**: `corpus/`, `corpus/HELDOUT.md`, `corpus/REPORT.md`, `docs/amenazas.md`, `demo/`, `docs/assets/demo.gif`. En PyPI resuelven contra `pypi.org/project/gatekeeper-asgi/...`, que no aloja ficheros del repo. *No pude observar el código de estado real porque el anti-bot de PyPI intercepta esas subrutas (devuelven un interstitial "Client Challenge"), pero la URL absoluta equivalente en GitHub sí da 200.* En la **web publicada** es aún más claro: `https://eche-dev.github.io/Gatekeeper/corpus/`, `/corpus/REPORT.md` y `/demo/` devuelven **404 verificado**.
- **B-7 · `README.md:99-102` promete que el CI vigila la línea base del 41 % de CRS.** El umbral real en `tools/evaluate.py:46` es `DEFAULT_MIN_CRS_DETECTION = 0.19` → una regresión del 41 % al 20 % **pasa CI**. `docs/deteccion.md:141-143` sí dice la verdad → el README contradice a su propia página.
- **B-8 · `README.md:162-167`, sección "Comparar rendimiento", está truncada**: termina en *"…ejecuta ambas versiones en la misma máquina:"* y no hay receta debajo.
- **B-9 · `docs/operacion.md:25`:** *"no se envía **aThird parties**"* (falta el espacio). `docs/compatibilidad.md:92,226`: *"Nuevas **functionality**"*, *"sin **consequences**"* — anglicismos sin traducir en la web publicada.
- **B-10 · Python 3.14 sin propagar:** falta el classifier `Programming Language :: Python :: 3.14` en `pyproject.toml`, y `docs/index.md:84` dice "Starlette ≥ 0.37" mientras `pyproject.toml:28` declara `starlette>=0.23` (y `docs/instalacion.md` dice 0.37 en la línea 43 y 0.23 en la 69).
- **B-11 · `docs/instalacion.md:36` ofrece `gatekeeper-asgi[dev]`** a usuarios finales: ese extra arrastra pytest, mypy, bandit, ruff, hypothesis, fakeredis, fastapi, uvicorn y mkdocs. En producción, no.
- **B-12 · `README.md:190` promete "parser multipart en v0.4"** — la versión actual **es** 0.4.0 y el parser no existe (`ROADMAP.md:49` lo sigue listando como pendiente).
- **B-13 · `corpus/CROSS_REPORT.md` está malformado:** 3 líneas sin cabecera ni título, enlazado desde el README.
- **B-14 · `ROADMAP.md` muy desactualizado:** "## v0.4 — siguiente" con features ya entregadas en 0.4.0 (métricas Prometheus), "83 ataques" cuando son 159, "tag v0.1.0" pendiente cuando ya se publicó 0.4.0.
- **B-15 · `SECURITY_REVIEW.md`** sigue titulado "v0.3.1", dice "1.807 líneas" (son 1.970) y `corpus/events.json:3` lleva `"version": "0.3.1"`.
- **B-16 · No existe `AGENTS.md`.** Dices que lo desarrollas "según tus reglas" de Open Code: esas reglas **no están en el repo**, así que no viajan con el proyecto ni las lee ninguna otra herramienta.

---

## 5. Verificación del informe que te pasaron

He reproducido **uno por uno** cada hallazgo de aquel informe. Resumen honesto:

| Afirmación del informe previo | Veredicto |
|---|---|
| DoS cuadrático en `normalize()` por `re.sub(r"/\*.*?\*/")` | ✅ **Confirmado**, con curva más limpia (×4,08 por duplicación) y confirmación de extremo a extremo |
| "128 KB → 20,9 s" | ✅ **Confirmado**: medí 23,587 s (el sandbox de ellos era más rápido) |
| "1 MiB → ~20 minutos" | ✅ **Confirmado**: extrapolo a ≈1.510 s (25 min) |
| "El parche baja 1 MiB hostil a 0,62 s" | ✅ **Mejor de lo que dijeron**: mi medición da 0,009 s a 128 KB (≈0,07 s a 1 MiB) |
| "Pasan los 2.134 tests" | ⚠️ El repo tiene **2.457** (2.467 con el parche). Su cifra era de una versión anterior |
| "WebSocket sin protección" | ✅ **Confirmado** (6/6 conexiones, sin rate limit) |
| "`application/octet-stream` se salta" | ✅ **Confirmado** |
| "Multipart sin inspeccionar" | ✅ **Confirmado** |
| "JSON legítimo de 1 MiB tarda 2,2 s" | ⚠️ **Matizable**: en esta máquina, **0,81 s**. Sigue siendo caro, no es 2,2 s |
| "300.000 IPs → 258 MB" | ✅ **Confirmado**: 245,8 MB (859 bytes/IP) |
| "El log no cumple lo que promete" | ✅ **Confirmado y es PEOR**: el payload *completo* llega al log, no solo la ruta |
| "Inyección en la terminal del operador" | ✅ **Confirmado** en los dos formatos del CLI |
| "Puntero JSON incorrecto >64 niveles" | ✅ **Confirmado** (y `exclude_fields` tampoco casa) |
| "Claves JSON duplicadas: discrepancia con lo de aguas abajo" | ❌ **No se reproduce como tal**: `json.loads` y Starlette coinciden (última gana). Riesgo real solo con parsers no estándar → **INFO** |
| "FN: `' or ''=`" | ✅ **Confirmado** |
| "FN: booleano ciego `substring(version(),1,1)=5`" | ✅ **Confirmado** |
| "FN: cmd con salto de línea" | ⚠️ **Parcial**: `; cmd` y `\| cmd` con salto **sí** se detectan; solo falla la variante sin separador (`foo\nrm -rf /`) |
| "FN: IP decimal en SSRF" | ✅ **Confirmado** (y también la hex) |
| "FP: `<script>` en prosa" | ✅ **Confirmado** |
| "FP: `1=1 in math`" | ❌ **No se reproduce**: no se detecta |
| "FP: `sleep(8 hours)`" | ✅ **Confirmado** |
| "Web con rutas `corpus/` rotas en PyPI" | ✅ **Confirmado** (y verificado 404 en la web publicada) |
| "Inicio rápido dice que no está en PyPI" | ✅ **Confirmado** |
| "`SECURITY.md` lista 0.3.x como activa" | ✅ **Confirmado** |
| "Solo en español" | ✅ **Confirmado**: no hay README en inglés |
| "Email personal expuesto" | ✅ **Confirmado** en metadatos de PyPI y `docs/seguridad.md:95` |
| "README de PyPI demasiado largo" | ✅ **Confirmado** |
| "Carpetas v0.1/v0.2/v0.3 en la raíz" | ✅ **Confirmado** |
| "sdist de 430 KB con demo, corpus y artículos" | ✅ **Confirmado**: 422,9 KB, 99 entradas, incluye `demo/`, `corpus/`, `docs/`, `benchmarks/` y el `app_servidor.py` suelto |
| "`__init__.py` al 43 % de cobertura" | ✅ **Confirmado** (total 95 %) |
| "Puntuación 74/100" | ≈ **73/100** la mía. Coincidimos |

**Correcciones al informe previo:** el "Inyección de comandos con salto de línea" es más estrecho de lo que dijeron; "1=1 in math" **no** es un falso positivo; las "claves JSON duplicadas" no producen discrepancia con Starlette; y el log filtra **más** de lo que dijeron.

---

## 6. Verificación del parche `fix-redos-comentarios-sql.patch`

**Estado:** untracked, **sin aplicar**. `git apply --check` → **exit 0**, aplica limpio sobre `744fbc7`.

Lo he aplicado en una **copia aislada** (`git apply --directory=.audit/patchtest_v1`) y he medido:

**A · Corrección del DoS**

| Bytes | Antes | Después | Ganancia |
|---:|---:|---:|---:|
| 8.000 | 0,084 s | 0,000 s | – |
| 32.000 | 1,351 s | 0,003 s | **450×** |
| 128.000 | 23,587 s | **0,009 s** | **2.600×** |

Y el escalado pasa de ×4 a ×2 por duplicación: **de O(n²) a O(n)**. Los comentarios versionados `/*!50000` repetidos, que también eran cuadráticos, pasan de 9,548 s a 0,010 s a 128 KB.

**B · No rompe nada**

- Test de regresión propio del parche: **10/10 pasan** en 1,18 s (el código sin parchear tardaría minutos en esas mismas entradas).
- Suite completa con el parche: **2.467 pasan, 1 skipped** (2.457 + sus 10 nuevos). Nota: los 5 fallos que verás si pruebas en una copia sin `.github/` son un artefacto del copiado (`tests/test_workflows.py:21` usa `parents[3]`), **no** del parche.
- Corpus: **cifras idénticas**. Propio 159/159, retenido 94,5 % / 0 FP, CRS 41,0 % / 4,7 % FP, modo cruzado 7/7.

**C · Revisión del código del parche:** la función lineal `_strip_sql_comments()` reproduce la semántica del par de regex original, incluido el caso `/*!50000union*/` (desenvuelve y conserva el SQL), el caso `/**/`, los comentarios anidados y el `/*` sin cerrar (que se deja tal cual). **El parche es correcto.**

**D · Lo que el parche NO arregla:** WebSocket, `octet-stream`, multipart, la fuga del payload al log, el escape del CLI, el tope de claves del rate limiter ni el puntero JSON. El DoS era **el** crítico, no **el único** crítico que queda.

---

## 7. Plan de mejora priorizado

### Sprint 0 — Hoy (bloqueantes, ~1 día)

1. **Aplicar el parche** y publicar **0.4.1**:
   ```bash
   git apply fix-redos-comentarios-sql.patch
   python -m pytest -q          # 2467 tests
   ```
   Sube a `main`, tag `v0.4.1`, deja que `publicar.yml` publique con Trusted Publishing.
2. **Abrir un GitHub Security Advisory** (`https://github.com/Eche-Dev/Gatekeeper/security/advisories/new`) documentando el DoS: sin autenticación, red de alcance medio, impacto alto, parche disponible. Sé honesto: es un tipo de vulnerabilidad que la comunidad respeta por cómo lo reportas, no por si te pillan.
3. **Añadir el test de complejidad temporal** que faltaba: para cada familia de entradas hostiles, que el tiempo crezca **linealmente** (no "que no tarde más de X"). Así el bug no vuelve.

### Sprint 1 — Semana 1 (seguridad de la superficie)

4. **WebSocket**: inspeccionar el handshake (query + cabeceras) y aplicar rate limit al `websocket.connect`. Como mínimo, **documentar el hueco** en `README.md`, `docs/amenazas.md` y `SECURITY.md`.
5. **`application/octet-stream`**: sniff del primer byte (`{`, `[`) y parseo JSON.
6. **Multipart**: parsear el cuerpo y extraer **nombres de campo y `filename`** (mínimo), ignorando el contenido binario de los ficheros.
7. **Sanear la salida del CLI** (`str.translate` sobre C0 + ESC) y aplicar el mismo control al log.
8. **Arreglar la promesa del log**: o dejas de meter el nombre del parámetro en el `field` (usa un hash truncado o un índice), o cambias la documentación. Hoy mienten las dos cosas: la doc dice que no se registra y el código registra el payload.
9. **Tope de claves** en `MemoryBackend` + agrupación IPv6 por /64.

### Sprint 2 — Semana 2 (corrección y documentación)

10. Corregir `rl_backend_unavailable` → `rate_backend_error` en los 5 ficheros.
11. Corregir los cuerpos 429/503 en `docs/api.md`, `docs/uso.md`, `docs/despliegue.md`.
12. Corregir el ejemplo de `custom_rules` (a `Config`), borrar `Config.validate()`, y corregir la afirmación de HSTS (o implementar el salto por esquema).
13. Mover los dos patrones SQLi de `sensitive_files` a `sqli` y borrar el duplicado.
14. Arreglar `_child_pointer()` para que añada el segmento y el puntero siga siendo correcto a partir de 64 niveles.
15. **Refrescar la web publicada**: eliminar los 4 avisos de "no está en PyPI", añadir sección "Desde PyPI" en `docs/instalacion.md`, actualizar la tabla de versiones de `SECURITY.md`, subir el umbral CRS de CI a la línea base real, y **convertir los enlaces relativos del README en absolutos a GitHub**.
16. Sanear los textos: "aThird parties", "functionality", "consequences", la frase truncada de "Comparar rendimiento", el "exímino".
17. **README en inglés** (o al menos una sección bilingüe) y mover el email personal a GitHub Advisories.

### Sprint 3 — Semana 3 (mantenibilidad)

18. **Aplanar el repo**: mover el paquete a `src/` + `tests/` + `docs/` en la raíz y dejar las versiones en tags. Esto rompe enlaces y scripts, así que hazlo **antes** de 1.0, no después.
19. **Excluir del sdist** `demo/`, `corpus/`, `benchmarks/`, `docs/` y el `app_servidor.py` suelto → sdist de ~60 KB en vez de 423 KB.
20. **Crear `AGENTS.md`** con las reglas con las que desarrollas (las que hoy solo existen en tu cabeza).
21. Actualizar `ROADMAP.md`, `SECURITY_REVIEW.md` y `corpus/events.json` (siguen en 0.3.1) y regenerar `corpus/CROSS_REPORT.md`.
22. Bajar `max_body_size` por defecto (1 MiB es generoso para un WAF) y añadir un **presupuesto de strings por petición**.

---

## 8. Qué NO he podido verificar

- **Si los ficheros publicados en PyPI corresponden exactamente a este commit.** La attestation apunta a `c964e861…`, distinto del `HEAD` local `744fbc7`.
- **Los enlaces `corpus/` de PyPI**: el anti-bot de PyPI intercepta esas subrutas y devuelve un interstitial "Client Challenge" en lugar del fichero o un 404. No puedo afirmar el código de estado; sí afirmo que PyPI no aloja ficheros del repo y que los equivalentes absolutos en GitHub funcionan. En la web publicada el 404 **sí** está verificado.
- **Redis real**: los tests de Redis requieren un servidor; validé la lógica por lectura y por tests, no levantando una instancia.
- **El estado del repo en GitHub**: issues, ramas y contenido de `main` no los he auditado (solo existencia y el `origin` configurado).
- **La matriz de compatibilidad** (`tools/compat_matrix.py`): no la he reproducido, solo la he contrastado con la documentación.

---

## 9. Reproducir esta auditoría

Los scripts están en `.audit/` (temporales, puedes borrarlos):

| Script | Qué hace |
|---|---|
| `.audit/redos_bench.py` | Mide la curva de coste de `normalize()`/`scan()` en procesos aislados con timeout duro. `GK_SRC` permite apuntarlo a una copia parcheada |
| `.audit/e2e_dos.py` | Demuestra el DoS de extremo a extremo por una sola petición HTTP |
| `.audit/security_probe.py` | 16 pruebas de ataque: WS, octet-stream, multipart, punteros JSON, memoria del rate limiter, log, CLI, FN/FP |
| `.audit/config_probe.py` | 18 controles de configuración: proxy, XFF, CIDR, `allow_paths`, cabeceras, content-types |
| `.audit/log_leak_probe.py` | Demuestra en qué casos el payload completo llega al log |
| `.audit/family_check.py` | Comprueba la atribución de familias de reglas |
| `.audit/patchtest_v1/` | Copia del paquete **con el parche aplicado**, para comparar (puedes borrarla) |

---

*Auditoría realizada sobre el código del repositorio y sobre el paquete publicado en PyPI. Todas las cifras de este informe son reproducibles con los scripts indicados.*
