# Changelog

Todo lo notable de Gatekeeper. El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y las versiones siguen [SemVer](https://semver.org/lang/es/spec/v2.0.0.html).

## [0.3.1] - 2026-10-22

### Añadido
- **Once firmas nuevas contra los misses del corpus de OWASP CRS**, que suben la
  detección externa del **21,0% (238/1135) al 27,1% (308/1135)** sin superar el
  techo de falsos positivos (4,7% sobre los negativos de CRS, gate ≤ 5%). No
  son casos copiados del examen: cada una cubre una técnica documentada.
  - SQLi: concatenación por barras seguida de palabra clave (`|| select`),
    funciones SQL en un parámetro (`ABS(`, `CAST(`, `CHAR(`, `COALESCE(`…) y
    operadores tolerantes de blindaje (`REGEXP`, `LIKE NULL`, `>>`, `&&`).
  - XSS: HTML con namespace (`<x:script xmlns:x=…>`, que evade la firma
    `<script` porque la etiqueta lleva prefijo), etiquetas SVG/MathML y APIs de
    JS que ejecutan o acceden al DOM (`eval(`, `setInterval(`, `document.cookie`,
    `window.`).
  - Ficheros sensibles: rutas de reconocimiento del sistema (`/sys/class`,
    `/sys/firmware`) y configuración de herramientas que antes no estaban
    (`/.claude/`, `/.cursor/`, `/.kube/`, `/.gnupg/`).
- **Pre filtro de familias** (`PREFILTER_LITERALS`): antes de evaluar las 60
  regex se comprueba si el texto contiene algún literal de cada familia
  (`script`, `union`, `/etc/`, `jndi`…) con una búsqueda de subcadena en C. Si no
  lo contiene, esa familia se descarta sin ejecutar una sola regex. Medido
  sobre texto limpio: **8× más rápido** (un payload de 250 caracteres pasa de
  262 a 33 µs). Solo se aplica a partir de 128 caracteres: por debajo, las 156
  comparaciones `in` no compensan y el escaneo corto ya es rápido. El
  escenario de ataque queda en 1,04× (ni mejor ni peor) y no hay ningún
  regresión. No cambia qué se detecta: `tests/test_prefilter.py` compara el
  escaneo con y sin pre filtro sobre los 1582 valores de ambos corpus y exige
  el mismo resultado.
- **Workflow de publicación en PyPI con Trusted Publishing**
  (`.github/workflows/publicar.yml`): sin token de API en el repo. GitHub
  demuestra su identidad a PyPI con OIDC y PyPI emite un token de un solo uso,
  así que lo único que puede publicar en tu nombre es quien pueda modificar el
  repo. Dispara al publicar una release, valida antes que la versión del tag
  coincida con la de `pyproject.toml`, que el paquete importe y que la CLI
  funcione, y tiene un `dry_run` manual que valida sin publicar nada.
- **Job `audit` en CI** con `pip-audit`: audita el runtime (lo que arrastra
  Gatekeeper: starlette y sus transitivas) y el entorno de desarrollo, en venvs
  limpios para que el resultado no dependa de la imagen del runner. Una CVE en
  una dependencia transitiva ya no espera a que alguien la reporte.
- Metadata de PyPI completa en `pyproject.toml`: `Homepage`, `Documentation`,
  `Repository`, `Changelog`, `Issues` y `Funding`, más los classifiers que faltaban
  (`Development Status`, `Environment`, `Intended Audience`, `OS Independent`).
- **Python 3.13** en la matriz de CI: probarla aquí es más barato que descubrir
  que se rompió en el release de un usuario.
- **Percentiles por petición real** (p50/p95/p99/máx) en `benchmarks/latency.py`,
  en lugar de la media por ronda: la media escondía la cola, que es lo que nota
  un usuario. El escenario «completo» que la media rondaba en ~90 µs tiene un
  p95 de 123 µs y un p99 de 149 µs.
- **Comparación de dos versiones** (`--save` / `--baseline`): mide en tu máquina,
  cambia el código, mide otra vez y te dice si algún escenario empeoró más del
  margen (25 % por defecto). Es la única comparación fiable y la que se usa antes
  de abrir un PR que toca el camino caliente.
- **Packs de reglas opt-in** (`rule_packs`): `minimal`, `api`, `web`,
  `infrastructure` y `strict` agrupan las familias por la superficie que la
  app expone. Sin configurar nada se siguen evaluando las once (los packs no
  cambian el defecto); un pack desconocido es `ValueError` al arrancar, para que
  un typo no deje la app sin protección en silencio.
- **Exclusiones por campo** (`exclude_fields`): parámetros de query, cabeceras
  y punteros JSON que quedan exentos de inspección, con globs `fnmatch` (el
  puntero `/user/bio` también casa por `bio`). La detección que cruza varios
  campos se conserva: el campo exento se quita del objetivo y el resto se sigue
  vigilando.
- **CLI `gatekeeper report`**: lee el log de tráfico (el JSON del logger de
  Gatekeeper o un access log genérico), agrupa por regla, ruta y campo, y
  propone un `exclude_fields` o un `disabled_rules` listo para copiar. Salida
  `--json` para máquinas. Cierra el ciclo que `monitor_only=True` promete: medir
  los falsos positivos del tráfico real antes de bloquear.
- **Siete familias de detección** con su regla, sus límites de falso positivo
  medidos y su caso en el corpus:
  - `nosql`: operadores de inyección Mongo `$ne`, `$nin`, `$where` y `$regex`
    (login bypass y ejecución de JS). `$gt`/`$lt`/`$in` se dejan fuera a
    propósito: los usan los filtros legítimos.
  - `cmdi`: separador shell + binario (`; ls`, `| cat`, `&& whoami`, `$(id)`,
    `` `uname` ``), LOLBins de Windows (`powershell.exe`), webshells PHP
    (`;system('`, `shell_exec(`) y reverse shells (`/dev/tcp/`).
  - `ssrf`: IPs de metadata cloud (AWS/GCP/Azure/Alibaba) y esquemas de lectura
    local (`file://`, `gopher://`, `dict://`, `jar://`, `netdoc://`, `tftp://`).
    `localhost` no se bloquea: OAuth de desarrollo y webhooks locales son
    tráfico legítimo.
  - `ssti`: la aritmética canónica de plantillas (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`,
    `#{7*7}`) y el acceso a objetos peligrosos (`config`, `self`, `request`,
    `__class__`, `__subclasses__`).
  - `crlf`: response splitting e inyección de cabeceras (salto de línea seguido
    de nombre de cabecera, sea CRLF real decodificado de `%0d%0a` o literal
    `\r\n`).
  - `log4shell`: `${jndi:…}` con sus ofuscaciones (`${${::-j}ndi:`,
    `${jndi:${lower:l}…}`), JNDI sin envoltorio y la cadena de lookups que
    exfiltra secretos (`${env:AWS_SECRET…}`).
  - `proto_pollution`: `__proto__` en cualquier posición y
    `constructor.prototype`.
- **Evasiones** que antes pasaban intactas:
  - **Entidades HTML nombradas** (`&lt;script`, `javascript&colon;`) resueltas
    como sus equivalentes numéricos, por rondas de decodificación.
  - **Esquema con tab o salto de línea** (`java\tscript:alert(1)`, `java&#9;script:`):
    el navegador descarta tab/NL/CR en cualquier punto de una URL (WHATWG), así
    que el esquema sigue siendo ejecutable. Solo se aceptan contenedores, no
    espacios: `java script:` en prosa no es un esquema y no salta.
  - **Comentarios versionados de MySQL** (`/*!50000union*/`) desenvueltos a su
    contenido (`union`) en lugar de borrarse: MySQL los ejecuta, y borrar el
    contenido convertía el payload en texto invisible para el inspector.
- `docs/amenazas.md`: **modelo de amenazas** con el desglose de las once familias,
  el supuesto de atacante, los transportes inspeccionados, las fronteras de falso
  positivo de cada firma y lo que NO cubre Gatekeeper.
- Detección de **entidades HTML numéricas** en `decode()`: `&#60;script&#62;`
  y `&#106;avascript:` ya no pasan intactos; rango acotado para que `&#99999999;`
  no reviente (protegido por test).
- Normalización de **UTF-8 sobre-long**: `%c0%af` → `/` y `%c0%ae` → `.` en sus
  formas porcentual (sustituida antes de decodificar) y de caracteres
  (`%u00c0%u00af`).
- Firma de SQLi **blind boolean**: `ASCII(SUBSTRING(nombre,1,1))>64`.
- `/WEB-INF/` como ruta sensible (por especificación Java EE es innaccesible
  desde un navegador; pedirla es exploración).
- **Inspección de cabeceras** con `inspect_headers` (por defecto `user-agent`,
  `referer`, `cookie` y `x-forwarded-for`): los payloads que viajan en
  `User-Agent`/`Referer`/`Cookie` ya no pasan sin revisarse.
- `blocked_ips` acepta **CIDR e IPv6** (`10.0.0.0/8`), además de IP exacta e
  identificador literal del peer; una máscara mal escrita es `ValueError` al
  arrancar, no un bloqueo ausente en silencio.
- `trusted_proxies` y `trusted_proxy_cidrs`: cuántos hops tuyos hay en la cadena
  XFF y desde qué redes se cree su valor.
- La auditoría de ataques añade **`field`** (JSON pointer o parámetro culpable),
  **`pattern`** (la regex que disparó) y **`entry`** (la red que bloqueó la IP);
  el contenido del payload sigue sin registrarse.

### Corregido
- **Actions fijadas a SHA completo** en todos los workflows (aviso de
  SonarCloud, `Security Rating on New Code`): un tag como `actions/checkout@v7`
  es una promesa móvil —quien mantiene la action puede re-apuntarlo a otro
  commit después de tu revisión— y en el job de publicación a PyPI eso es
  especialmente-sensitive. Los SHA se resolvieron contra la API de GitHub y
  cada pin lleva su comentario `# v7`, que es lo que lee Dependabot para seguir
  ofreciendo actualizaciones: el pin no te deja atrapado en una versión vieja.
- **Herramientas de CI fijadas a versión exacta** (`build==1.6.1`,
  `twine==7.0.0`, `mypy==2.4.0`, `pip-audit==2.10.1`) y con
  `--only-binary ":all:"` para que pip no ejecute scripts de instalación de un
  paquete comprometido (avisos de SonarCloud). Verificado que cada versión
  existe y que el pipeline de build funciona con ellas.
- **`permissions` explícitos en los workflows** (aviso de CodeQL
  `actions/missing-workflow-permissions`): sin ese bloque los workflows heredan
  los permisos del repositorio, que en repos anteriores a 2023 son read-write.
  Ahora es `contents: read` en todo lo que no publica, y solo el despliegue de
  docs y la publicación en PyPI piden `write`/`id-token`, declarados en su job.
- **Dependabot abría PRs duplicadas**: había dos entradas de pip y una estaba
  anidada dentro de la otra (`/gatekeeper-v0.3/gatekeeper` y
  `/…/gatekeeper/demo`), así que notificaba lo mismo dos veces — una pedía
  `fastapi>=0.146.0` y la otra `>=0.148.0`, y competían por el merge. Se elimina
  la entrada redundante y se agrupan las actualizaciones en una sola PR.
- **[seguridad]** `X-Forwarded-For` se tomaba de izquierda a derecha
  (`ips[0]`, un valor que escribe el cliente): rotándolo se evadían el rate
  limit y `blocked_ips`. Se lee de derecha a izquierda (`ips[-trusted_proxies]`)
  y, con `trusted_proxy_cidrs`, el XFF de un peer que no es tu proxy se ignora.
- **[seguridad]** Solo se inspeccionaban bodies JSON/form: un POST
  `text/plain` o sin `content-type` pasaba sin revisarse aunque
  `await request.json()` lo parseara igual. Ahora todo content-type textual se
  inspecciona (denylist de binarios; `multipart` queda para v0.4).
- **[seguridad]** Las cabeceras no pasaban por las reglas: `User-Agent`,
  `Referer` y `Cookie` admitían payloads sin salir del middleware
  (resuelto con `inspect_headers`, arriba).
- `blocked_ips` solo hacía coincidencia exacta; con un rango de red
  (`10.0.0.0/8`) el bloqueo no existía aunque la configuración lo dijera.

### Cambiado
- El benchmark mide percentiles por petición real (p50/p95/p99) en lugar de la
  media por ronda: una media mezcla la pausa del recolector de basura con el
  trabajo real del middleware y esconde la cola de latencia.
- Corpus propio: **148/148 (100.0%)**, 0 FP sin documentar, 5 FP documentados (los
  cuatro de antes más `benign-071`, búsquedas sobre `__proto__`). El gate de CI
  sube de ≥ 90% a **100%**: cualquier regresión de detección deja CI en rojo.
- Corpus CRS: **27.1% (308/1135)** con 4.7% de FP sobre sus negativos. El gate
  de detección externa se queda en ≥ 19% (es una guarda de regresión, no una
  promesa) y el de FP en ≤ 5%.
- Corpus CRS recalibrado con las cabeceras y los bodies textuales en alcance:
  **21.0% (238/1135)** con 3.9% de FP; los excluidos bajan de 212 a 12 (solo
  binarios y cabeceras fuera de `inspect_headers`). Gate de CI: ≥ 19%.

## [0.3.0] - 2026-10-21

### Añadido
- Rate limiting en Redis (`rate_backend="redis"`): ventana deslizante atómica con
  script Lua, cliente `redis.asyncio` (no bloquea el event loop) y opción `redis_url`.
- Política de fallo del backend: `rate_fail_open` (por defecto `True`) decide si se
  sigue admitiendo o se devuelve 503 cuando Redis no responde; ambos casos se auditan.
- Corpus público de evaluación en `corpus/`: 83 payloads de ataque y 62 peticiones
  benignas, con procedencia y límites documentados.
- **Corpus externo** `corpus/crs_payloads.json`: 1379 tests de regresión de
  [OWASP CRS](https://github.com/coreruleset/coreruleset) (Apache-2.0, commit
  `30cb436`), con licencia incluida e importador `tools/import_crs.py`. Sus
  umbrales entran en `evaluate.py --check` como guarda de regresión sobre la
  línea base medida (18.8% de detección, 4.3% de FP en las familias 930/941/942).
- Tests de propiedades con **hypothesis** (`tests/test_fuzz.py`): ninguna entrada
  arbitraria revienta `scan()`, `normalize()`, `extract_strings()` ni `Config`;
  `allow_paths` nunca exime una ruta con indicios de traversal.
- Documentación con **MkDocs Material** en `docs/` (guía de uso, detección y
  medición, seguridad, API y desarrollo), con `mkdocs build --strict` en CI y
  despliegue en GitHub Pages en cada push a `main`.
- Gobernanza en la raíz del repo: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  plantillas de issues y PR, y workflows movidos a `.github/` de la raíz
  (GitHub solo ejecuta los workflows y lee las plantillas de raíz).
- Demo desplegable en `demo/`: app FastAPI de juguete con playground de
  payloads, configs para Vercel y Docker, y el GIF de una sesión real
  (`docs/assets/demo.gif`, regenerable con `demo/make_gif.py`).
- `ARTICLE.md`: artículo listo para publicar (dev.to / blog personal) sobre la
  medición honesta con dos corpus y el ReDoS cuadrático de v0.3.
- `tools/evaluate.py`: mide tasa de detección y falsos positivos; `--check` sirve de
  umbral en CI y `--write-report` genera `corpus/REPORT.md`.
- `benchmarks/latency.py`: latencia añadida por petición, por escenario.
- Regla `sensitive_files` (`/etc/shadow`, `/proc/self/environ`, `win.ini`,
  `.ssh/id_rsa`, `.env`), ampliada en esta versión a `.ssh/*`, `.aws/credentials`,
  `.docker/secrets`, `.git/config` y `/etc/subuid`.
- Comprobación de tipos estricta con mypy y marcador `py.typed` (PEP 561).

### Cambiado
- Reglas `sqli` ampliadas con firmas genéricas: sondeo de columnas (`ORDER BY 10`),
  subconsultas (`EXISTS(SELECT`), time-based de SQL Server/PostgreSQL
  (`WAITFOR DELAY`, `pg_sleep`), error-based (`EXTRACTVALUE`, `UPDATEXML`,
  `CONVERT(int`), consultas apiladas con `SELECT/INSERT/UPDATE/EXEC` y `xp_cmdshell`,
  tautología canónica (`?a=1=1`) y con literales (`or 'a'='a'`).
- `decode()` entiende los escapes Unicode de IIS `%uXXXX` (mayúsculas o no) y
  `normalize()` aplica NFKC con un segundo pase de decodificación: `＜script` y
  `％Ｕ００２７` se convierten antes de evaluar.
- `normalize()` elimina los comentarios SQL de ofuscación (`/**/`) antes de evaluar.
- XSS: handlers de evento sin etiqueta delante (`"onmouseover=`, ` onload=`).
- `path_traversal` exige frontera de segmento: `foo../bar` es un nombre de fichero,
  no un salto de directorio.
- El límite de `benchmark()` se restaura (se había perdido en v0.2).

### Corregido
- 6 falsos negativos y 4 falsos positivos detectados con el nuevo corpus y corregidos.
- **ReDoS cuadrático** en las reglas de SQLi: dos cuantificadores de blancos
  adyacentes (`\s*[(']?\s*`) hacían O(n²) — `or` + 80.000 espacios tardaba 118 s.
  Todos los cuantificadores acotados (`\s{0,16}`), ahora lineal: <1 s con
  entradas de 1M de caracteres. Encontrado por la batería de rendimiento nueva.

### Conocido
- Falsos positivos y negativos documentados en `corpus/README.md`. No se ocultan:
  son límites aceptados y medibles.
- Sobre el corpus externo de CRS: los 8 FP son texto legítimo que cita vectores de
  inyección (sesgo inevitable de un WAF heurístico) y los misses restantes son
  obfuscación sin firma genérica; se listan completos en `corpus/REPORT.md`.

## [0.2.0] - 2026-10-21

### Añadido
- Inspección del body `application/json` y `application/x-www-form-urlencoded`
  (claves y valores, a cualquier profundidad) con `max_body_size` → 413.
- Reglas personalizadas (`custom_rules`) y configuración por YAML (`Config.from_yaml`).
- `allow_paths` con globs, resistente a traversal y codificación residual.

### Corregido
- ReDoS en la regla de XSS: cuantificadores acotados.
- Fuga de memoria en el rate limiter: se limpian las IPs inactivas.

## [0.1.0] - 2026-10-21

### Añadido
- Rate limiting en memoria con ventana deslizante y `Retry-After`.
- Cabeceras de seguridad por defecto (no pisa las de la app).
- Reglas `sqli`, `xss` y `path_traversal` sobre ruta y query string.
- Modo `monitor_only`, lista de IPs bloqueadas y auditoría en JSON.
