# Changelog

Todo lo notable de Gatekeeper. El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y las versiones siguen [SemVer](https://semver.org/lang/es/spec/v2.0.0.html).

## [0.3.1] - 2026-10-22

### Añadido
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
- Corpus propio: **83/83 (100.0%)**, 0 FP sin documentar. El gate de CI sube
  de ≥ 90% a **100%**: cualquier regresión de detección deja CI en rojo.
- Corpus CRS recalibrado con las cabeceras y los bodies textuales en alcance:
  **19.3% (219/1135)** con 3.9% de FP; los excluidos bajan de 212 a 12 (solo
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
