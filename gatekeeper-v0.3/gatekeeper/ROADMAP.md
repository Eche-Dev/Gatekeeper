# Hoja de ruta

## v0.1 — núcleo
- [x] Rate limiting en memoria (ventana deslizante)
- [x] Cabeceras de seguridad por defecto
- [x] Reglas sqli / xss / path traversal sobre ruta + query string
- [x] Modo `monitor_only` y lista de IPs bloqueadas
- [x] Auditoría en JSON (logger `gatekeeper`)

## v0.2 — body, YAML, exclusiones
- [x] Inspección del body JSON y form-urlencoded con límite de tamaño (413)
- [x] Reglas personalizadas y configuración por YAML (`Config.from_yaml`)
- [x] `allow_paths` resistente a traversal
- [x] Regex acotadas (anti-ReDoS) y limpieza de IPs inactivas en el rate limiter

## v0.3 — medida, Redis y honestidad
- [x] Corpus público de 83 ataques + 62 peticiones benignas (`corpus/`) con
      procedencia y límites documentados
- [x] Evaluador `tools/evaluate.py`: tasa de detección, falsos positivos y
      umbral de CI (`--check`)
- [x] Reglas nuevas midiendo antes y después: sondeo de columnas, EXISTS,
      error-based, time-based de SQL Server/PostgreSQL, ficheros sensibles
- [x] Rate limiting en Redis con script Lua atómico y cliente `redis.asyncio`
      (no bloquea el event loop), política `rate_fail_open`
- [x] Benchmark de latencia por petición (`benchmarks/latency.py`)
- [x] mypy estricto + `py.typed` (PEP 561), `CHANGELOG.md`, `SECURITY.md`,
      build + `twine check` y prueba de instalación limpia en CI
- [x] Corpus **externo** de OWASP CRS (1379 tests, Apache-2.0 con atribución y
      commit de procedencia) como segunda batería de medida, con guarda de
      regresión en CI
- [x] Fuzzing con hypothesis (`tests/test_fuzz.py`): propiedades sobre
      `scan`, `normalize`, `extract_strings`, `Config` y `allow_paths`
- [x] ReDoS cuadrático de los cuantificadores de blancos medido y corregido
      (`or` + 80k espacios: 118 s → <1 s) con test de regresión
- [x] Documentación con MkDocs Material (`docs/`), CONTRIBUTING, código de
      conducta y plantillas de issues/PR; workflows en la raíz del repo para
      que GitHub los ejecute
- [x] Demo desplegable (`demo/`: playground con payloads, Vercel/Docker) con
      el GIF de una sesión real (`docs/assets/demo.gif`)
- [x] Artículo de publicación (`ARTICLE.md`)
- [x] GitHub Pages publicando la docs en cada push a main
      (https://eche-dev.github.io/Gatekeeper/)
- [ ] Demo en Vercel (`vercel --prod` desde `demo/`) — credenciales del
      propietario
- [ ] Publicación del artículo (`ARTICLE.md` listo, sin placeholders)
- [ ] (opcional) CodeQL y Release v0.3.0 en GitHub

## v0.4 — siguiente
- [ ] Inspección de `multipart/form-data` (nombres de campo y de archivo, no el contenido)
- [ ] Métricas Prometheus (contadores de bloqueos y de rate limit)
- [ ] Integración con Starlette/FastAPI como dependencia declarada en tests
- [ ] Decodificación de entidades HTML y de UTF-8 sobre-long para cerrar los
      falsos negativos documentados

## Publicación (pendiente hasta cerrar el proyecto)
- [ ] Nombre y versión finales, TestPyPI, tag v0.1.0 y release notes
- [ ] GIF de antes/después con `examples/vulnerable_vs_protected.py`
