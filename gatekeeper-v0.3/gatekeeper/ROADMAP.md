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

## v0.4 — siguiente
- [ ] Inspección de `multipart/form-data` (nombres de campo y de archivo, no el contenido)
- [ ] Métricas Prometheus (contadores de bloqueos y de rate limit)
- [ ] Importar payloads del OWASP Core Rule Set (Apache 2.0) con atribución
- [ ] Integración con Starlette/FastAPI como dependencia declarada en tests
- [ ] Decodificación de entidades HTML y de UTF-8 sobre-long para cerrar los
      falsos negativos documentados

## Publicación (pendiente hasta cerrar el proyecto)
- [ ] Nombre y versión finales, TestPyPI, tag v0.1.0 y release notes
- [ ] GIF de antes/después con `examples/vulnerable_vs_protected.py`
