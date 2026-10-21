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
- [ ] Benchmark de latencia por petición (`benchmarks/`)
- [ ] GIF antes/después con `examples/vulnerable_vs_protected.py`

## v0.3
- Backend de rate limiting en Redis (multi-proceso)
- Métricas Prometheus
- Corpus de payloads OWASP para medir falsos positivos/negativos
- Inspección de multipart (nombres de campo y de archivo)

## Publicación (pendiente hasta cerrar el proyecto completo)
- [ ] TestPyPI -> PyPI, tag, release notes
