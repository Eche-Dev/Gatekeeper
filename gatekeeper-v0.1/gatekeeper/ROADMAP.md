# Hoja de ruta

## v0.1 — núcleo (este scaffold)
- [x] Rate limiting en memoria (ventana deslizante)
- [x] Cabeceras de seguridad por defecto
- [x] Reglas sqli / xss / path traversal sobre ruta + query string
- [x] Modo `monitor_only` y lista de IPs bloqueadas
- [x] Auditoría en JSON (logger `gatekeeper`)
- [ ] Benchmark de latencia por petición (`benchmarks/`)
- [ ] README con GIF antes/después + tabla de qué cubre y qué NO
- [ ] Publicar en TestPyPI y PyPI, tag `v0.1.0`

## v0.2
- Inspección del body (JSON/form) con límite de tamaño
- Reglas personalizadas por YAML
- Allowlist por ruta (excluir `/docs`, `/health`)

## v0.3
- Backend de rate limiting en Redis (multi-proceso)
- Métricas Prometheus
- Corpus de payloads OWASP para medir falsos positivos/negativos
