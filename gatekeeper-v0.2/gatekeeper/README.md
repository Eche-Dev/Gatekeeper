# Gatekeeper

Middleware ASGI de seguridad para FastAPI/Starlette. Una capa extra delante de tu app:
rate limiting, cabeceras seguras, detección de patrones de ataque en query y body,
reglas propias por YAML y auditoría en JSON.

```bash
pip install gatekeeper-asgi            # núcleo
pip install "gatekeeper-asgi[yaml]"    # + configuración por YAML
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
# o: Config.from_yaml("gatekeeper.yaml")   (ver examples/gatekeeper.yaml)
```

## Qué cubre
| Protección | Detalle |
|---|---|
| Rate limiting | Ventana deslizante por IP, en memoria, 429 + `Retry-After`; limpieza automática de IPs inactivas |
| Cabeceras | nosniff, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy (no pisa las de tu app) |
| Patrones (query) | SQLi, XSS, path traversal en ruta y query string, con decodificación doble |
| Patrones (body) | `application/json` y `application/x-www-form-urlencoded`: claves y valores, a cualquier profundidad |
| Límite de body | `max_body_size` (1 MiB por defecto) -> 413, también sin `Content-Length` |
| Reglas propias | Regex en YAML o `Config(custom_rules=...)`, validadas al arrancar |
| Exclusión de rutas | `allow_paths` (globs). Rutas con `..`, `\` o codificación residual nunca se eximen |
| Auditoría | Eventos JSON en el logger `gatekeeper`; **nunca** incluye el contenido del payload |
| Modo monitor | `monitor_only=True` registra sin bloquear, para medir falsos positivos |

## Qué NO cubre
- `multipart/form-data` y otros content-types no se inspeccionan ni se almacenan en memoria (subidas de archivos pasan intactas).
- La detección por regex tiene falsos positivos/negativos: **no sustituye** a consultas parametrizadas ni a un WAF.
- Cada valor del body se analiza por separado: un ataque repartido en varios campos no se detecta.
- El rate limiting es por proceso: con varios workers, cada uno cuenta aparte.
- `trust_proxy=False` por defecto; actívalo solo detrás de un proxy de confianza.
- Un body JSON/form mayor que `max_body_size` se rechaza: súbelo o usa `inspect_body=False` si tu API recibe payloads grandes.
- `allow_paths` exime de inspección, no de rate limit ni de bloqueo de IP.

## Configuración defensiva
`Config` falla al arrancar, no en producción: claves desconocidas (un typo como `rate_limt`), regex inválidas o vacías, nombres de regla duplicados y `disabled_rules` inexistentes lanzan `ValueError`.
Las reglas propias se evalúan sobre el texto **decodificado y en minúsculas**; evita patrones con backtracking catastrófico, los patrones propios no están acotados por Gatekeeper.

## Desarrollo
```bash
pip install -e ".[dev]"
ruff check . && bandit -r src -q && pytest --cov=gatekeeper
```

Licencia MIT.
