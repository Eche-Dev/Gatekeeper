# Gatekeeper

Middleware ASGI de seguridad para FastAPI/Starlette. Una capa extra delante de tu
app: rate limiting, cabeceras seguras, detección de patrones de ataque en query y
body, reglas propias por YAML y auditoría en JSON.

```bash
pip install gatekeeper-asgi             # núcleo
pip install "gatekeeper-asgi[yaml]"     # + configuración por YAML
pip install "gatekeeper-asgi[redis]"    # + rate limit compartido entre workers
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
# o con Redis para que todos los workers cuenten lo mismo:
# Config(rate_backend="redis", redis_url="redis://localhost:6379/0")
# o: Config.from_yaml("gatekeeper.yaml")   (ver examples/gatekeeper.yaml)
```

## Qué cubre

| Protección | Detalle |
|---|---|
| Rate limiting | Ventana deslizante por IP. En memoria (un proceso) o en Redis con script Lua atómico (compartido entre workers), vía `redis.asyncio`, sin bloquear el event loop |
| Cabeceras | nosniff, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy (no pisa las de tu app) |
| SQLi | UNION SELECT, tautologías (`' OR '1'='1`), consultas apiladas (`; DROP`), time-based (`sleep()`, `WAITFOR DELAY`), error-based (`EXTRACTVALUE`, `CONVERT`), sondeo de columnas (`ORDER BY 10`) |
| XSS | `<script>`, handlers de evento (`onerror=`, `onload=`...), `javascript:`, `data:text/html`, con doble codificación |
| Path traversal | `../`, `..\`, `..;/`, con decodificación repetida |
| Ficheros sensibles | `/etc/shadow`, `/proc/self/environ`, `win.ini`, `.ssh/id_rsa`, `.env` (exigen separador de ruta: `?q=.env` pasa) |
| Límite de body | `max_body_size` (1 MiB por defecto) → 413, también sin `Content-Length` |
| Reglas propias | Regex en YAML o `Config(custom_rules=...)`, validadas al arrancar |
| Exclusión de rutas | `allow_paths` (globs). Rutas con `..`, `\` o codificación residual nunca se eximen |
| Auditoría | Eventos JSON en el logger `gatekeeper`; **nunca** incluye el contenido del payload |
| Modo monitor | `monitor_only=True` registra sin bloquear, para medir falsos positivos en tu tráfico real |

## Qué mide (no qué promete)

Las reglas se evalúan contra un corpus público de 83 payloads de ataque y 62
peticiones legítimas ([corpus/](corpus/), procedencia documentada):

| Métrica | Valor |
|---|---|
| Ataques detectados | 78 / 83 (**94.0%**) |
| Falsos negativos sin documentar | 0 |
| Peticiones legítimas bloqueadas sin documentar | **0** / 62 |
| Falsos positivos documentados (límites aceptados) | 4 |
| Falsos negativos documentados (límites aceptados) | 5 |

El detalle, incluidos los payloads que se escapan y por qué, está en
[corpus/REPORT.md](corpus/REPORT.md). El workflow falla si una regla nueva empeora
esas cifras (`python tools/evaluate.py --check`).

## Latencia

`python benchmarks/latency.py` mide el coste por petición en tu máquina
(Python 3.14, portátil, sin red):

| Escenario | µs/petición | µs añadidos |
|---|---|---|
| sin middleware (base) | 12.95 | — |
| solo cabeceras | 24.52 | +11.56 |
| inspección (query + body) | 42.63 | +29.67 |
| rate limit solo | 26.22 | +13.27 |
| completo (inspección + rate limit) | 43.81 | +30.86 |
| request atacante (403 temprano) | 20.49 | +7.54 |

Son microsegundos relativos, no una promesa de latencia: sirve para comparar
escenarios y detectar regresiones.

## Qué NO cubre

- La detección por regex tiene falsos positivos y falsos negativos: **no sustituye**
  a consultas parametrizadas, a validación de entradas ni a un WAF.
- `multipart/form-data` no se inspecciona (las subidas de archivos pasan intactas).
- Cada valor del body se analiza por separado: un ataque repartido en varios campos no se detecta.
- No decodifica entidades HTML (`&#60;script&#62;`) ni UTF-8 sobre-long (`%c0%af`).
- Con `rate_backend="memory"` y varios workers, el límite efectivo se multiplica: usa Redis.
- Si Redis no responde, `rate_fail_open=True` (por defecto) sigue admitiendo peticiones; ponlo a `False` si prefieres 503.
- `trust_proxy=False` por defecto; actívalo solo detrás de un proxy de confianza.
- Un body JSON/form mayor que `max_body_size` se rechaza: súbelo o usa `inspect_body=False`.
- `allow_paths` exime de inspección, no de rate limit ni de bloqueo de IP.

## Configuración

| Opción | Por defecto | Descripción |
|---|---|---|
| `rate_limit` / `rate_window` | `100` / `60` | peticiones permitidas por IP y ventana (0 desactiva) |
| `rate_backend` | `memory` | `memory` o `redis` |
| `redis_url` / `redis_prefix` | `redis://localhost:6379/0` / `gatekeeper:rl:` | conexión y prefijo de claves |
| `rate_fail_open` | `True` | política si Redis no responde: admitir o 503 |
| `inspect_requests` / `inspect_body` | `True` | inspección de query y de body |
| `monitor_only` | `False` | registrar sin bloquear |
| `disabled_rules` | `∅` | `sqli`, `xss`, `path_traversal`, `sensitive_files` o tus reglas |
| `custom_rules` | `∅` | `{nombre: regex}` o lista `{name, pattern}` |
| `max_body_size` | `1 MiB` | límite del body inspeccionado |
| `allow_paths` | `[]` | globs exentos de inspección |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | bloqueo directo y uso de `X-Forwarded-For` |
| `security_headers` | ver fuente | `None` = cabeceras por defecto |

`Config` falla al arrancar, no en producción: claves desconocidas (un typo como
`rate_limt`), regex inválidas o vacías, nombres duplicados y `disabled_rules`
inexistentes lanzan `ValueError`.
Las reglas propias se evalúan sobre texto **decodificado, sin comentarios `/**/` y
en minúsculas**; evita patrones con backtracking catastrófico, los patrones
propios no están acotados por Gatekeeper.

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check . && bandit -r src -q
pytest --cov=gatekeeper
python tools/evaluate.py --check     # tasas de detección y FP
python benchmarks/latency.py         # coste por petición
```

Licencia MIT.
