# Uso

## Montaje mínimo

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config())
```

`Config()` con sus defectos ya es una configuración sensata: 100 peticiones por
minuto por IP, inspección activa, body hasta 1 MiB.

## Rate limiting

| Campo | Defecto | Notas |
|---|---|---|
| `rate_limit` | `100` | Peticiones por ventana. `0` desactiva |
| `rate_window` | `60.0` | Segundos de la ventana deslizante |
| `rate_backend` | `"memory"` | `"memory"` (un proceso) o `"redis"` (todos los workers) |
| `redis_url` | `redis://localhost:6379/0` | Con `rate_backend="redis"` |
| `rate_fail_open` | `True` | Qué hacer si Redis no responde (ver abajo) |

!!! warning "Un worker, un contador"
    Con el backend en memoria cada proceso cuenta lo suyo: 4 workers con
    `rate_limit=100` admiten ~400/min. Para un límite global usa Redis:

    ```python
    Config(rate_backend="redis", redis_url="redis://localhost:6379/0")
    # o en YAML: rate_backend: redis
    ```

    La ventana se actualiza con un script Lua **atómico** (sin carreras
    leer-modificar-escribir) y el cliente es `redis.asyncio`: no bloquea el
    event loop.

### Política si Redis no responde

| `rate_fail_open` | Comportamiento | Para quién |
|---|---|---|
| `True` (defecto) | Se admite la petición, se audita `rl_backend_unavailable` | Disponibilidad primero |
| `False` | 503 con `{"detail": "rate_limit_backend_unavailable"}` | Seguridad estricta |

En ambos casos el fallo queda en la auditoría: no hay forma de que Redis caiga
en silencio.

## Qué inspecciona

En este orden, y el primero que salta manda:

1. **IP bloqueada** (`blocked_ips`) → 403.
2. **Rate limit** → 429.
3. **Ruta + query string** decodificadas contra las reglas → 403.
4. **Body** con content-type `application/json`, `+json` o
   `application/x-www-form-urlencoded` → 403. Si el body supera
   `max_body_size` (o no declara `Content-Length`) → 413.

!!! note "Qué NO inspecciona (por diseño)"
    Cabeceras, cookies, `multipart/form-data` y bodies XML/binarios. Son límites
    conscientes y están declarados en la medición del corpus externo: no se
    cuentan como fallos, se cuentan como exclusiones.

### Bloqueo y modo observación

La respuesta de bloqueo es `403` con JSON:

```json
{"detail": "Forbidden"}
```

Para medir falsos positivos con tu tráfico real antes de bloquear nada:

```python
Config(monitor_only=True)   # todo se audita, nada se bloquea
```

También puedes apagar la inspección completa (`inspect_requests=False`) o
desactivar reglas concretas (`disabled_rules={"sqli"}`).

## Rutas exentas

```python
Config(allow_paths=["/docs*", "/openapi.json", "/health"])
```

Globs `fnmatch` (sensible a mayúsculas). La garantía de seguridad: una ruta que
contenga `..`, barra invertida o codificación residual **nunca** se exime, así
que `/docs/../admin` no se cuela por `/docs/*`. El rate limit y el bloqueo de IP
siguen aplicando en las rutas exentas.

## Auditoría

Todo se registra en el logger `gatekeeper` (nivel `INFO` para eventos, `WARNING`
para backend caído), como JSON. Por defecto **no incluye el contenido del
payload**: `attack_detected` trae la regla que saltó y la IP, no el texto.

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Eventos: `attack_detected`, `rate_limited`, `blocked_ip`, `body_too_large`,
`rl_backend_unavailable`.

## Cabeceras de seguridad

Se añaden sin pisar las tuyas. Por defecto: `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` y HSTS.
Para cambiarlas por completo, `Config(security_headers={...})`.

!!! warning "HSTS"
    `Strict-Transport-Security` solo se sirve sobre HTTPS (se omite en
    `http://`), porque forzarla en desarrollo local rompería tu entorno.

## Reglas propias

En código:

```python
Config(custom_rules={
    "token_interno": r"\btk_[a-z0-9]{24}\b",   # se filtra una clave interna
})
```

O por YAML (extra `[yaml]`):

```yaml
# gatekeeper.yaml
rate_limit: 60
rate_window: 60
custom_rules:
  token_interno: '\btk_[a-z0-9]{24}\b'
```

```python
app.add_middleware(GatekeeperMiddleware, config=Config.from_yaml("gatekeeper.yaml"))
```

Las reglas personalizadas se evalúan sobre texto decodificado y en minúsculas,
iguales que las integradas. **No están acotadas contra ReDoS**: revisa tus
patrones (las integradas sí lo están; ver [Seguridad](seguridad.md)).

!!! danger "Fallar al arrancar, no en producción"
    Una clave con typo (`rate_limt`) o un patrón inválido **rompe el arranque**
    con `ValueError`. Nunca te levantas con una protección que crees tener y no
    tienes.

## Ejemplo completo

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(
    GatekeeperMiddleware,
    config=Config(
        rate_limit=120,
        rate_window=60,
        rate_backend="redis",
        redis_url="redis://localhost:6379/0",
        allow_paths=["/docs*", "/openapi.json", "/health"],
        max_body_size=1_048_576,
    ),
)

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
```

---

Siguiente: [Detección y medición →](deteccion.md)
