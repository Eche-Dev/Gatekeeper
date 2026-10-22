# Referencia (API)

Toda la superficie pública está en el paquete raíz y es `mypy --strict`:

```python
from gatekeeper import Config, GatekeeperMiddleware
```

## `GatekeeperMiddleware`

```python
GatekeeperMiddleware(app, config: Config | None = None)
```

| Parámetro | Tipo | Notas |
|---|---|---|
| `app` | ASGI app | La app que protege |
| `config` | `Config` o `None` | `None` usa `Config()` (defectos conservadores) |

Se añade con `app.add_middleware(GatekeeperMiddleware, config=...)`.

### Respuestas

| Status | Body | Cuándo |
|---|---|---|
| `403` | `{"detail": "Forbidden"}` | Regla de detección, IP bloqueada |
| `429` | `{"detail": "rate limit exceeded"}` | Rate limit |
| `413` | `{"detail": "payload too large"}` | Body sobre `max_body_size` o sin `Content-Length` |
| `503` | `{"detail": "rate_limit_backend_unavailable"}` | Redis caído con `rate_fail_open=False` |

## `Config`

Dataclass con validación en `__post_init__`. Un valor inválido lanza
`ValueError` (o `TypeError` para tipos erróneos) **al construir**.

### Rate limiting

| Campo | Tipo | Defecto |
|---|---|---|
| `rate_limit` | `int` | `100` (0 desactiva) |
| `rate_window` | `float` | `60.0` |
| `rate_backend` | `str` | `"memory"` (`"memory"` \| `"redis"`) |
| `redis_url` | `str` | `"redis://localhost:6379/0"` |
| `redis_prefix` | `str` | `"gatekeeper:rl:"` |
| `rate_fail_open` | `bool` | `True` |

### Detección

| Campo | Tipo | Defecto |
|---|---|---|
| `inspect_requests` | `bool` | `True` |
| `inspect_headers` | `set[str]` | `{"user-agent", "referer", "cookie", "x-forwarded-for"}` (vacío = desactivado) |
| `monitor_only` | `bool` | `False` (solo registra) |
| `disabled_rules` | `set[str]` | `set()` — nombres de `sqli`, `xss`, `path_traversal`, `sensitive_files` |
| `custom_rules` | `dict[str, str]` o `list[dict]` | `dict()` |

### Body y rutas

| Campo | Tipo | Defecto |
|---|---|---|
| `inspect_body` | `bool` | `True` |
| `max_body_size` | `int` | `1_048_576` bytes |
| `allow_paths` | `list[str]` | `[]` (globs `fnmatch`) |

### Red y cabeceras

| Campo | Tipo | Defecto |
|---|---|---|
| `blocked_ips` | `set[str]` | `set()` — IP exacta, CIDR (`10.0.0.0/8`, IPv6) o identificador literal del peer |
| `trust_proxy` | `bool` | `False` (ponlo `True` solo detrás de un proxy de confianza) |
| `trusted_proxies` | `int` | `1` — hops tuyos en la cadena; el cliente es `ips[-trusted_proxies]` |
| `trusted_proxy_cidrs` | `set[str]` | `set()` — si se define, el XFF solo se cree si el peer pertenece a estas redes |
| `security_headers` | `dict[str, str]` \| `None` | `None` = cabeceras por defecto |

### Métodos

| Método | Comportamiento |
|---|---|
| `Config.from_dict(data)` | Valida claves desconocidas (error) y convierte listas a sets |
| `Config.from_yaml(path)` | Extra `[yaml]`; mismo esquema, claves: valor |
| `Config.validate()` | Re-valida después de mutar campos (se llama solo al construir) |
| `config.headers()` | Cabeceras de seguridad efectivas |

## Tipado

El wheel incluye `py.typed` (PEP 561): mypy y los editores resuelven los tipos
del paquete instalado en tu proyecto, sin stubs.

## Registro de eventos (auditoría)

Logger `gatekeeper`: eventos `attack_detected` (con `rule` y `source`),
`rate_limited`, `blocked_ip`, `body_too_large` y `rl_backend_unavailable`
(`WARNING`). El contenido de los payloads nunca se registra.

---

Siguiente: [Desarrollo →](desarrollo.md)
