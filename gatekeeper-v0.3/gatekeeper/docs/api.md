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
| `413` | `{"detail": "Payload Too Large"}` | Tamaño declarado o leído del body supera `max_body_size` |
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
| `rate_max_keys` | `int` | `10000` — tope de IPs distintas que el backend en memoria recuerda (al llegar al tope sale la menos usada) |
| `rate_ipv6_prefix` | `int` | `64` — bits de prefijo IPv6 que se agrupan al contar (un /64 es el prefijo delegable más pequeño, RFC 6177) |

**Qué se cuenta como "el mismo cliente".** La clave de conteo no es la IP
cruda: `::ffff:1.2.3.4` cuenta como `1.2.3.4` (es la misma dirección con
dos formas) y las IPv6 del mismo prefijo cuentan juntas (por defecto, el
/64). Sin esa normalización, rotar direcciones IPv6 dentro del propio /64
evadía el límite, que es la evasión clásica de un limitador por IP. La IP
**cruda** es la que se registra en la auditoría.

`rate_max_keys` acota la memoria del backend en memoria: sin tope, inundar
de IPs distintas hacía crecer el proceso sin límite (medido: 300.000 IPs →
~245 MB). Al llegar al tope se descarta la clave menos usada, de modo que el
límite por cliente sigue mandando y la memoria queda acotada.

### Detección

| Campo | Tipo | Defecto |
|---|---|---|
| `inspect_requests` | `bool` | `True` |
| `inspect_headers` | `set[str]` | `{"user-agent", "referer", "cookie", "x-forwarded-for"}` (vacío = desactivado) |
| `monitor_only` | `bool` | `False` (solo registra) |
| `inspect_cross_carrier` | `bool` | `False` (combina ruta/query con valores textuales del body; claves se inspeccionan individualmente; opt-in por posibles falsos positivos) |
| `rule_packs` | `list[str] \| None` | `None` = **todas** las familias (los packs son opt-in): `minimal`, `api`, `web`, `infrastructure`, `strict` |
| `disabled_rules` | `set[str]` | `set()` — nombres de `sqli`, `xss`, `path_traversal`, `sensitive_files`, `nosql`, `cmdi`, `ssrf`, `ssti`, `crlf`, `log4shell`, `proto_pollution` (ver [modelo de amenazas](amenazas.md)) |
| `exclude_fields` | `list[str]` | `[]` — parámetros, cabeceras o punteros JSON exentos de inspección (globs `fnmatch`; el puntero `/user/bio` también casa por `bio`) |
| `custom_rules` | `dict[str, str]` o `list[dict]` | `dict()` |

Un `rule_packs` desconocido es `ValueError` al arrancar, igual que un
`disabled_rules` con nombres inexistentes.

`exclude_fields` conserva la detección que cruza varios parámetros de
ruta/query: el campo exento se quita del objetivo antes de escanear, el resto se
sigue vigilando. En el cruce opcional query/body, los valores excluidos tampoco
participan.

### Body y rutas

| Campo | Tipo | Defecto |
|---|---|---|
| `inspect_body` | `bool` | `True` |
| `inspect_multipart` | `bool` | `True` (nombres de campo y de fichero; el contenido del fichero no). Implica leer el body, así que también aplica `max_body_size` |
| `inspect_websockets` | `bool` | `True` (handshake: ruta, query y cabeceras, con rate limit; los frames no) |
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
