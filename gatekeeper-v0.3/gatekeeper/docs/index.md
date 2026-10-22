# Gatekeeper

**Middleware ASGI de seguridad para FastAPI y Starlette.** Rate limiting,
cabeceras seguras, detección de patrones de ataque en query, cabeceras y body,
reglas propias por YAML y auditoría en JSON: una capa adicional delante de tu app.

!!! warning "Qué es y qué no es"
    Gatekeeper es una **defensa en profundidad**, no un WAF. Una regex no
    sustituye a las consultas parametrizadas ni a la validación de entradas, y
    tiene falsos positivos y negativos que se miden y se publican — no se ocultan.

## Ejemplo

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(
    GatekeeperMiddleware,
    config=Config(rate_limit=100, rate_window=60),
)
```

Eso ya te da rate limiting por IP, cabeceras de seguridad, bloqueo de SQLi/XSS/
path traversal en query, cabeceras y body, y eventos de auditoría en el logger
`gatekeeper`.

## Qué mide (no qué promete)

Dos corpus con guarda en CI — uno propio, otro escrito por gente distinta:

| Métrica | Corpus propio (131 ataques / 72 benignos) | OWASP CRS externo (1379 tests) |
|---|---|---|
| Ataques detectados | **100.0%** (131/131) | **21.0%** (238/1135) |
| Falsos positivos sin documentar | **0** (5 documentados) | 3.9% sobre los negativos de CRS (línea base) |
| Falsos negativos sin documentar | 0 | — (muestra en el informe) |

El 21.0% del corpus externo no es una meta: es la **línea base** de un corpus
diseñado para un WAF de 500+ reglas y mucho más ofuscado, y el workflow la
vigila para que no baje. Ver [Detección y medición](deteccion.md),
[Modelo de amenazas](amenazas.md) y
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md).

## Demo

El mismo comportamiento en vivo, con una app de juguete y un playground de
botones en [`demo/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo)
(vercel.json y Dockerfile incluidos):

![Demo de Gatekeeper](assets/demo.gif)

## Características

| Protección | Detalle |
|---|---|
| Rate limiting | Ventana deslizante por IP, en memoria o Redis (script Lua atómico, no bloquea el event loop) |
| Cabeceras | nosniff, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy |
| SQLi | UNION SELECT, tautologías, consultas apiladas, time-based, error-based |
| XSS | `<script>`, handlers de evento, `javascript:`, entidades nombradas, con doble codificación |
| Path traversal | `../`, `..;`, con decodificación repetida y frontera de segmento |
| Ficheros sensibles | `/etc/shadow`, `.ssh/*`, `.aws/credentials`, `.env` y más |
| NoSQL · Comandos · SSRF | `$ne`/`$where`; `; ls` y `` `id` ``; metadata cloud y `file://` |
| SSTI · CRLF · Log4Shell · Proto | `{{7*7}}`; splitting con cabecera; `${jndi:…}`; `__proto__` |
| Evasiones | URL-encoding repetido, escapes `%uXXXX` (IIS), ancho completo (NFKC), comentarios versionados `/*!…*/` |
| Límite de body | 1 MiB por defecto → 413 |
| Auditoría | Eventos JSON en el logger `gatekeeper`, sin contenido de payloads |

El desglose completo por familia, con su frontera de falsos positivos, está en
[Modelo de amenazas](amenazas.md).

## Requisitos

- Python 3.10–3.12 (probado también en 3.14)
- [Starlette](https://www.starlette.io/) ≥ 0.37 — FastAPI lo trae ya

!!! success "Tipado real"
    El paquete es `mypy --strict` y distribuye `py.typed` (PEP 561): tu editor
    y tu mypy ven los tipos de Gatekeeper en tu propio proyecto.

---

Siguiente: [Instalación →](instalacion.md)
