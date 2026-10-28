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

Tres corpus con guarda en CI — uno propio, uno **retenido** y otro escrito por
gente distinta:

| Métrica | Corpus propio (160 ataques / 132 benignos) | **Retenido** (109 / 140) | OWASP CRS externo (1379 tests) |
|---|---|---|---|
| Ataques detectados | **100.0%** (160/160) | **94.5%** (103/109) | **41.0%** (465/1135) |
| Falsos positivos sin documentar | **0** (9 documentados) | **0** (5 documentados) | 4.7% (11/232 negativos de CRS, línea base) |
| Falsos negativos sin documentar | 0 | 0 (6 documentados) | — (muestra en el informe) |

Las cifras no incluyen el modo opt-in `inspect_cross_carrier=True`.
El 41.0% del corpus externo no es una meta: es la **línea base** de un corpus
diseñado para un WAF de 500+ reglas y mucho más ofuscado, y el workflow la
vigila para que no baje.

El corpus **retenido** es la medida que no se puede maquillar: se escribió una
vez sin mirar las firmas de las reglas y desde entonces solo se mide. Por eso
da un número más bajo (94,5%) que el de desarrollo (100%): esa diferencia es
información, no un defecto. Ver
[Detección y medición](deteccion.md),
[Modelo de amenazas](amenazas.md),
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) y
[corpus/HELDOUT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md).

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
| Límite de body | 256 KiB por defecto → 413 |
| Auditoría | Eventos JSON en el logger `gatekeeper`, sin los valores de los campos (el nombre del que saltó, saneado y acotado) |

El desglose completo por familia, con su frontera de falsos positivos, está en
[Modelo de amenazas](amenazas.md).

## Requisitos

- Python 3.10–3.13 (probado también localmente en 3.14)
- [Starlette](https://www.starlette.io/) ≥ 0.23 — FastAPI ya la trae

!!! success "Tipado real"
    El paquete es `mypy --strict` y distribuye `py.typed` (PEP 561): tu editor
    y tu mypy ven los tipos de Gatekeeper en tu propio proyecto.

---

Siguiente: [Instalación →](instalacion.md)
