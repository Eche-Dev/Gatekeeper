# Gatekeeper

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0b132b,100:1c2541&height=200&section=header&text=Gatekeeper&fontSize=48&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Middleware%20ASGI%20de%20Seguridad%20para%20FastAPI%20y%20Starlette&descAlignY=62&descSize=18" />

  <p>
    <img src="https://github.com/Eche-Dev/Gatekeeper/raw/main/gatekeeper-v0.3/gatekeeper/imgDev.png" alt="Gatekeeper — WAF para aplicaciones ASGI" width="100%" />
  </p>

  <!-- Stack principal -->
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Starlette-20232A?style=for-the-badge&logo=starlette&logoColor=white" />
  <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" />
  <img src="https://img.shields.io/badge/Testing-pytest-0A9E4F?style=for-the-badge&logo=pytest&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-Audit%2097%2F100-red?style=for-the-badge&logo=shield&logoColor=white" />
</div>

<br />

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![mypy](https://img.shields.io/badge/mypy-strict-2a6db2)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

> **In English: [README.en.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/README.en.md)**

**Gatekeeper es un middleware ASGI de seguridad para FastAPI y Starlette.** Se
coloca delante de tu aplicación y, en cada petición, hace tres cosas:

1. **Limita el tráfico** por IP (ventana deslizante, en memoria o compartida en Redis).
2. **Añade las cabeceras de seguridad** que tu app debería servir y que nadie
   se acuerda de poner (`nosniff`, `HSTS`, `X-Frame-Options`…).
3. **Busca patrones de ataque** en la ruta, la query string, las cabeceras y el
   body: SQLi, XSS, path traversal, NoSQL, comandos del sistema, SSRF, SSTI,
   CRLF, Log4Shell y proto-pollución.

Es **una capa más** de defensa en profundidad, no un WAF: no sustituye a las
consultas parametrizadas ni a la validación de entradas. Y no promete "no te
van a atacar": **publica cuánto detecta y cuánto se equivoca**, con tres
corpus medidos y con los números a la vista.

## Por qué existe

Tres problemas que aparecen en casi cualquier API y que no necesitan a nadie
malicioso:

- **Una IP puede pedirlo todo.** Sin límite de peticiones, un bucle contra tu
  login es un ataque de fuerza bruta y un crawler es un DDoS.
- **Las cabeceras de seguridad no se ponen solas.** `X-Content-Type-Options`,
  `Strict-Transport-Security` o `X-Frame-Options` hay que añadirlas a mano en
  cada servicio, y basta un microservicio olvidado.
- **Un campo sin validar es una puerta.** Una búsqueda, un filtro o un
  parámetro que acaba en una consulta o en una plantilla se convierte en
  inyección si nadie lo revisa.

Gatekeeper los cubre **en un punto, delante de tu app**, sin que tengas que
tocar endpoint por endpoint.

## Instalación

```bash
pip install gatekeeper-asgi             # núcleo
pip install "gatekeeper-asgi[yaml]"     # + configuración por YAML
pip install "gatekeeper-asgi[redis]"    # + rate limit compartido entre workers
```

Requiere Python 3.10+ y Starlette 0.23+ (FastAPI ya la incluye).

## Uso

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
# o con Redis, para que todos los workers cuenten lo mismo:
# Config(rate_backend="redis", redis_url="redis://localhost:6379/0")
# o: Config.from_yaml("gatekeeper.yaml")   (ver examples/gatekeeper.yaml)
```

Una línea y tu app ya tiene rate limit, cabeceras de seguridad e inspección de
la query y del body. La configuración entera está en
[la referencia de la API](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/api.md).

## Qué pasa cuando detecta algo

Una petición con un payload de SQLi en la query:

```console
$ curl -i "http://localhost:8000/?q=1%27%20OR%20%271%27%3D%271"
HTTP/1.1 403 Forbidden
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY
strict-transport-security: max-age=31536000; includeSubDomains

{"detail":"Forbidden"}
```

Y en el log, un evento JSON (nunca los **valores** del payload: solo la regla,
el **nombre** del campo que saltó —lo elige el atacante, así que va saneado y
acotado— y el patrón):

```json
{"ts": 1793039080.65, "event": "attack_detected", "ip": "203.0.113.7",
 "method": "GET", "path": "/", "rule": "sqli", "source": "query",
 "field": "q", "pattern": "\\b(or|and)\\b\\s{0,16}...", "blocked": true}
```

El catálogo completo de eventos está en
[`corpus/events.json`](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/events.json).

## Qué revisa

| | Detalle |
|---|---|
| Rate limiting | Ventana deslizante por IP. En memoria (un proceso) o en Redis con un script Lua atómico (compartido entre workers), vía `redis.asyncio`, sin bloquear el event loop |
| Cabeceras | `nosniff`, `X-Frame-Options`, `HSTS`, `Referrer-Policy`, `Permissions-Policy`. Nunca pisa las de tu app, y también van en los rechazos |
| Detección | Once familias: SQLi, XSS, path traversal, ficheros sensibles, NoSQL, comandos del sistema, SSRF, SSTI, CRLF, Log4Shell y proto-pollución. El detalle de cada una, con su frontera de falsos positivos, está en [docs/amenazas.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/amenazas.md) |
| Superficies | Ruta, query string, cabeceras, body JSON y de formulario, nombres de multipart y handshake de WebSocket |
| Evasiones | URL-encoding repetido (3 rondas), escapes IIS `%uXXXX`, caracteres de ancho completo (NFKC), comentarios SQL `/**/` y versionados (`/*!50000…*/`), entidades HTML numéricas **y nombradas** |
| Presupuestos | `max_body_size` (256 KiB), `max_fields` (1000 textos) y `max_inspection_ms` (1000 ms). Si se agotan, la petición se rechaza con **413**: nunca se admite sin inspeccionar |
| Reglas propias | Regex en YAML o en `Config(custom_rules=...)`, validadas al arrancar (una regex con backtracking catastrófico es un `ValueError`) |
| Auditoría | Eventos JSON en el logger `gatekeeper`. Nunca los valores de los campos |

## Qué mide (no qué promete)

Se miden tres corpus, y los tres tienen guarda en CI: si una regla nueva los
empeora, el workflow falla.

El primero es **nuestro**, escrito a mano y con la procedencia documentada
([corpus/](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/corpus/)):

| Métrica (corpus propio) | Valor |
|---|---|
| Ataques detectados | 160 / 160 (**100.0%**) |
| Falsos negativos sin documentar | 0 |
| Peticiones legítimas bloqueadas sin documentar | **0** / 132 |
| Falsos positivos documentados (límites aceptados) | 9 |

El segundo es el **retenido**: un corpus escrito una vez, sin mirar las firmas
de las reglas, y desde entonces solo medido. Es el que dice si las reglas
generalizan o solo se acuerdan de los casos con los que se escribieron:

| Métrica (corpus retenido) | Valor |
|---|---|
| Ataques detectados | 103 / 109 (**94.5%**) |
| Falsos negativos sin documentar | 0 (6 documentados, con su motivo) |
| Peticiones legítimas bloqueadas sin documentar | **0** / 140 |
| Falsos positivos documentados (límites aceptados) | 5 |

Que dé 94,5% y no 100% es lo esperado: el corpus propio se puede usar para
ajustar las reglas y el retenido no. Esa diferencia es información, no un
defecto: es lo que separa "las reglas detectan esto" de "las reglas detectan lo
que se escribieron para ellas". La metodología está en
[corpus/HELDOUT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md).

El tercero es **ajeno**: los tests de regresión del
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) (Apache-2.0,
commit `30cb436`, importado con `tools/import_crs.py`), que escribió otra gente
para otro WAF, con sus propios negativos:

| Métrica (corpus externo CRS, familias 930/941/942) | Valor |
|---|---|
| Tests importados | 1379 (1135 en alcance, 12 excluidos y declarados) |
| Ataques detectados | 465 / 1135 (**41.0%**) |
| Negativos de CRS bloqueados (FP) | 11 / 232 (4.7%) |

Ese 41.0% no es una meta: es la **línea base** de un corpus diseñado para un
WAF de 500+ reglas y payloads mucho más ofuscados, y el workflow la vigila para
que no baje. Publicarlo entero es el punto: un 100% propio y un 41.0% ajeno,
los dos medidos y los dos con guarda en CI.

El detalle, incluidos los payloads que escapan y por qué, está en
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md).
Estas cifras miden los escaneos individuales; no incluyen
`inspect_cross_carrier=True`.

## Configuración

Lo esencial, con el resto en
[la referencia de la API](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/api.md):

| Opción | Por defecto | Qué hace |
|---|---|---|
| `rate_limit` / `rate_window` | `100` / `60` | peticiones permitidas por IP y ventana (0 desactiva) |
| `rate_backend` | `memory` | `memory` o `redis` (compartido entre workers) |
| `inspect_requests` / `inspect_body` | `True` | inspección de query y de body |
| `monitor_only` | `False` | registrar sin bloquear (para medir antes de bloquear) |
| `disabled_rules` | `∅` | apagar familias concretas (`sqli`, `xss`, `path_traversal`…) |
| `rule_packs` | `∅` (todas) | activar un subconjunto: `minimal`, `api`, `web`, `infrastructure`, `strict` |
| `exclude_fields` | `[]` | campos exentos de inspección (parámetro, cabecera o puntero JSON); admite globs |
| `custom_rules` | `∅` | tus propias regex: `{nombre: regex}` o `[{name, pattern}]` |
| `max_body_size` | `256 KiB` | límite del body inspeccionado |
| `max_fields` / `max_inspection_ms` | `1000` / `1000` | presupuestos de inspección (se agotan → 413) |
| `redis_timeout` | `2.0` | segundos de espera al conectar con Redis. Con Redis caído, cada petición espera esto (medido: 2,0 s por petición) |
| `allow_paths` | `[]` | globs exentos de inspección (no de rate limit) |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | bloqueo por IP o CIDR, y uso de `X-Forwarded-For` |

`Config` **falla al arrancar**, no en producción: claves desconocidas (un typo
como `rate_limt`), regex inválidas o vacías, nombres duplicados,
`disabled_rules` inexistentes y packs desconocidos lanzan `ValueError`.

### Dos decisiones que suelen necesitarse

**Si tu app expone menos superficie de la que asumes**, en vez de apagar
reglas una a una, activa un pack:

```python
from gatekeeper import Config

Config(rule_packs=["api"])   # SQLi, NoSQL, traversal, ficheros, SSRF, Log4Shell, CRLF, cmdi
```

Un pack desconocido es `ValueError` al arrancar: una app no puede quedarse sin
protección porque alguien escribiera `rule_packs=["we"]`.

**Si tu app acepta por diseño un valor que una firma bloquea** (un buscador
que indexa documentación de seguridad, un parámetro `template` con Jinja, un
webhook), exime **ese campo**, no la familia entera:

```python
Config(exclude_fields=["template", "bio", "doc_*"])
```

Funciona en los tres transportes (parámetro de query, cabecera y puntero
JSON), y la detección que cruza varios campos se conserva: si excluyes `a`
pero el payload está repartido entre `a` y `b`, Gatekeeper quita `a` del
objetivo y sigue vigilando `b`.

### Medir antes de bloquear

Pón el middleware delante con `monitor_only=True`, deja correr el tráfico real
y mira qué salta:

```bash
gatekeeper report gatekeeper.log          # ranking de reglas, rutas y campos
gatekeeper report gatekeeper.log --json   # salida legible por máquina
```

El informe agrupa por (regla, campo) —lo que se repite es ruido— y propone un
`exclude_fields` o un `disabled_rules` listo para copiar. Acepta el JSON que
emite el logger de Gatekeeper o un log de acceso genérico
(`GET /ruta?q=… 200`).

## Qué NO cubre

- La detección por regex tiene falsos positivos y falsos negativos: **no
  sustituye** a consultas parametrizadas, a validación de entradas ni a un WAF.
- El **contenido** de los ficheros adjuntos no se inspecciona (sí los nombres
  de campo y de fichero).
- Los **frames** de un WebSocket no se inspeccionan: sí el handshake, que
  además tiene rate limit.
- Los binarios que no son JSON (imagen, PDF, zip…) no se leen.
- Por defecto, cada valor del body se analiza por separado. Con
  `inspect_cross_carrier=True` se combinan ruta/query con los valores textuales
  no excluidos; es opt-in y su resultado **no** está en las cifras de arriba.
- Los operadores `$gt`/`$lt`/`$in` de Mongo quedan fuera de la firma NoSQL a
  propósito (los usan los filtros legítimos); `localhost` y `127.0.0.1` no
  cuentan como SSRF (OAuth de desarrollo).
- Con `rate_backend="memory"` y varios workers, el límite efectivo se
  multiplica: usa Redis.
- Si Redis no responde, `rate_fail_open=True` (por defecto) sigue admitiendo
  peticiones; ponlo a `False` si prefieres 503.
- `trust_proxy=False` por defecto; actívalo solo detrás de un proxy de
  confianza, y añade `trusted_proxy_cidrs` si la app es alcanzable por otro
  camino.
- `allow_paths` exime de inspección, no de rate limit ni de bloqueo de IP.

## Demo

Una sesión real contra
[`demo/app.py`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo/)
(uvicorn + curl, sin trucos): el tráfico normal pasa, los payloads reciben 403
y la auditoría registra la regla, el campo y el patrón que saltó — nunca el
contenido.

![Demo de Gatekeeper](https://github.com/Eche-Dev/Gatekeeper/raw/main/gatekeeper-v0.3/gatekeeper/docs/assets/demo.gif)

## Coste por petición

`python benchmarks/latency.py` mide el coste en tu máquina, invocando ASGI
directamente y sin red. En la última corrida local (Python 3.14.8 en Windows),
el escenario completo —inspección de query más rate limit— tuvo un **p50 de
141 µs, un p95 de 155 µs y un p99 de 216 µs** sobre una base de 13 µs sin
middleware. Con un body JSON pequeño, p50 de 244 µs.

**El tamaño del body es lo que manda**, y conviene decirlo claro:

| Body | p50 | p95 | p99 | CPU |
|---|---:|---:|---:|---:|
| vacío | 141 µs | 155 µs | 216 µs | 0,6 ms |
| 100 KB | **8,3 ms** | 10,9 ms | 18,7 ms | 9,0 ms |

Un body de 100 KB cuesta **59 veces más** que uno vacío, y el middleware lo
paga **antes** de que la aplicación vea la petición. El presupuesto por
defecto (`max_body_size`, 256 KiB) es lo que evita que esto crezca sin tope;
con bodies grandes, bajarlo es la primera palanca.

Son medidas locales con ruido: no son latencia de extremo a extremo ni un SLA.
El benchmark publica p50, p95 y p99 para que la cola no quede escondida
detrás de un promedio, y `python benchmarks/latency.py --save base.json` guarda
una línea base para comparar un cambio en la misma máquina. El CI compara
**el código del PR y el de `main` en el mismo runner** (el ruido de la máquina
se cancela; un umbral absoluto no serviría).

**Y si Redis se cae**, cada petición espera el timeout de conexión antes de
decidir: medido, **2,0 s por petición** con el valor por defecto (fail-open
admitió la petición tras 2.017 ms; fail-closed devolvió 503 tras 2.018 ms).
Es un tiempo de espera, no un fallo: la API sigue respondiendo, pero despacio.
Se ajusta con `redis_timeout` (por defecto 2,0 s; bájalo si tu Redis está en
la misma red).

## Documentación

Guía completa con [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
en [`docs/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/docs/):
uso, detección y medición, modelo de amenazas, seguridad, referencia de API y
desarrollo. En local: `mkdocs serve`. Se publica en
<https://eche-dev.github.io/Gatekeeper/> en cada push a `main` (build
`--strict` en CI: un enlace roto rompe el workflow).

¿Acabas de llegar? Empieza por la
[guía de inicio rápido](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/inicio-rapido.md):
dos comandos `curl` verifican que una petición normal da 200 y un ataque da
403. Y si decides **dónde** desplegarlo, la
[guía de despliegue](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/despliegue.md)
dice qué valor cambia en cada topología (un proceso, varios workers, Docker,
proxy inverso).

Contribuir: [CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md)
· [Código de conducta](https://github.com/Eche-Dev/Gatekeeper/blob/main/CODE_OF_CONDUCT.md)
· Plantillas de issues y PR en la raíz del repo.

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check .            # estilo
mypy                    # tipos estrictos (src/gatekeeper)
bandit -r src -q        # análisis estático de seguridad
pytest --cov=gatekeeper   # incluye fuzzing con hypothesis (tests/test_fuzz.py)
python tools/evaluate.py --check     # tasas de detección y FP (propio + CRS)
python tools/import_crs.py --check   # procedencia del corpus externo
python tools/check_docs.py           # la doc dice la verdad (versión, enlaces, mínimos)
python benchmarks/latency.py         # coste por petición
python -m build && twine check dist/*   # el paquete se puede publicar
```

## Proyecto

- [CHANGELOG.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/CHANGELOG.md) — qué cambia en cada versión.
- [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md) — modelo de amenazas, límites y cómo reportar un fallo.
- [AUDITORIA-IA-COMPARATIVA.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/AUDITORIA-IA-COMPARATIVA.md) — comparativa de auditorías multi-IA y certificación 97/100.
- [corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) — informe de detección generado.

Licencia MIT.
