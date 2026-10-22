# Gatekeeper

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.12-blue)
![mypy](https://img.shields.io/badge/mypy-strict-2a6db2)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

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
| SQLi | UNION SELECT, tautologías (`' OR '1'='1`, `?a=1=1`), consultas apiladas (`; DROP`), time-based (`sleep()`, `WAITFOR DELAY`), error-based (`EXTRACTVALUE`, `CONVERT`), sondeo de columnas (`ORDER BY 10`) |
| XSS | `<script>`, handlers de evento con y sin etiqueta (`onerror=`, ` onload=`), `javascript:`, `data:text/html`, con doble codificación |
| Path traversal | `../`, `..\`, `..;/`, con decodificación repetida y frontera de segmento (`foo../x` no es un salto) |
| Ficheros sensibles | `/etc/passwd`, `shadow`, `subuid`; `/proc/self/environ`; `win.ini`; `.ssh/id_*`; `.aws/credentials`; `.docker/secrets`; `.git/config`; `.env` (exigen separador: `?q=.env` pasa) |
| NoSQL | Operadores de inyección Mongo: `$ne`, `$nin`, `$where`, `$regex` en JSON o corchetes (`user[$ne]=x`). `$gt`/`$lt`/`$in` quedan fuera: los usan los filtros legítimos |
| Comandos del sistema | Separador shell + binario (`; ls`, `\| cat`, `&& whoami`, `$(id)`, `` `uname` ``), LOLBins de Windows (`powershell.exe`), webshells PHP (`;system('`, `shell_exec(`), reverse shell `/dev/tcp/` |
| SSRF | Metadata cloud (AWS/GCP/Azure/Alibaba) y esquemas de lectura local (`file://`, `gopher://`, `dict://`, `jar://`); `localhost` no bloquea (OAuth de desarrollo) |
| SSTI | Aritmética de plantillas (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`) y objetos peligrosos (`config`, `self`, `__class__`, `__subclasses__`) |
| CRLF | Salto de línea seguido de cabecera: response splitting e inyección de cabeceras (CRLF real o `\r\n` literal) |
| Log4Shell | `${jndi:ldap://…}` con sus ofuscaciones (`${${::-j}ndi:`) y lookups de exfiltración (`${env:AWS_SECRET…}`) |
| Proto-pollución | `__proto__` en cualquier posición y `constructor.prototype` |
| Evasiones | URL-encoding repetido (3 rondas), escapes IIS `%uXXXX` mayúsculas o no, ancho completo (`＜script` vía NFKC), comentarios SQL `/**/` y versionados (`/*!50000union*/`), entidades HTML numéricas **y nombradas** (`&lt;script`), tab/NL dentro del esquema (`java\tscript:`) |
| Límite de body | `max_body_size` (1 MiB por defecto) → 413, también sin `Content-Length` |
| Reglas propias | Regex en YAML o `Config(custom_rules=...)`, validadas al arrancar |
| Exclusión de rutas | `allow_paths` (globs). Rutas con `..`, `\` o codificación residual nunca se eximen |
| Auditoría | Eventos JSON en el logger `gatekeeper`; **nunca** incluye el contenido del payload |
| Modo monitor | `monitor_only=True` registra sin bloquear, para medir falsos positivos en tu tráfico real |

## Qué mide (no qué promete)

Se miden dos corpus. El primero es nuestro, redactado y con procedencia
documentada ([corpus/](corpus/)):

| Métrica (corpus propio) | Valor |
|---|---|
| Ataques detectados | 131 / 131 (**100.0%**) |
| Falsos negativos sin documentar | 0 |
| Peticiones legítimas bloqueadas sin documentar | **0** / 72 |
| Falsos positivos documentados (límites aceptados) | 5 |
| Falsos negativos documentados (límites aceptados) | 0 |

Once familias de detección: SQLi, XSS, path traversal, ficheros sensibles, NoSQL,
comandos del sistema, SSRF, SSTI, CRLF, Log4Shell y proto-pollución. El
desglose con la frontera de falsos positivos de cada una está en
[docs/amenazas.md](docs/amenazas.md).

El segundo es **ajeno**: los tests de regresión de
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) (Apache-2.0,
commit `30cb436`, importado con `tools/import_crs.py`), que escribió otra gente
para otro WAF, con sus propios negativos:

| Métrica (corpus externo CRS, familias 930/941/942) | Valor |
|---|---|
| Tests importados | 1379 (1135 en alcance, 12 excluidos y declarados) |
| Ataques detectados | 238 / 1135 (**21.0%**) |
| Negativos de CRS bloqueados (FP) | 9 / 232 (3.9%) |

Ese 21.0% no es una meta: es la **línea base** de un corpus diseñado para un
WAF de 500+ reglas y payloads mucho más ofuscados, y el workflow la vigila para
que no baje. Publicarlo entero es el punto: un 100% propio y un 21.0% ajeno, los
dos medidos y los dos con guarda en CI.

El detalle, incluidos los payloads que se escapan y por qué, está en
[corpus/REPORT.md](corpus/REPORT.md). El workflow falla si una regla nueva
empeora esas cifras (`python tools/evaluate.py --check`).

## Demo

Una sesión real contra [`demo/app.py`](demo/) (uvicorn + curl, sin trucos):
tráfico normal pasa, los payloads reciben 403 y la auditoría registra la
regla, el campo y el patrón que saltó — nunca el contenido.

![Demo de Gatekeeper](docs/assets/demo.gif)

La app de la demo incluye un playground con botones y configs de despliegue
para Vercel (`vercel --prod`) y Docker: [`demo/`](demo/).

## Latencia

`python benchmarks/latency.py` mide el coste por petición en tu máquina
(Python 3.14, portátil, sin red):

| Escenario | µs/petición | µs añadidos |
|---|---|---|
| sin middleware (base) | 12.87 | — |
| solo cabeceras | 32.06 | +19.19 |
| inspección (query + cabeceras + body) | 89.92 | +77.05 |
| rate limit solo | 35.09 | +22.22 |
| completo (inspección + rate limit) | 93.00 | +80.13 |
| request atacante (403 temprano) | 58.18 | +45.31 |

Las once familias de 0.3.1 (NoSQL, comandos, SSRF, SSTI, CRLF, Log4Shell y
proto-pollución además de las cuatro anteriores) cuestan ~21 µs más por
petición que la tabla de v0.3.0: son 31 regex más que evaluar, y es el precio de
cubrir esas familias sin WAF externo. Microsegundos absolutos: lo que importa es
que la comparación entre escenarios siga siendo reproducible.

## Documentación

Guía completa con [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
en [`docs/`](docs/): uso, detección y medición, modelo de amenazas, seguridad,
referencia de API y desarrollo. En local: `mkdocs serve`. Se publica en
<https://eche-dev.github.io/Gatekeeper/> en cada push a `main` (build
`--strict` en CI: un enlace roto rompe el workflow).

Contribuir: [CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md)
· [Código de conducta](https://github.com/Eche-Dev/Gatekeeper/blob/main/CODE_OF_CONDUCT.md)
· Plantillas de issues y PR en la raíz del repo.

Son microsegundos relativos, no una promesa de latencia: sirve para comparar
escenarios y detectar regresiones.

## Qué NO cubre

- La detección por regex tiene falsos positivos y falsos negativos: **no sustituye**
  a consultas parametrizadas, a validación de entradas ni a un WAF.
- `multipart/form-data` y bodies binarios no se inspeccionan (las subidas de archivos pasan intactas; parser en v0.4).
- Cada valor del body se analiza por separado: un ataque repartido en varios campos no se detecta.
- Los operadores `$gt`/`$lt`/`$in` de Mongo quedan fuera de la firma NoSQL a propósito (los usan los filtros legítimos); `localhost` y `127.0.0.1` no cuentan como SSRF (OAuth de desarrollo).
- Con `rate_backend="memory"` y varios workers, el límite efectivo se multiplica: usa Redis.
- Si Redis no responde, `rate_fail_open=True` (por defecto) sigue admitiendo peticiones; ponlo a `False` si prefieres 503.
- `trust_proxy=False` por defecto; actívalo solo detrás de un proxy de confianza. Con `trust_proxy=True` el XFF se lee de derecha a izquierda (`ips[-trusted_proxies]`); añade `trusted_proxy_cidrs` si la app es alcanzable por otro camino.
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
| `disabled_rules` | `∅` | `sqli`, `xss`, `path_traversal`, `sensitive_files`, `nosql`, `cmdi`, `ssrf`, `ssti`, `crlf`, `log4shell`, `proto_pollution` o tus reglas |
| `custom_rules` | `∅` | `{nombre: regex}` o lista `{name, pattern}` |
| `max_body_size` | `1 MiB` | límite del body inspeccionado |
| `allow_paths` | `[]` | globs exentos de inspección |
| `inspect_headers` | `user-agent, referer, cookie, x-forwarded-for` | cabeceras inspeccionadas (`∅` desactiva) |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | bloqueo por IP o CIDR y uso de `X-Forwarded-For` |
| `trusted_proxies` / `trusted_proxy_cidrs` | `1` / `∅` | hops de proxy a saltar en el XFF y redes de las que se cree |
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
ruff check .            # estilo
mypy                    # tipos estrictos (src/gatekeeper)
bandit -r src -q        # análisis estático de seguridad
pytest --cov=gatekeeper   # incluye fuzzing con hypothesis (tests/test_fuzz.py)
python tools/evaluate.py --check     # tasas de detección y FP (propio + CRS)
python tools/import_crs.py --check   # procedencia del corpus externo
python benchmarks/latency.py         # coste por petición
python -m build && twine check dist/*   # el paquete se puede publicar
```

## Proyecto

- [CHANGELOG.md](CHANGELOG.md) — qué cambia en cada versión.
- [SECURITY.md](SECURITY.md) — modelo de amenazas, límites y cómo reportar fallos.
- [corpus/REPORT.md](corpus/REPORT.md) — informe de detección generado.

Licencia MIT.
