# Gatekeeper

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
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
| Límite de body | `max_body_size` (1 MiB por defecto) → 413 si el tamaño declarado o leído lo supera |
| Cruce query + body | Opt-in con `inspect_cross_carrier=True`; combina ruta/query con valores textuales no excluidos del body, puede añadir falsos positivos, probar primero con `monitor_only=True` |
| Reglas propias | Regex en YAML o `Config(custom_rules=...)`, validadas al arrancar |
| Exclusión de rutas | `allow_paths` (globs). Rutas con `..`, `\` o codificación residual nunca se eximen |
| Auditoría | Eventos JSON en el logger `gatekeeper`; **nunca** incluye el contenido del payload |
| Modo monitor | `monitor_only=True` registra sin bloquear, para medir falsos positivos en tu tráfico real |

## Qué mide (no qué promete)

Se miden dos corpus. El primero es nuestro, redactado y con procedencia
documentada ([corpus/](corpus/)):

| Métrica (corpus propio) | Valor |
|---|---|
| Ataques detectados | 159 / 159 (**100.0%**) |
| Falsos negativos sin documentar | 0 |
| Peticiones legítimas bloqueadas sin documentar | **0** / 81 |
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
| Ataques detectados | 459 / 1135 (**40.4%**) |
| Negativos de CRS bloqueados (FP) | 11 / 232 (4.7%) |

Ese 40.4% no es una meta: es la **línea base** de un corpus diseñado para un
WAF de 500+ reglas y payloads mucho más ofuscados, y el workflow la vigila para
que no baje. Publicarlo entero es el punto: un 100% propio y un 40.4% ajeno, los
dos medidos y los dos con guarda en CI.
Estas cifras miden los escaneos individuales; no incluyen
`inspect_cross_carrier=True`.

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

`python benchmarks/latency.py` mide el coste por petición en tu máquina,
invocando ASGI directamente y sin red:

| Escenario | p50 | p95 | p99 | +p50 vs base |
|---|---|---|---|---|
| sin middleware (base) | 17.40 | 56.70 | 308.70 | — |
| solo cabeceras | 41.60 | 194.10 | 989.50 | +23.50 |
| inspección de query, sin body ni rate limit | 206.10 | 937.80 | 2057.20 | +171.20 |
| inspección de body JSON, sin rate limit | 346.60 | 612.90 | 1029.60 | +329.20 |
| cruce query/body opt-in (benigno) | 434.80 | 715.00 | 1179.90 | +429.20 |
| cruce query/body opt-in (ataque, 403) | 322.90 | 474.50 | 709.50 | +305.50 |
| rate limit solo | 46.50 | 55.30 | 99.00 | +27.30 |
| completo (inspección + rate limit) | 193.40 | 394.10 | 677.90 | +173.70 |
| request atacante (403 temprano) | 114.40 | 331.30 | 743.20 | +97.40 |

Una corrida local de **Python 3.14.8 en Windows**, con 1000 iteraciones × 5
rondas, produjo esos percentiles; la columna de overhead usa 3 repeticiones.
Los resultados dependen del entorno y no son una promesa de latencia de producción.
Los escenarios de body y cruce entregan el body real al middleware; los tests
verifican que el caso benigno responde 200 y el cruce de ataque 403.

**El pre filtro de familias.** Antes de ejecutar las regex, comprueba si el
texto contiene un literal obligatorio de cada familia y omite las que no
pueden coincidir. Para textos de menos de 128 caracteres no lo aplica. Esta
optimización no debe cambiar detecciones. `tests/test_prefilter.py` compara el
escaneo con y sin pre filtro sobre los 1787 valores de ambos corpus (payloads
propios, solicitudes CRS y valores de cabecera) y exige el mismo resultado.

El benchmark publica p50, p95 y p99 por petición para que la cola no quede
oculta por un promedio. En esta corrida el escenario completo tuvo p50 de
193.40 µs, p95 de 394.10 µs y p99 de 677.90 µs; son medidas locales con ruido,
no latencia de extremo a extremo ni un SLA.

`python benchmarks/latency.py --save base.json` y, tras cambiar el código,
`python benchmarks/latency.py --baseline base.json` comparan dos versiones **en
tu máquina** y dicen si algún escenario empeoró más de un margen (25 % por
defecto). Sirven para comparar cambios bajo condiciones locales similares
antes de abrir un PR que toca el camino caliente.

### Comparar rendimiento

No hay un umbral fijo de latencia en CI: los runners compartidos no son una
base estable. El benchmark es un informe local; para comparar cambios, guarda
una línea base y ejecuta ambas versiones en la misma máquina:

## Documentación

Guía completa con [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
en [`docs/`](docs/): uso, detección y medición, modelo de amenazas, seguridad,
referencia de API y desarrollo. En local: `mkdocs serve`. Se publica en
<https://eche-dev.github.io/Gatekeeper/> en cada push a `main` (build
`--strict` en CI: un enlace roto rompe el workflow).

Contribuir: [CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md)
· [Código de conducta](https://github.com/Eche-Dev/Gatekeeper/blob/main/CODE_OF_CONDUCT.md)
· Plantillas de issues y PR en la raíz del repo.

## Qué NO cubre

- La detección por regex tiene falsos positivos y falsos negativos: **no sustituye**
  a consultas parametrizadas, a validación de entradas ni a un WAF.
- `multipart/form-data` y bodies binarios no se inspeccionan (las subidas de archivos pasan intactas; parser en v0.4).
- Por defecto, cada valor del body se analiza por separado. Con `inspect_cross_carrier=True`, los valores textuales no excluidos se combinan con ruta/query; las claves JSON y las cabeceras no participan.
- `inspect_cross_carrier=True` combina ruta/query con los valores textuales no excluidos del body cuando los escaneos individuales no detectan nada. Las claves se inspeccionan individualmente, pero no se combinan. Es opt-in; su resultado no está incluido en las métricas publicadas del corpus.
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
| `inspect_cross_carrier` | `False` | combinar ruta/query + valores textuales del body tras escaneos individuales limpios |
| `monitor_only` | `False` | registrar sin bloquear |
| `disabled_rules` | `∅` | `sqli`, `xss`, `path_traversal`, `sensitive_files`, `nosql`, `cmdi`, `ssrf`, `ssti`, `crlf`, `log4shell`, `proto_pollution` o tus reglas |
| `rule_packs` | `∅` (todas) | packs opt-in: `minimal`, `api`, `web`, `infrastructure`, `strict` (ver abajo) |
| `exclude_fields` | `[]` | campos (parámetro, cabecera o puntero JSON) exentos de inspección; admite globs |
| `custom_rules` | `∅` | `{nombre: regex}` o lista `{name, pattern}` |
| `max_body_size` | `1 MiB` | límite del body inspeccionado |
| `allow_paths` | `[]` | globs exentos de inspección |
| `inspect_headers` | `user-agent, referer, cookie, x-forwarded-for` | cabeceras inspeccionadas (`∅` desactiva) |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | bloqueo por IP o CIDR y uso de `X-Forwarded-For` |
| `trusted_proxies` / `trusted_proxy_cidrs` | `1` / `∅` | hops de proxy a saltar en el XFF y redes de las que se cree |
| `security_headers` | ver fuente | `None` = cabeceras por defecto |

`Config` falla al arrancar, no en producción: claves desconocidas (un typo como
`rate_limt`), regex inválidas o vacías, nombres duplicados, `disabled_rules`
inexistentes y packs desconocidos lanzan `ValueError`.
Las reglas propias se evalúan sobre texto **decodificado, sin comentarios `/**/` y
en minúsculas**; evita patrones con backtracking catastrófico, los patrones
propios no están acotados por Gatekeeper.

## Packs de reglas

Las once familias se evalúan por defecto. Si tu app expone menos superficie de
la que asumes, puedes activar un subconjunto (los packs son **opt-in**: sin
`rule_packs` no cambia nada respecto a lo que ya hacía Gatekeeper).

| Pack | Familias | Para qué |
|---|---|---|
| `strict` | las once | defecto explícito; apps que sirven HTML de terceros |
| `web` | + `xss` sobre `api` | web pública con HTML (el pack que casi todos quieren) |
| `api` | `sqli`, `nosql`, `path_traversal`, `sensitive_files`, `ssrf`, `log4shell`, `crlf`, `cmdi` | APIs JSON/GraphQL: sin `xss`, `ssti` ni `proto_pollution` porque no hay plantilla que renderizar |
| `minimal` | `sqli`, `path_traversal` | solo lo que no depende de la superficie expuesta |
| `infrastructure` | `ssrf`, `log4shell`, `crlf`, `cmdi` | segunda capa tras un WAF, o backend sin SQL |

```python
from gatekeeper import Config

Config(rule_packs=["api"], disabled_rules=["cmdi"])   # API sin XSS ni SSTI, sin cmdi
```

Un pack desconocido es `ValueError` al arrancar: una app no puede quedarse sin
protección porque alguien escribiera `rule_packs=["we"]`.

## Excluir campos (y no campos)

Cuando tu app acepta por diseño un valor que una firma bloquea (un buscador que
indexa documentación de seguridad, un parámetro `template` con Jinja, un
webhook), exímeno **ese campo**, no la familia entera:

```python
Config(exclude_fields=["template", "bio", "doc_*"])
```

Funciona en los tres transportes: parámetro de query, cabecera (`user-agent`)
y puntero JSON (`/user/bio` o solo `bio`). La detección que cruza varios campos
se conserva: si excluyes `a` pero el payload está repartido entre `a` y `b`,
Gatekeeper quita `a` del objetivo y sigue vigilando `b`. La alternativa es
`disabled_rules`, que apaga la familia para toda la app.

## `gatekeeper report`: mide antes de bloquear

Poner el middleware delante en `monitor_only=True`, dejar correr el tráfico real
y mirar qué salta:

```bash
monitor_only: true      # en tu configuración, mientras tanto
gatekeeper report gatekeeper.log          # ranking de reglas, rutas y campos
gatekeeper report gatekeeper.log --json   # salida legible por máquina
```

El informe agrupa por (regla, campo) —lo que se repite es ruido— y propone un
`exclude_fields` o un `disabled_rules` listo para copiar. Acepta el JSON que
emite el logger de Gatekeeper o un log de acceso genérico
(`GET /ruta?q=... 200`). Los eventos de auditoría no incluyen el contenido del
payload, así que este informe tampoco puede filtrar lo que el log no trae.

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
