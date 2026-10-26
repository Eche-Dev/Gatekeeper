# Gatekeeper 0.9.0

## Qué es

La **validación externa**: la fase que hace que el proyecto deje de depender de
la palabra de quien lo escribió. En esta versión el WAF se mide contra código
ajeno (OWASP CRS), se audita solo en cada push (semgrep + zizmor), se vigila
que no se degrade (benchmarks comparados contra `main`) y se demuestra, con
tests, que el middleware y la aplicación **interpretan el body igual**.

Y en el camino apareció un **bypass real**: el `+` de un body.

| | Antes (0.8.0) | Ahora (0.9.0) |
|---|---:|---:|
| Bypass de SQLi por el `+` del body | **Pasaba con 200** | **403** |
| Análisis estático en cada push | bandit + pip-audit | **+ semgrep (propio y comunidad) + zizmor** |
| Guard de rendimiento en CI | No | **PR vs `main`, misma máquina** |
| Tests diferenciales del body | No | **26 cuerpos borde × Starlette y FastAPI, en 10 versiones** |
| Paquete para la revisión independiente | No | **Sí** (`.audit/PACK-REVISOR/`) |

## Qué cambia

### 1 · Un bypass de SQLi: el `+` de un body

En una **query string**, el `+` es un espacio: así lo parsea el servidor, y así
se trataba desde la 0.7.0. En un **body** o en una **cabecera** no: para la
aplicación, un `+` es un carácter **literal**, y el operador de MySQL en
`sleep(10+6)` lo es.

El middleware lo traducía igual, así que inspeccionaba `sleep(10 6)` mientras
la aplicación usaba `sleep(10+6)`:

| entrada | lo que ve la app | lo que inspeccionaba el middleware | antes |
|---|---|---|---|
| form `q=sleep(10%2B6)` | `sleep(10+6)` | `sleep(10 6)` | **200 (bypass)** |
| json `{"q":"sleep(10+6)"}` | `sleep(10+6)` | `sleep(10 6)` | **200 (bypass)** |
| query `?q=sleep(10%2B6)` | `sleep(10+6)` | `sleep(10+6)` | 403 (ya bien) |

Un `sleep(10+6)` en MySQL duerme **16 segundos**: el time-based SQLi funcionaba.

**El arreglo:** el `+` se lee de las **dos** formas —como espacio y como
literal— en todo lo que no viene de una query string. En la query se mantiene
la lectura de siempre.

**No se pierde ninguna detección:** propio 160/160 (era 159/159; el payload
nuevo es `sleep(10+6)`), retenido 103/109 (94,5 %), CRS 465/1135 (41,0 %) y
11/232 (4,7 %) de falsos positivos, todo igual.

**Coste:** el segundo escaneo solo ocurre si el valor tiene un `+`. Medido en
la misma máquina, antes y después: **+17 %** (209 µs → 245 µs) en ese
escenario, y **+0 % a +2 %** (ruido) en los demás. El benchmark tiene ese
escenario, así que el guard del CI lo vigila.

### 2 · Tests diferenciales: el middleware y la app interpretan el body igual

El middleware lee el body para inspeccionarlo y se lo reinyecta a la
aplicación. Si los dos lo interpretaran de forma distinta, el middleware
inspeccionaría una cosa y la app usaría otra: eso es un bypass o un falso
positivo. **Nadie lo comprobaba.**

`tools/diferencial_body.py` hace tres comprobaciones, contra Starlette y
FastAPI:

- **IGUALDAD** — la app ve **exactamente** lo mismo con y sin middleware (26
  cuerpos borde: JSON con BOM, JSON malformado, forms con campos duplicados,
  multipart con fichero, `text/plain`, sin `content-type`, `octet-stream`…).
- **MARCADOR** — el middleware inspecciona el valor que la app usa. Se mide con
  una regla propia que solo casa con el valor que la app ha declarado y con
  **todas las reglas integradas desactivadas**: si el middleware inspeccionara
  otra cosa, la petición pasaría. **Es la comprobación que encontró el bypass
  de arriba.**
- **ATAQUES** — 12 payloads bloqueados, con la regla esperada y su evento de
  auditoría.

La **fuente única** es el script: el test de pytest llama a las mismas
funciones y la **matriz de compatibilidad** lo ejecuta dentro de un venv con
cada versión, así que el diferencial se mide **en cada versión**, no solo con
la última. Verde en las **10 combinaciones** (Starlette 0.23.0 → última,
FastAPI 0.103.2 → última).

Y está **verificado que no es un test vacío**: contra el código sin el arreglo
del `+` falla (10 fallos, 5 por framework).

### 3 · Análisis estático en cada push (`sast`)

- `semgrep` con **cuatro reglas propias** (`tools/semgrep_rules.yml`) que
  **bloquean**: el log no interpola texto con f-string, `%` ni `.format()`; las
  regex de detección no llevan cuantificadores sin cota (un `\s*` es un DoS
  esperando: es la versión estática del test de fuzzing); nada bloqueante
  dentro de `async def` (congelaría el event loop de todo el proceso); y
  `trust_proxy=True` no se activa dentro del paquete.
- `semgrep` con `p/default` (290 reglas de la comunidad) **informa**: la
  comunidad cambia sus reglas con el tiempo y un hallazgo nuevo suyo no es un
  fallo de este repositorio.
- `zizmor` para los workflows de GitHub Actions, bloqueando desde severidad
  media. Con `persist-credentials: false` en los siete `actions/checkout`, los
  **7 hallazgos de severidad media** que había son **0**.
- Cada regla propia se midió **en las dos direcciones**: 0 hallazgos con el
  código bueno, y salta con el bug que vigila.

### 4 · Guard de rendimiento en CI (`bench`)

No compara contra un umbral absoluto: en un runner de CPU compartida, una
máquina lenta y una regresión real dan el mismo número, así que un umbral solo
puede dar falsos positivos o ser ciego (ya estaba medido y documentado).

Compara **el código del PR y el de `main` en el mismo runner**, con la
**mediana de tres repeticiones**. Medido en local: cuatro de cinco corridas
del mismo código variaron un **0,3 %**, y la quinta un 41 % (una pausa del
sistema: por eso la mediana y no la media). El job publica además el **ruido
medido en ese runner**, que es el dato con el que se calibra el margen.

`benchmarks/latency.py` mide ahora **CPU** (µs por petición) y **memoria pico**
(KiB), y añade los escenarios que faltaban: **carga grande** (body de 100 KB)
y **Redis caído**.

### 5 · Con Redis caído, el WAF no era el cuello de botella

El timeout de conexión a Redis estaba **escrito a pelo**: con Redis caído, cada
petición esperaba **2,0 s** antes de decidir (fail-open admitía tras 2.017 ms;
fail-closed devolvía 503 tras 2.018 ms). La API seguía respondiendo, pero
despacio.

Ahora hay **`Config.redis_timeout`** (2,0 s por defecto, o sea, **el
comportamiento no cambia**: lo que cambia es que el operador tiene la
palanca). Ojo documentado: un timeout *muy* corto hace que un Redis lento
parezca caído, y con `rate_fail_open=True` eso desactiva el rate limit en
silencio. Si lo bajas, baja también ese riesgo.

### 6 · El log de auditoría: también los avisos de configuración

El log de auditoría sanea y acota **todo** lo que escribe —la ruta, el nombre
del campo, el patrón—, pero los avisos de `config.py` (una regla personalizada
con riesgo de ReDoS) escribían el nombre de la regla y el motivo del análisis
tal cual. Un ESC en el nombre limpiaba la terminal de quien leía el log, y un
nombre de 100 KB producía una línea de log de 100 KB. Ahora pasan por
`sanear_y_acotar()`.

**Sin cambios de comportamiento**: el nombre se sanea al escribirlo, no al
validarlo.

### 7 · Paquete para la revisión de seguridad independiente

La revisión que hace falta para cerrar el 100/100 la tiene que escribir
**alguien que no haya ajustado las reglas**. `.audit/PACK-REVISOR/` le da ese
material: el alcance con las fronteras de confianza por orden de prioridad,
**15 comprobaciones ejecutables** sobre el código real, el estado medido
(como línea base), los límites ya conocidos para que no se redescubran como
«hallazgos» y la **plantilla** del informe.

## Migración desde 0.8.0

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni
parámetros obligatorios nuevos. `Config`, `GatekeeperMiddleware`,
`custom_rules`, `disabled_rules`, `rule_packs` y `exclude_fields` funcionan
igual.

**Lo único que puede afectar:**

1. **`Config.redis_timeout`** es un campo nuevo (2,0 s por defecto). El
   comportamiento no cambia; lo que cambia es que se puede ajustar.
2. **La detección ha mejorado** (el `+` del body), no se ha roto. Si tenías un
   campo con `+` y una regla que lo disparaba, ahora puede saltar una regla
   más: es el comportamiento correcto (ese `+` lo ejecutaba MySQL), pero si
   te rompe algo, `exclude_fields` está para eso.
3. **El body con `+` se escanea dos veces**: +17 % de CPU en ese caso medido,
   nada en el resto.

## Detección

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | **160/160 (100 %)** | 0 no documentados (9 documentados) |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados (5 documentados) |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

## Qué NO cubre

Sin cambios respecto a 0.8.0, más un límite nuevo que conviene conocer:

- El **contenido** de los ficheros adjuntos (sí los nombres).
- Los **frames** de un WebSocket (sí el handshake).
- Binarios que no son JSON (imagen, PDF, zip…).
- El tráfico entre query y body si `inspect_cross_carrier=False`.
- **Una aplicación que interprete el body de una forma que su `Content-Type`
  no anuncia**: Gatekeeper decide cómo inspeccionar el body según el
  content-type, y no puede saber lo que hace tu parseo. No es un fallo del
  middleware (es el límite de ser una capa por delante), pero conviene saberlo.
- Autenticación, autorización y consultas parametrizadas: eso va en tu app.
- El regex **dentro** de un mismo texto: lo que se controla es el **número de
  campos**, no el coste de una única evaluación.
- Los cuatro límites de la 0.7.0 (`{{config}}`, `${env:…}`/`${jndi}`, CRLF con
  cabecera citada, IP de metadata citada).

## Compatibilidad

Sin cambios: Python 3.10–3.14, Starlette 0.23.0–1.10.0, FastAPI
0.103.2–0.162.0, uvicorn/hypercorn/daphne y Redis 5.0/7.2. La matriz completa
y **medida** está en
[docs/compatibilidad.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

## Instalación

```bash
pip install --upgrade gatekeeper-asgi          # núcleo
pip install "gatekeeper-asgi[yaml]"             # + configuración por YAML
pip install "gatekeeper-asgi[redis]"            # + rate limit distribuido
```

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

El DoS de disponibilidad de la 0.4.0 (corregido en la 0.4.1) está en
[SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md),
en la sección «Vulnerabilidades corregidas».
