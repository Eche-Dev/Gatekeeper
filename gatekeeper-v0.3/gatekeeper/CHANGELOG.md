# Changelog

Todo lo notable de Gatekeeper. El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y las versiones siguen [SemVer](https://semver.org/lang/es/spec/v2.0.0.html).

## [Sin publicar]

### Corregido

- **El `+` de un body se traducía a espacio: el payload llegaba intacto a la
  aplicación.** En una **query string** el `+` sí es un espacio (así lo parsea
  el servidor) y así se trata desde la 0.7.0. En un **body** o en una
  **cabecera** no: para la aplicación, un `+` es un carácter literal, y el
  operador de MySQL en `sleep(10+6)` lo es. El middleware lo traducía igual
  (`sleep(10 6)`) y **no lo detectaba**: un `q=sleep(10%2B6)` en un formulario
  —o un `{"q": "sleep(10+6)"}` en un JSON— pasaba con **200**, y la aplicación
  ejecutaba la consulta con `sleep(10+6)`, que en MySQL duerme 16 segundos.
  - **Cómo se ha corregido**: el `+` se lee de las **dos** formas —como espacio
    y como carácter literal— en todo lo que no viene de una query string. En
    la query se mantiene la lectura de siempre (una sola traducción, en la
    primera ronda de decodificación: el arreglo de la 0.7.0).
  - **Medido**: corpus propio **160/160** (era 159/159; el payload nuevo es
    `sleep(10+6)`), retenido **103/109 (94,5 %)** sin cambios, CRS **465/1135
    (41,0 %)** y **11/232 (4,7 %)** de falsos positivos sin cambios: **no se
    pierde ninguna detección**.
  - 5 tests nuevos y 2 entradas de corpus (el ataque y su contraparte benigna,
    `2+2=4`).
  - **Coste medido**: el segundo escaneo solo ocurre si el valor tiene un `+`.
    Medido en la misma máquina, antes y después: **+17 %** (209 µs → 245 µs) en
    el escenario de un body con `+`, y **+0 % a +2 %** (ruido) en los demás.
    El benchmark tiene ese escenario, así que el guard del CI lo vigila.
- **El timeout de Redis estaba escrito a pelo y no se podía ajustar.** Con
  Redis caído, cada petición esperaba **2,0 s** antes de decidir (medido:
  fail-open admitió la petición tras 2.017 ms; fail-closed devolvió 503 tras
  2.018 ms). La API seguía respondiendo, pero despacio: si Redis se caía, el
  WAF se convertía en el cuello de botella. Ahora hay **`Config.redis_timeout`**
  (2,0 s por defecto, o sea, **el comportamiento no cambia**: lo que cambia es
  que el operador tiene la palanca).
  - Ojo documentado: un timeout *muy* corto hace que un Redis lento parezca
    caído, y con `rate_fail_open=True` eso desactiva el rate limit en
    silencio. Si lo bajas, baja también ese riesgo.
  - La 0.6.0 ya añadió campos nuevos a la `Config` (`max_fields`,
    `max_inspection_ms`), así que esto sigue la práctica del proyecto: campo
    nuevo con valor por defecto, sin romper nada.
  - 4 tests nuevos, uno de ellos de regresión: con el timeout corto, la caída
    de Redis no puede colgar la petición.
- **El nombre de una regla personalizada llegaba al log sin sanear.** El log
  de auditoría (`middleware._audit`) sanea y acota todo lo que escribe —la
  ruta, el nombre del campo, el patrón—, pero los avisos de `config.py` (una
  regla personalizada con riesgo de ReDoS) escribían el nombre de la regla y
  el motivo del análisis tal cual. Un ESC en el nombre limpiaba la terminal de
  quien leía el log, y un nombre de 100 KB producía una línea de log de 100
  KB. Ahora el nombre y el motivo pasan por `sanear_y_acotar()`.
  - **Cómo se ha encontrado**: en la Fase 6, montando las reglas de semgrep.
  - **Sin cambios de comportamiento**: el nombre se sanea al escribirlo, no al
    validarlo. Un nombre que no sea texto sigue aceptándose igual que antes.

### Añadido

- **Tests diferenciales del body** (`tools/diferencial_body.py`): la misma
  petición con y sin middleware, contra Starlette y FastAPI.
  - **IGUALDAD**: la aplicación tiene que ver **exactamente** lo mismo con y
    sin middleware. 26 cuerpos borde: JSON con BOM, JSON malformado, forms con
    campos duplicados, multipart con fichero, `text/plain`, sin `content-type`,
    `octet-stream`…
  - **MARCADOR**: el middleware tiene que **inspeccionar el valor que la
    aplicación usa**. Se mide con una regla propia que solo casa con el valor
    que la app ha declarado, y con **todas las reglas integradas desactivadas**:
    si el middleware inspeccionara otra cosa, la petición pasaría. Esta
    comprobación es la que encontró el bypass del `+` de arriba.
  - **ATAQUES**: 12 payloads tienen que estar bloqueados, con la regla
    esperada y con su evento de auditoría.
  - La **fuente única** es el script: el test de pytest llama a las mismas
    funciones y la **matriz de compatibilidad** lo ejecuta dentro de un venv
    con cada versión de Starlette y FastAPI, así que el diferencial se mide
    **en cada versión**, no solo con la última.
  - **Medido**: verde en las **10 combinaciones** de la matriz (Starlette
    0.23.0 → última, FastAPI 0.103.2 → última), y **verificado que no es un
    test vacío**: contra el código sin el arreglo del `+` falla (10 fallos, 5
    por framework).
- **Job `sast` en el CI**: `semgrep` con las reglas de la comunidad y con
  **cuatro reglas propias del proyecto**, y `zizmor` para los workflows de
  GitHub Actions.
  - Las reglas propias (`tools/semgrep_rules.yml`) **bloquean**; las de la
    comunidad solo informan, porque `p/default` cambia con el tiempo y un
    hallazgo nuevo de la comunidad no es un fallo de este repositorio.
  - Cada regla se midió **en las dos direcciones**: 0 hallazgos con el código
    bueno, y salta con el bug que vigila. El script que lo comprueba está en
    `.audit/f6_mide_reglas.py`.
  - Las cuatro: el log no interpola texto con f-string, `%` ni `.format()`; las
    regex de detección no llevan cuantificadores sin cota (un `\s*` es un DoS
    esperando: es la versión estática del test de fuzzing); nada bloqueante
    dentro de `async def` (congelaría el event loop de todo el proceso); y
    `trust_proxy=True` no se activa dentro del paquete.
  - El job **anula el `working-directory` del workflow**: necesita las dos
    raíces (el paquete, para semgrep, y la raíz del repo, para zizmor). Sin
    eso, semgrep buscaba las reglas en
    `gatekeeper-v0.3/gatekeeper/gatekeeper-v0.3/gatekeeper/tools/…` y moría
    con «unable to find a config».
  - Cada paso guarda su salida en el log y en el resumen del job, y emite
    `::error::` con el código de salida: si un análisis falla, el motivo se lee
    sin abrir el log a mano.
- **`persist-credentials: false` en los siete `actions/checkout`** de los tres
  workflows. El token de GitHub no se queda en `.git/config`, donde puede
  acabar en un artefacto. `zizmor` lo auditaba: 7 hallazgos de severidad
  media, ahora **0**.
- **Job `bench` en el CI**: guard de regresiones de rendimiento. No compara
  contra un umbral absoluto (en un runner de CPU compartida, una máquina lenta
  y una regresión real dan el mismo número, así que un umbral solo puede dar
  falsos positivos o ser ciego: ya estaba medido y documentado en
  `benchmarks/latency.py`). Compara **el código del PR y el de `main` en el
  mismo runner**, con la mediana de tres repeticiones.
  - El ruido de la máquina se cancela al comparar dos ejecuciones en la misma
    máquina. Medido en local: cuatro de cinco corridas del mismo código
    variaron un **0,3 %**, y la quinta un 41 % (una pausa del sistema: por eso
    la mediana y no la media).
  - El job publica además el **ruido medido en ese runner**, que es el dato
    con el que se calibra el margen.
- **`benchmarks/latency.py` ampliado**: mide ahora **CPU** (µs por petición,
  con `process_time`) y **memoria pico** (KiB, con `tracemalloc`), y añade los
  escenarios que faltaban: **carga grande** (body de 100 KB) y **Redis caído**.
  `--ruido` mide cuánto se mueven dos corridas del mismo código, que es lo que
  decide si un umbral en CI puede existir.

## [0.8.0] - 2026-10-26

### Distribución y repositorio

- **El sdist pasa de 514 KiB a 95 KiB.** Se carryendo el corpus (588 KiB sin
  comprimir), la web, las demos, los benchmarks y los tests. Eso vive en
  GitHub y el README lo enlaza; lo que se baja de PyPI es el WAF.
  - El CI lo **vigila**: el job `package` falla si el sdist pasa de 100 KiB, y
    además instala el sdist en un entorno limpio (es lo que se baja quien
    instala "desde el código").
- **`AGENTS.md`** en la raíz del repo: el método con el que se trabaja el
  proyecto (verificar, no creer; medir antes de endurecer una firma; test
  antes del arreglo; los falsos positivos se documentan, no se esconden).
- **Limpieza de la raíz**: `anchor_check.py` y `link_check.py` (sueltos,
  sustituidos por `tools/check_docs.py`), el parche suelto del fix de ReDoS y
  los dos planes antiguos se mueven a `.audit/`, que es donde vive la
  evidencia del proyecto. `Evaluacion-ia/` también.
- `corpus/events.json` actualizado a la **0.8.0** (el catálogo de eventos
  decía 0.3.1).

### Documentación

- **La documentación no miente, y ahora se comprueba.** `tools/check_docs.py`
  (nuevo, en CI) verifica tres cosas de forma automática: que la versión que
  dicen el README, la guía de instalación, la tabla de `SECURITY.md` y el
  CHANGELOG sea **la misma** que la de `pyproject.toml`; que los enlaces
  internos y sus **anclas** existan (un ancla con tilde se rompía según cómo
  se escribiera, y ahora los títulos llevan ancla explícita `{#id}`); y que no
  vuelvan a colarse las erratas que ya se colaron una vez (`aThird parties`,
  `functionality`, `consequences`, el email personal…).
- **README en inglés** (`README.en.md`), enlazado desde el español. La
  documentación y el CHANGELOG siguen en español.
- **Los enlaces del README son absolutos.** En la ficha de PyPI un enlace
  relativo a `docs/…` daba 404: ahora apuntan al repo.
- **`Config.validate()` fuera de la documentación**: ese método no existe (la
  validación ocurre en `__post_init__`). Y el ejemplo de `custom_rules` usaba
  `re.compile(...)` donde la API espera **patrones de texto**.
- **La API pública es explícita**: `gatekeeper.scan`, `gatekeeper.scan_all`,
  `gatekeeper.scan_detailed`, `gatekeeper.RULES`, `gatekeeper.PACK_NAMES` y
  `gatekeeper.resolve_rules` se exportan y se testean (`tests/test_api_publica.py`).
  `scan_all` recorre **varios valores** y devuelve la primera coincidencia
  (su docstring lo dice, porque el nombre puede hacer pensar otra cosa).
- **Sin email personal en los metadatos** de PyPI: el canal de contacto es
  GitHub Security Advisories.
- **El umbral de CI del corpus de CRS sube a la línea base real** (0,19 → 0,40).
  Con 0,19, una regresión del 41 % al 20 % pasaba el CI mientras el README
  prometía lo contrario.
- `ROADMAP.md` al día (seguía en la v0.3) y `SECURITY_REVIEW.md` con una nota
  que aclara que describe **la 0.3.1**, no el código actual.
- Corregidos: `aThird parties`, `functionality`, `consequences`, la frase
  truncada de «Comparar rendimiento» (ahora con la receta completa) y la
  contradicción de `allow_paths` con el rate limit en la guía de despliegue.
- `attr_list` activado en MkDocs para que las anclas explícitas funcionen.
- `tools/metrics.py` tiene **tests** (`tests/test_metrics.py`): los
  contadores cuentan lo que dicen y las métricas **no filtran** IPs, rutas,
  nombres de campo ni patrones.
- El job `compat` del CI (programado, no bloqueante) **mide** la matriz de
  compatibilidad: `tools/compat_matrix.py` ya estaba escrito y no se ejecutaba
  nunca.

### Corregido

- **La portada de la web anunciaba un mínimo de Starlette que no era el real.**
  `docs/index.md` decía «Starlette ≥ 0.37» mientras `pyproject.toml` declara
  `starlette>=0.23`. El 0.37 no era un mínimo arbitrario: era el que **rompía
  la instalación** de quien usara FastAPI 0.103.x, porque al instalar
  Gatekeeper, pip subía Starlette por encima de 0.28 y FastAPI dejaba de
  funcionar (arreglado en la 0.4.0). La portada —la primera página que ve
  quien llega a la web— seguía anunciando el valor causante del problema.
  - Es el hallazgo **B-10** de `AUDITORIA-2026-10-25.md`, que la Fase 4
    corrigió a medias: `docs/instalacion.md` sí se arregló, `docs/index.md` no.
  - **`tools/check_docs.py` ahora lo caza**: comprueba que el mínimo que
    afirma la documentación sea el que declara `pyproject.toml`. La versión de
    Gatekeeper ya se comparaba entre sitios; ahora también la de sus
    dependencias. La comprobación exige que cada afirmación nombre a la
    dependencia en su propia frase, para que un `redis >= 5.0` cerca de
    `starlette` no se confunda.

### Cambiado

- **Los README reescritos** (el del paquete, el de la web y el inglés). Ahora
  explican **qué hace el proyecto y por qué existe** antes de entrar en
  detalle: el problema (una IP que pide de más, cabeceras que nadie pone, un
  campo sin validar), las tres cosas que hace el middleware y una sección
  corta de «qué revisa». El ejemplo de respuesta 403 y de evento de auditoría
  es **real**, generado ejecutando el middleware, no escrito a mano.
  - La tabla de 22 filas de protecciones pasa a ser una tabla de 7 por
    superficie, con el detalle por familia en `docs/amenazas.md` (que ya
    existía).
  - La tabla de percentiles de latencia pasa a un párrafo con los tres
    números y el comando para reproducirlos: la ficha de PyPI se leía peor.

## [0.7.0] - 2026-10-26

### Corregido

Falsos negativos reales: vectores que **no se detectaban** y que un atacante
usa sin que el WAF se entere. Cada uno se reprodujo contra el código antes de
tocar nada (`.audit/f3_probe.py`, 15 casos).

- **Tautología con literales vacíos** (`' or ''=`). La firma exigía un literal
  con contenido (`['\"]\w+['\"]`), así que el atacante que cierra la comilla
  del valor y mete la comparación con cadena vacía se colaba.
- **Booleano ciego con la función de recorte primero**
  (`substring(version(),1,1)=5`). La firma solo veía la forma invertida
  (`ascii(substring(...))`).
- **SSRF con la IP de metadata escrita en decimal, hex y octal**
  (`http://2852039166/`, `http://0xa9fea9fe/`, `http://0252.0376.0252.0376/`).
  El parser de URL del navegador las resuelve igual que `169.254.169.254`.
- **Comandos separados por un salto de línea** (`foo\nrm -rf /`). En shell, un
  salto de línea es un separador tan real como `;`.
- **El `+` de un query string se perdía al decodificar.** `decode()` traducía
  `+` a espacio en **cada** ronda, así que `sleep(10%2B6)` llegaba como
  `sleep(10 6)` y no se detectaba. Ahora la traducción de `+` se aplica **una
  sola vez**, en la primera ronda: el `+` que el servidor entrega al usuario
  se entrega también a Gatekeeper.

Falsos positivos: texto normal que un operador recibe cada día (documentación,
tutoriales, una consulta que se describe en prosa) y que la firma confundía con
un ataque.

- **`<script>` en prosa.** «En el manual pone: `<script>` para incrustar
  código» no es un ataque. Ahora `<script>` solo salta con atributos, con
  etiqueta de cierre, o seguido de algo que no puede ser prosa.
- **`sleep(8 hours)`** y cualquier `sleep` con unidades: es texto, no una
  función SQL. Ahora `sleep` exige un argumento **numérico** (se admiten
  `20.to_i` y una operación aritmética, que son las formas reales de
  blindaje).
- **`union all` en un tutorial de SQL.** Ahora exige contexto de consulta o
  de ruta detrás (`select`, `from`, `null`, `values`, `table`, `(`, `/`).
- **`waitfor delay` en prosa.** Ahora exige el literal de tiempo detrás (la
  forma real es `WAITFOR DELAY '0:0:5'`).
- **`like null` en prosa.** Ahora exige el cierre del payload detrás.
- **Operadores NoSQL citados en una búsqueda** (`qué es el operador $ne de
  mongodb`). Ahora exigen estar dentro de un objeto JSON o de un parámetro
  (`{"$ne": ""}`, `user[$ne]=x`), que es donde llega el ataque.

Ningún endurecimiento perderá una detección: cada firma se midió antes de
tocarla, contando cuántos ataques dependían **solo** de ella (`.audit/f3_ajustes.py`),
y después se comparó el corpus externo de OWASP CRS payload a payload
(`0 perdidos, 0 ganados` sobre los 1.379 tests importados).

### Añadido

- **100 peticiones legítimas nuevas** en el corpus, escritas en **español e
  inglés**: 50 en el corpus de desarrollo (`corpus/benign.json`,
  `benign-082`…`benign-131`) y 50 en el corpus **retenido**
  (`corpus/heldout_benign.json`, `hob-091`…`hob-140`), estos últimos escritos
  **después** de congelar las firmas y medidos **una vez**: un falso positivo
  ahí no se corrige con una firma escrita para él, se documenta.
- Los cuatro falsos positivos del lote retenido que quedan abiertos están
  **publicados** con su motivo (`{{config}}`, `${env:…}`/`${jndi}`, el salto de
  línea seguido de cabecera, y la IP de metadata citada en una explicación).
- 39 tests de regresión (`tests/test_deteccion_f3.py`) que fijan los 4 FN
  cerrados, los 2 FP de prosa cerrados y las detecciones que no pueden
  perderse, y 35 más (`tests/test_deteccion_f3_5.py`) que fijan el contrato
  del corpus de falsos positivos nuevo.
- `corpus/README.md`, `corpus/HELDOUT.md`, `docs/deteccion.md`, `README.md` y
  `docs/index.md` con las cifras nuevas (corpus propio: 159 ataques y **131**
  peticiones legítimas; retenido: 109 ataques y **140** peticiones legítimas).

### Nota de comportamiento

Endurecer una firma tiene un precio y aquí está medido:

| Firma | Qué ya no se detecta | Por qué |
|---|---|---|
| `union all` | `union all` sin contexto de consulta detrás | «union all» en un tutorial es de las búsquedas más frecuentes |
| `WAITFOR DELAY` | `waitfor delay` sin comilla ni dígito detrás | La forma real siempre lleva el literal |
| `like null` | `like null` en mitad de una frase | La forma de ataque cierra el payload |
| NoSQL | `$ne` suelto, sin objeto JSON ni parámetro | El ataque va dentro de un objeto |
| `sleep` | `sleep(8 hours)` y cualquier unidad | Es prosa, no una función SQL |

El detalle completo, con las cifras, está en
[docs/deteccion.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/deteccion.md).

## [0.6.0] - 2026-10-26

### Corregido
- **El rate limiter no tenía tope de claves.** El backend en memoria guardaba un
  `deque` por cada IP distinta, sin límite: medido, 200.000 IPs distintas
  costaban **174,9 MB** de RAM (875 B por clave) y la poda era O(n) en cada
  limpieza. Ahora la tabla está acotada (`rate_max_keys`, 10.000 por defecto):
  al llegar al tope sale la clave **menos usada** (LRU). Con el tope, esas
  mismas 200.000 IPs ocupan **9,4 MB**, y la inserción es O(1).
- **La IPv6 se contaba por dirección, y eso no limitaba a nadie.** Un /64 es el
  prefijo delegable más pequeño (RFC 6177): quien tiene un /64 puede rotar
  2^64 direcciones sin que el contador se entere. Ahora las direcciones del
  mismo prefijo cuentan juntas (`rate_ipv6_prefix`, /64 por defecto; 128 = sin
  agrupar).
- **`::ffff:1.2.3.4` y `1.2.3.4` contaban aparte.** La misma dirección en dos
  formas llevaba dos contadores. Ahora la clave de conteo se normaliza. La IP
  **cruda** se sigue registrando en la auditoría.
- **`blocked_ips` con una entrada IPv4-mapped era un no-op silencioso.**
  `blocked_ips={"::ffff:127.0.0.1"}` (o `{"::ffff:0:0/96"}`) se aceptaba al
  arrancar y **no bloqueaba nada**: la IP entrante se normaliza a IPv4 y se
  comparaba contra una red IPv6, que nunca coincide. Una protección que no
  protege. Ahora esas entradas se traducen a su equivalente IPv4 y bloquean las
  dos formas.

### Añadido
- `Config(rate_max_keys=...)`: tope de IPs distintas que el backend en memoria
  recuerda (10.000). `Config(rate_ipv6_prefix=...)`: bits de prefijo IPv6 que se
  agrupan al contar (64).
- **Presupuesto de campos por petición** (`Config.max_fields`, 1000 textos
  inspeccionados: una clave y su valor cuentan como dos). Al superarlo, la
  petición se **rechaza con 413** y se audita `too_many_fields`. Los campos que
  sobran **no se ignoran**: ignorarlos sería un bypass, porque el atacante
  mandaría el payload en el campo que se queda sin inspeccionar.
- **Presupuesto de tiempo de inspección** (`Config.max_inspection_ms`, 1 s).
  Al superarlo, la petición se **rechaza con 413** y se audita
  `inspection_timeout`. No hay modo fail-open: un presupuesto que se pudiera
  agotar a propósito para saltarse la detección sería un bypass. El defecto
  es holgado a propósito: la protección principal es `max_fields`, que no
  depende de la velocidad de la máquina.
- 23 tests que fijan el contrato de lo anterior (`tests/test_ratelimit_hardening.py`).
- 18 tests que fijan el contrato del presupuesto
  (`tests/test_presupuesto_inspeccion.py`), dos contadores nuevos en
  `tools/metrics.py` (`gatekeeper_too_many_fields_total`,
  `gatekeeper_inspection_timeout_total`) y dos eventos nuevos en el catálogo
  `corpus/events.json`.
- **Las reglas propias se validan al arrancar** (`src/gatekeeper/redos.py`).
  Antes se compilaban tal cual: `(a+)+$` sobre 60 caracteres no terminaba en
  20 segundos, y eso era un DoS en el propio WAF, sin necesidad de adversario.
  Ahora el patrón se analiza **de forma estática** (sin ejecutarlo: medirlo
  sería el propio DoS) y hay dos niveles:
  - **Exponencial** → `ValueError` al arrancar: cuantificadores anidados sin
    nada obligatorio detrás (`(a+)+`), alternativas solapadas en un grupo
    repetido (`(a|a)+`, `(a|ab)+`) y referencias atrás repetidas.
  - **Cuadrático** → warning en el log, la app arranca: cuantificadores
    anidados con separador detrás (`(?:\w+\.)+\w+`). No cuelga con una
    entrada corta, pero se degrada con el tamaño (medido: 7,4 s con 50.000
    caracteres).
  - `Config(allow_unsafe_custom_rules=True)` acepta el riesgo exponencial
    (y avisa). También hay topes de longitud de patrón (1000) y de número de
    reglas (100).
  - 33 tests que fijan el contrato (`tests/test_custom_rules_redos.py`).

### Corregido
- **El puntero JSON perdía el segmento al llegar a 64 niveles.** Se marcaba el
  corte y se devolvía la ruta del padre: la atribución apuntaba al campo
  equivocado y `exclude_fields` (que compara por el último segmento) no
  casaba con el campo real, de modo que un campo exento a 64 niveles seguía
  bloqueándose. Ahora el puntero conserva la clave exterior, marca el corte y
  acaba en el campo que saltó: a 80 niveles, `/n1/…/n80`.
- **Dos patrones de inyección SQL estaban en la familia equivocada.**
  `union all` y `or '…` vivían en `sensitive_files`, así que
  `disabled_rules=["sqli"]` no los apagaba (medido: `union all select 1` se
  seguía detectando y se reportaba como `sensitive_files`). Ahora están en
  `sqli`, con los cuantificadores acotados (`\s{1,32}`) como toda regla
  integrada. Se ha movido también `||`, que estaba en el mismo grupo con el
  mismo comentario. El corpus no se mueve: 159/159 y 158 por la regla
  esperada, igual que antes.
- **Patrones duplicados dentro de `sensitive_files`:** los de logs y volcados
  estaban escritos dos veces (con las clases de caracteres en distinto
  orden). Ahora hay una sola copia.
- **La documentación nombraba un evento que el middleware nunca emitía**
  (`rl_backend_unavailable`; el real es `rate_backend_error`) y describía
  cuerpos de error que no eran los reales (`rate limit exceeded` y
  `rate_limit_backend_unavailable`; los reales son `Too Many Requests` y
  `Service Unavailable`). Corregidos, con un test que comprueba que la doc no
  invente eventos ni cuerpos.
- **El HSTS se documentaba como condicional al esquema, y no lo es.** La doc
  decía que se omitía en `http://` "porque forzarla en desarrollo local
  rompería tu entorno". No es cierto: según el RFC 6797 (§7.2) el
  navegador **tiene que ignorar** un STS recibido por una conexión no
  segura. Y omitirlo según el esquema sería peor: detrás de un proxy que
  termina TLS, la app ve `http` y HSTS desaparecería sin avisar. Se corrige
  la doc; el código se queda como estaba.
- **El escape de terminal en `gatekeeper report`** (ambos formatos). Lo que el
  CLI imprime lo elige el atacante (el nombre de un campo, la ruta): un
  `\x1b[2J` en la URL podía borrar la pantalla del operador o reescribir el
  título de su ventana. En el formato JSON, `json.loads` convertía el
  `\u001b` del archivo en un ESC real, que llegaba a la terminal tal cual. Ahora
  todo el texto que se imprime va **saneado** (sin ESC ni otros caracteres de
  control; el ESC se marca como `\e` para que se vea que había algo).
- **El log de auditoría se sanea y se acota.** El mismo texto no confiable
  llegaba al archivo de log, y de ahí a la terminal de quien lo abría (o a un
  SIEM). Ahora el texto que se registra va sin caracteres de control y
  acotado a 256 caracteres: un nombre de campo de 100 KB ya no produce una
  línea de log de 100 KB.
- **La promesa del log era falsa.** Documentaba que "nunca se registra el
  contenido del payload", pero el **nombre** de un campo lo elige el atacante:
  un parámetro cuyo nombre es el payload entero llegaba entero al log. Lo que
  se garantiza (y ahora se dice con precisión en `SECURITY.md`, `docs/`,
  `README.md` y `corpus/events.json`) es que los **valores** nunca se
  registran; los **nombres** sí, porque sin ellos no se puede atribuir un
  falso positivo. El log es texto no confiable, no un depósito de
  credenciales interceptadas.

### Cambiado
- **`max_body_size` baja de 1 MiB a 256 KiB por defecto.** Es el límite de lo
  que se lee: la inspección consume CPU. Si tu app acepta bodies mayores,
  súbelo (por endpoint, con dos instancias de `Config` si hace falta).

### Corregido
- **El coste de inspeccionar escalaba con el número de campos, y el límite de
  tamaño no lo cubría.** Medido: ~67 µs por campo, así que 20.000 campos
  costaban **1,34 s** de CPU en una sola petición (y el `max_body_size` no
  los frenaba: un cuerpo de muchos campos es pequeño). Con el presupuesto,
  26.000 campos se rechazan en **0,003 s**.

## [0.5.0] - 2026-10-25

Cierra tres de los bypasses que encontró la auditoría de seguridad del 25 de
octubre (ver `AUDITORIA-2026-10-25.md` en el repo). Los tres eran **superficies
que el atacante elige**: el protocolo, el content-type y el formato del body.

### Añadido
- **WebSocket: el handshake se inspecciona y tiene rate limit.** Antes el
  middleware salía con `scope["type"] != "http"` y dejaba pasar todo lo que no
  fuera HTTP: un handshake como `/ws?q=union%20select...` se aceptaba sin
  mirar, y **sin rate limit** (con `rate_limit=1` entraban 6 conexiones de 6).
  Ahora del handshake se revisan la ruta, la query y las cabeceras, la IP
  cuenta igual que en HTTP (bloqueo y rate limit), y el handshake rechazado se
  cierra con el código 1008 (el servidor responde 403). Los **frames** no se
  inspeccionan: llegan después de aceptar la conexión. Se desactiva con
  `inspect_websockets=False`.
- **`application/octet-stream` se sniffea.** El content-type genérico lo
  controla el atacante, así que no decide: decide el **contenido**. Si el
  cuerpo es JSON (empieza por `{` o `[`), se inspecciona como JSON. Antes,
  mandar la consulta con ese content-type esquivaba la detección entera, y una
  app con `await request.json()` lo parsea igual.
- **Multipart: se inspeccionan los nombres de campo y de fichero.** Un
  `filename=../../etc/passwd` o un campo de texto con un payload ahora se
  bloquean (403). El **contenido** del fichero no se inspecciona: es binario y
  leerlo entero no aporta nada. El parser es mínimo y conservador (sin
  dependencias nuevas): si el multipart no se entiende, no se inventa nada.
  Se desactiva con `inspect_multipart=False`.

### Cambiado
- **Los bodies multipart ahora se leen**, así que les aplica el
  `max_body_size` (1 MiB por defecto) como a los demás: una subida de más de
  1 MiB recibe un **413**. Si tu app acepta ficheros grandes, sube
  `max_body_size` o pon `inspect_multipart=False`. Es el precio de poder
  inspeccionar el multipart: no se puede revisar lo que no se lee.
- `docs/amenazas.md`, `docs/uso.md`, `README.md` y `SECURITY.md`: la tabla de
  transportes inspeccionados refleja las tres superficies nuevas, y la lista
  de lo que **no** se cubre dice exactamente qué queda fuera (el contenido de
  los ficheros, los frames de WebSocket y los binarios que no son JSON).

### Sin cambios
- Las cifras de detección **no se mueven**: corpus propio 159/159 (100 %),
  corpus retenido 94,5 % con 0 falsos positivos no documentados, OWASP CRS
  41,0 % de detección y 4,7 % de falsos positivos, modo cruzado 7/7. Ninguna
  regla nueva: se ha cerrado el alcance de las que ya había.

## [0.4.1] - 2026-10-25

### Corregido
- **DoS cuadrático en la normalización de comentarios SQL** (seguridad, sin
  autenticación). `normalize()` usaba `re.sub(r"/\*.*?\*/", " ", text,
  flags=re.DOTALL)`: por cada `/*` **sin cierre** el motor recorrería el resto
  del texto, así que el coste crecía como O(n²). Medido sobre el código de
  0.4.0: **23,6 s con 128 KB** y **5,5 s con una sola petición de 64 KB**, que
  además devolvía 200 y bloqueaba el event loop; con el `max_body_size` de
  1 MiB por defecto eran **~25 minutos de CPU por petición**. El caso más
  fácil de explotar es un `POST` con `Content-Type: text/plain` y el cuerpo
  formado por `/*a` repetido. La corrección sustituye los dos `re.sub` por un
  barrido **lineal** con `str.find` (`_strip_sql_comments()`), que conserva la
  semántica original: `/*!50000union*/` se sigue **desenvolviendo** (MySQL lo
  ejecuta) y un `/*` sin cierre se deja tal cual. Con el arreglo, 128 KB
  tardan **0,009 s** y el tiempo crece de forma lineal.
  Regresión cubierta por `tests/test_redos_comentarios.py`, que además exige
  que el coste **crezca linealmente** y no solo que «no tarde mucho».
- Las cifras de detección **no cambian**: corpus propio 159/159, corpus
  retenido 94,5 % con 0 falsos positivos no documentados, OWASP CRS 41,0 % de
  detección y 4,7 % de falsos positivos, modo cruzado 7/7.

### Añadido
- **Sección «Vulnerabilidades corregidas»** en `SECURITY.md` y aviso de
  seguridad en GitHub (GHSA) con los detalles, la PoC y elmitigación.

### Cambiado
- `SECURITY.md` y `docs/seguridad.md`: la tabla de versiones soportadas pasa a
  listar **0.4.x como activa** (0.4.0 ya estaba publicada en PyPI) y se
  elimina el aviso de que «todavía no hay nada publicado en PyPI», que era
  falso desde la 0.4.0.
- `docs/seguridad.md`: la sección «ReDoS: la historia honesta» incluye ahora
  **este** hallazgo, no solo el backtracking de los cuantificadores de v0.3.
- `docs/seguridad.md` y `SECURITY.md`: la vía de reporte unificada es **GitHub
  Security Advisories**; se retira el email personal de la documentación.

## [0.4.0] - 2026-10-25

### Añadido
- **Matriz de compatibilidad medida** (`docs/compatibilidad.md` y
  `tools/compat_matrix.py`): Starlette 0.23.0–1.10.0, FastAPI
  0.103.2–0.162.0, Python 3.10–3.14, uvicorn/hypercorn/daphne y Redis
  5.0/7.2. La herramienta crea un entorno virtual por cada combinación y
  comprueba que el middleware bloquea un ataque, deja pasar lo legítimo y
  pone las cabeceras de seguridad; la tabla se regenera con ella, así que
  no es una suposición.
- **Política de soporte, compatibilidad de API y proceso de release**
  (`docs/compatibilidad.md`): qué significa «soportada», qué ramas reciben
  correcciones, qué se considera API pública (y qué no, y por qué), la
  política de deprecaciones según SemVer, el proceso de release con sus
  tags, y las notas de migración por versión.
- **Límites de tiempo y memoria en el fuzzing** (`tests/test_fuzz.py`):
  además de las propiedades con Hypothesis, ahora hay límites de tiempo
  (entradas patológicas de hasta 1 MiB en menos de 1 s) y de memoria (el
  escaneo y la extracción no pueden amplificar la memoria más de un factor
  acotado). El límite de memoria es la regresión del hallazgo de seguridad
  H-1. También se cubre que una regex del usuario inválida rompe el
  arranque.
- **Revisión de seguridad** (`SECURITY_REVIEW.md`): revisión por zonas de
  confianza con PoC ejecutables sobre el código real. Documenta un hallazgo
  alto (el DoS de memoria corregido más abajo), 4 hallazgos aceptados con su
  justificación y 5 límites conocidos. El informe declara explícitamente que
  **no es una revisión independiente** (la hizo quien escribió el código) y
  qué parte sí lo es (las mediciones y las regresiones).
  `tests/test_informe_seguridad.py` comprueba que las afirmaciones medibles
  del informe siguen siendo ciertas.
- **Extra `servers`** (`hypercorn`, `daphne`): los servidores ASGI alternativos
  para las pruebas de integración con servidores reales. No están en el extra
  `dev` a propósito: daphne arrastra Twisted, cuya versión **estable**
  (26.4.0) tiene avisos de seguridad cuyos parches solo están en una release
  candidate (26.10.0rc1). Como el runtime del paquete no depende de ellos, no
  tiene por qué arrastrar ese riesgo. Para probarlos:
  `pip install -e ".[dev,servers]"`.
- **Catálogo de eventos de auditoría** (`corpus/events.json`): los 5 tipos de
  evento que emite el middleware, con sus campos, a qué código de respuesta
  corresponden, qué NUNCA se registra (payload, cuerpos, valores de cabeceras,
  cookies) y la política de privacidad. Un test comprueba que el catálogo y el
  código no se desincronizan.
- **Exportador de métricas Prometheus** (`tools/metrics.py`): convierte un log
  de auditoría en 5 contadores (`gatekeeper_attacks_total{rule,source}`,
  `gatekeeper_rate_limited_total`, `gatekeeper_blocked_ips_total`,
  `gatekeeper_body_too_large_total`,
  `gatekeeper_rate_backend_errors_total{fail_open}`). Verificado por test: la
  salida **no contiene IPs, rutas, payloads ni patrones**, solo conteos.
- **Guía operativa** (`docs/operacion.md`): qué observar, qué alertar, el
  despliegue gradual en 4 pasos y la tabla de rollback.
- **Pruebas con servidores ASGI reales** (`tests/test_servidores_asgi.py`):
  uvicorn, hypercorn y daphne se lanzan como subprocesos y reciben
  peticiones HTTP por un socket de verdad. Con los tres: la petición legítima
  da 200, el ataque da 403, el 413 por `Content-Length` llega sin enviar el
  body, y las cabeceras de seguridad salen. Los tres servidores se añaden al
  extra `dev`, así que CI los prueba.
- **Pruebas de límites de memoria** (`tests/test_limites_memoria.py`): un body
  que excede `max_body_size` se corta sin acumularse (64 MiB con límite de
  1 MiB consumen ~1 MiB); el consumo de un body permitido está acotado a ~2× su
  tamaño e independiente de la fragmentación; y el middleware no retiene
  memoria entre peticiones.
- **Pruebas de rate limit entre procesos de Python reales**
  (`tests/test_redis_multiproceso.py`): cuatro procesos lanzados con
  `multiprocessing`, cada uno con su cliente de Redis, se conceden
  exactamente los permisos del límite. Incluye el contraste con el backend en
  memoria, que concede el límite **por proceso**: sin ese contraste, el test
  no demostraría nada.
- **Corpus retenido (held-out)**: `corpus/heldout_attacks.json` (109 ataques) y
  `corpus/heldout_benign.json` (90 peticiones legítimas), con su evaluador
  `tools/evaluate_heldout.py`, su informe `corpus/HELDOUT_REPORT.md` y la
  metodología en `corpus/HELDOUT.md`. Es un corpus escrito **una vez, sin
  mirar las firmas de las reglas**, y desde entonces solo medido: mide si las
  reglas generalizan, no si se acuerdan de los casos con los que se escribieron.
  Resultado: **103/109 (94,5%)** de detección y **0** falsos positivos sin
  documentar sobre tráfico legítimo. Entra en CI con su propia guarda.
- **Corpus retenido del modo cruzado** (`corpus/heldout_cross.json`, 20 ataques
  y 20 benignos), evaluado con `tools/evaluate_cross.py --heldout`: **20/20**
  ataques bloqueados en modo `inspect_cross_carrier=True` y **0/20** benignos
  bloqueados, frente a **10/20** en el modo por defecto. Confirma que el modo
  cruzado generaliza y no solo se acordaba de los 7 casos del corpus de
  desarrollo. Entra en CI con su propia guarda.
- **Procedimiento para medir con tráfico real** (`docs/trafico-real.md`): cómo
  poner Gatekeeper en modo monitor, recoger los eventos, analizarlos con
  `gatekeeper report`, decidir los ajustes y volver a medir, con el rollback
  escrito antes de activar el bloqueo. Incluye los requisitos de autorización
  (solo tráfico propio y con consentimiento) y qué se puede publicar (agregados,
  nunca el log en crudo). `tests/test_trafico_real.py` ejecuta el camino
  completo, así que el procedimiento no es papel: si deja de funcionar, falla
  el pipeline.
- **`tools/measure_rules.py`**: mide el efecto de un cambio de reglas sobre los
  cuatro corpus a la vez (desarrollo, retenido, benignos propios y negativos de
  CRS), para ver el coste (FP nuevos) junto al beneficio (detecciones nuevas).
- Detección opt-in de firmas repartidas entre ruta/query y valores textuales del
  body mediante `Config(inspect_cross_carrier=True)`. Está desactivada por
  defecto por el posible aumento de falsos positivos; se recomienda validar en
  `monitor_only`. No está incluida en las cifras de evaluación existentes.
- **Evaluación separada del modo cruzado** (`tools/evaluate_cross.py`, corpus
  `corpus/cross.json`, informe `corpus/CROSS_REPORT.md`): 7/7 ataques divididos
  bloqueados y 0/15 benignos bloqueados, con guarda en CI (`--check`).
  Se publica aparte y **no se mezcla** con las métricas del modo individual.
  Es un corpus de desarrollo, no retenido ni representativo de tráfico real.
- **Guía de inicio rápido** (`docs/inicio-rapido.md`): instalar, añadir el
  middleware y los dos `curl` que verifican que una petición normal devuelve
  200 y un ataque devuelve 403, con qué revisar si el ataque pasa.
- **Guía de despliegue por topología** (`docs/despliegue.md`): un proceso,
  varios workers, Docker/Kubernetes y proxy inverso, con la matriz de decisión
  de valores, el checklist de producción y el orden de reversión.
- **Pruebas de los límites de confianza del body y del rate limit**
  (`tests/test_limites_body_ratelimit.py`): límite exacto y excedido, body
  fragmentado, `Content-Length` ausente o mentiroso, desconexión del cliente a
  mitad del body, tipos de contenido no inspeccionados, concurrencia en el
  backend en memoria y política de fallo de Redis (fail-open y fail-closed).
- **Pruebas que verifican lo que la documentación promete**
  (`tests/test_inicio_rapido.py`, `tests/test_despliegue.py`): los códigos de
  respuesta de la guía rápida, y las afirmaciones de seguridad de la guía de
  despliegue (el límite en memoria se multiplica con los workers, el XFF se
  ignora si el peer no es de confianza, `allow_paths` exime de inspección pero
  no de rate limit).
- Comprobación en CI de que los ejemplos de la documentación se ejecutan
  (`tests/test_docs_examples.py`): bloques `python` de `README.md` y `docs/`
  válidos y ejecutables, más el ejemplo `examples/gatekeeper.yaml`.
- **Pruebas de rate limiting contra un Redis real** (`tests/test_redis_real.py`,
  13 tests) y un job de CI que levanta un Redis de verdad (`redis:7.2-alpine`).
  Comprueban lo que `fakeredis` no puede simular: que el límite es **global
  entre workers** (50 workers contra la misma IP se admiten exactamente los 10
  del límite, ni uno se cuela), que el contador **sobrevive a un reinicio** del
  proceso, que las IPs distintas tienen contadores separados, que el script Lua
  se ejecuta de verdad, que las claves expiran y que Redis caído da 503 con
  `rate_fail_open=False` y se audita con `rate_fail_open=True`. Si no hay Redis
  disponible, los tests se omiten con un motivo claro.



### Corregido
- **`gatekeeper.__version__` se quedaba desfasada al subir la versión.
  Estaba escrita a mano (`__version__ = "0.3.1"`): el wheel 0.4.0
  instalado decia `0.3.1`. Ahora se lee de los metadatos del paquete
  instalado (con `importlib.metadata`), con el `pyproject.toml` como
  respaldo cuando se importa desde el árbol de fuentes. Encontrado al
  preparar el release 0.4.0, antes de llegar a PyPI.
- **Las cabeceras de seguridad NO llegaban en las respuestas de rechazo.**
  Se añadían solo en el camino de éxito; los rechazos (403, 413, 429, 503)
  se enviaban sin pasar por el envoltorio que las añade. Es al revés de lo
  que quieres: un 403 sin `X-Frame-Options` ni HSTS es una respuesta **más
  débil** que la de 200, y el rechazo es la respuesta que ve el atacante.
  Ahora todas las respuestas del middleware llevan las cabeceras.
  Regresión en `tests/test_cabeceras_rechazo.py`.
- **Instalar Gatekeeper rompía FastAPI 0.103.x.** El mínimo de Starlette
  era `>=0.37`, pero FastAPI 0.103.x exige `starlette<0.28`: al instalar
  Gatekeeper, pip subía Starlette y FastAPI dejaba de funcionar
  (`Router.__init__() got an unexpected keyword argument 'on_startup'`).
  Medido que el middleware funciona con Starlette desde la **0.23.0**, así
  que el mínimo baja a `>=0.23`. El middleware solo usa `MutableHeaders`,
  `JSONResponse` y los tipos ASGI, estables desde hace años. La cota
  superior sigue sin ponerse, a propósito: acotar Starlette rompería
  instalaciones legítimas.
- **DoS de memoria con cuerpos pequeños (hallazgo de seguridad alto).** El
  puntero JSON que identifica el campo en la auditoría se construía
  concatenando un segmento por nivel de anidamiento: a profundidad N, cada
  puntero mide O(N) caracteres y, con N campos, el total es O(N²).

  Medido a través del middleware real: un body de **83 KiB** con 14.100
  niveles consumía **193,6 MiB** (2401× la entrada), y 10 peticiones
  simultáneas llegaban a **1,9 GiB** y 24 s de CPU. La respuesta era **200**:
  el atacante recibía una respuesta normal y el consumo era invisible.
  `max_body_size` no lo acotaba, porque 83 KiB están muy por debajo de 1 MiB:
  el problema no era el tamaño del body, sino su estructura.

  Ahora la ruta se lleva como una lista de segmentos acotada
  (`MAX_POINTER_DEPTH` 64, `MAX_POINTER_LENGTH` 256, `MAX_SEGMENT_LENGTH` 64),
  conservando el primer y el último segmento (el que nombra el usuario en
  `exclude_fields` y el campo que saltó) y marcando el corte con `…`.
  `field_excluded` compara también por el primer segmento, para que
  `exclude_fields` siga funcionando con punteros recortados.

  Resultado: **193,6 MiB → 7,8 MiB** por petición, y **1,9 GiB → 58,3 MiB**
  con 10 peticiones simultáneas. La detección no se pierde: el recorte es del
  puntero, no del texto. Regresión en `tests/test_dos_punteros_json.py`.

- **El body se guardaba dos veces en memoria.** `read_body` acumulaba los
  bytes en una lista de chunks **y** dentro de los mensajes de ASGI (que ya
  los llevan). Un body de 8 MiB ocupaba el doble de lo necesario. Ahora los
  bytes se guardan una sola vez.
- **Falso positivo sobre trafico legitimo: blogs con fecha en la ruta.** La
  regla `\d{4}/\d{2}/\d{2}/` (buscaba volcados con fecha) saltaba con
  **cualquier** ruta con fecha, incluidos los slugs de los blogs
  (`/blog/2026/01/15/titulo`): habria bloqueado articulos legitimos en
  cualquier blog. El corpus de desarrollo no lo detecto porque no tenia ni
  un caso con fecha en la ruta; lo encontro el corpus retenido. Ahora la
  ruta tiene que parecer un volcado (`backup/2024/01/15/`, `.../2024/01/15/x.sql`).
- **Las firmas nuevas se perdian en textos largos.** El pre filtro de
  familias solo se aplica a partir de 128 caracteres, asi que una firma sin
  su literal en `PREFILTER_LITERALS` funcionaba en los corpus cortos y
  **desaparecia en los largos**: el pre filtro descartaba la familia antes
  de evaluarla. Los corpus no lo detectaban porque casi todos sus payloads
  son cortos. Anadidos los literales que faltaban y una regresion que mete
  cada payload detras de 200 caracteres de relleno.
- **`...//` (tres puntos) se escapaba del path traversal.** El lookbehind
  `(?<![.\w])` impedia que `..` casara tras un punto, y asi
  `...//...//etc/passwd` pasaba. Ahora hay un patron para la variante de
  tres puntos.
- **Redis < 6 no funcionaba.** El cliente `redis-py` moderno (8.x) hace
  handshake RESP3 por defecto, y un Redis 5.x o 6.0 no lo entiende: la primera
  petición fallaba con `unknown command HELLO` y, con la política por defecto
  (`rate_fail_open=True`), **todas las peticiones pasaban sin rate limit en
  silencio**. Gatekeeper ahora fuerza RESP2 al conectar, que es lo que permite
  hablar con cualquier Redis >= 5.0 (el mínimo que promete el extra `[redis]`).
  La ventana deslizante solo usa `EVAL`/`ZADD`/`ZRANGE`, así que RESP3 no
  aportaba nada.
- **`Retry-After` devolvía un segundo de más.** Con una ventana de 60 s, la
  cabecera decía `Retry-After: 61`. Además, el backend en memoria y el script
  Lua de Redis **no coincidían** entre sí (truncaban frente a redondear hacia
  arriba), así que cambiar de backend cambiaba la respuesta. Ahora ambos
  devuelven el mismo valor, y es el correcto: los segundos que faltan para
  que la petición más antigua salga de la ventana, redondeados hacia arriba
  porque `Retry-After` es un entero de segundos.
- `examples/gatekeeper.yaml` no era YAML válido: el valor `redis_prefix:
  gatekeeper:rl:` sin comillas rompía el parser (`ScannerError`). Ahora va
  entrecomillado y el ejemplo se carga de verdad en los tests.
- `tests/test_docs_examples.py` fallaba en CI: los ejemplos de FastAPI de la
  documentación se ejecutan de verdad, pero FastAPI no estaba en el extra
  `dev` que instala el pipeline (el paquete solo depende de Starlette). FastAPI
  se añade al extra `dev` y, si no estuviera, los ejemplos que lo necesitan se
  omiten con un motivo explícito en vez de romper la suite.

## [0.3.1] - 2026-10-22

### Añadido
- **Veintidós firmas contra los misses de OWASP CRS** en dos tandas medidas. La
  detección externa sube del **21,0% (238/1135) al 34,7% (394/1135)**,
  manteniendo los falsos positivos de CRS en 4,7% (techo del gate: 5%) y cero
  falsos positivos sin documentar en el corpus propio.
  El método: se agrupan los misses por regla de origen, se identifica la
  técnica (no el caso) y **se mide cada firma antes de entrarla** —cuántas
  detecciones añade y cuántos FP cuesta en CRS y en el corpus propio—. Dos
  firmas se descartaron por medición, no por intuición.
  - SQLi: concatenación por barras seguida de palabra clave (`|| select`),
    subconsulta entre paréntesis (`( SELECT`), funciones SQL en un parámetro
    (`ABS(`, `CAST(`, `CHAR(`, `COALESCE(`), operadores JSONB de PostgreSQL
    (`::jsonb`, `<@`, `@>`), lectura de ficheros del servidor (`load_file`,
    `pg_read_file`), negaciones pegadas a la comilla (`'not like`, `' is not`),
    construcción de strings sin comillas (`CHR(`, `XMLType(`, `UNHEX(`) y
    operadores tolerantes de blindaje (`REGEXP`, `LIKE NULL`, `>>`, `<<`).
  - XSS: HTML con namespace (`<x:script xmlns:x=…>`, que evade la firma
    `<script` porque la etiqueta lleva prefijo), SVG/MathML, APIs de JS que
    ejecutan o acceden al DOM (`eval(`, `setInterval(`, `document.cookie`) y
    exfiltración por CSS (`@import 'http://…'`, `expression(`).
  - Ficheros sensibles: rutas de reconocimiento del sistema (`/sys/class`) y
    configuración de herramientas (`/.claude/`, `/.cursor/`, `/.kube/`).
- **Pre filtro de familias** (`PREFILTER_LITERALS`): antes de evaluar las 60
  regex se comprueba si el texto contiene algún literal de cada familia
  (`script`, `union`, `/etc/`, `jndi`…) con una búsqueda de subcadena en C. Si no
  lo contiene, esa familia se descarta sin ejecutar una sola regex. Medido
  sobre texto limpio: **8× más rápido** (un payload de 250 caracteres pasa de
  262 a 33 µs). Solo se aplica a partir de 128 caracteres: por debajo, las 156
  comparaciones `in` no compensan y el escaneo corto ya es rápido. El
  escenario de ataque queda en 1,04× (ni mejor ni peor) y no hay ningún
  regresión. No cambia qué se detecta: `tests/test_prefilter.py` compara el
  escaneo con y sin pre filtro sobre los 1582 valores de ambos corpus y exige
  el mismo resultado.
- **Workflow de publicación en PyPI con Trusted Publishing**
  (`.github/workflows/publicar.yml`): sin token de API en el repo. GitHub
  demuestra su identidad a PyPI con OIDC y PyPI emite un token de un solo uso,
  así que lo único que puede publicar en tu nombre es quien pueda modificar el
  repo. Dispara al publicar una release, valida antes que la versión del tag
  coincida con la de `pyproject.toml`, que el paquete importe y que la CLI
  funcione, y tiene un `dry_run` manual que valida sin publicar nada.
- **Job `audit` en CI** con `pip-audit`: audita el runtime (lo que arrastra
  Gatekeeper: starlette y sus transitivas) y el entorno de desarrollo, en venvs
  limpios para que el resultado no dependa de la imagen del runner. Una CVE en
  una dependencia transitiva ya no espera a que alguien la reporte.
- Metadata de PyPI completa en `pyproject.toml`: `Homepage`, `Documentation`,
  `Repository`, `Changelog`, `Issues` y `Funding`, más los classifiers que faltaban
  (`Development Status`, `Environment`, `Intended Audience`, `OS Independent`).
- **Python 3.13** en la matriz de CI: probarla aquí es más barato que descubrir
  que se rompió en el release de un usuario.
- **Percentiles por petición real** (p50/p95/p99/máx) en `benchmarks/latency.py`,
  en lugar de la media por ronda: la media escondía la cola, que es lo que nota
  un usuario. El escenario «completo» que la media rondaba en ~90 µs tiene un
  p95 de 123 µs y un p99 de 149 µs.
- **Comparación de dos versiones** (`--save` / `--baseline`): mide en tu máquina,
  cambia el código, mide otra vez y te dice si algún escenario empeoró más del
  margen (25 % por defecto). Es la única comparación fiable y la que se usa antes
  de abrir un PR que toca el camino caliente.
- **Packs de reglas opt-in** (`rule_packs`): `minimal`, `api`, `web`,
  `infrastructure` y `strict` agrupan las familias por la superficie que la
  app expone. Sin configurar nada se siguen evaluando las once (los packs no
  cambian el defecto); un pack desconocido es `ValueError` al arrancar, para que
  un typo no deje la app sin protección en silencio.
- **Exclusiones por campo** (`exclude_fields`): parámetros de query, cabeceras
  y punteros JSON que quedan exentos de inspección, con globs `fnmatch` (el
  puntero `/user/bio` también casa por `bio`). La detección que cruza varios
  campos se conserva: el campo exento se quita del objetivo y el resto se sigue
  vigilando.
- **CLI `gatekeeper report`**: lee el log de tráfico (el JSON del logger de
  Gatekeeper o un access log genérico), agrupa por regla, ruta y campo, y
  propone un `exclude_fields` o un `disabled_rules` listo para copiar. Salida
  `--json` para máquinas. Cierra el ciclo que `monitor_only=True` promete: medir
  los falsos positivos del tráfico real antes de bloquear.
- **Siete familias de detección** con su regla, sus límites de falso positivo
  medidos y su caso en el corpus:
  - `nosql`: operadores de inyección Mongo `$ne`, `$nin`, `$where` y `$regex`
    (login bypass y ejecución de JS). `$gt`/`$lt`/`$in` se dejan fuera a
    propósito: los usan los filtros legítimos.
  - `cmdi`: separador shell + binario (`; ls`, `| cat`, `&& whoami`, `$(id)`,
    `` `uname` ``), LOLBins de Windows (`powershell.exe`), webshells PHP
    (`;system('`, `shell_exec(`) y reverse shells (`/dev/tcp/`).
  - `ssrf`: IPs de metadata cloud (AWS/GCP/Azure/Alibaba) y esquemas de lectura
    local (`file://`, `gopher://`, `dict://`, `jar://`, `netdoc://`, `tftp://`).
    `localhost` no se bloquea: OAuth de desarrollo y webhooks locales son
    tráfico legítimo.
  - `ssti`: la aritmética canónica de plantillas (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`,
    `#{7*7}`) y el acceso a objetos peligrosos (`config`, `self`, `request`,
    `__class__`, `__subclasses__`).
  - `crlf`: response splitting e inyección de cabeceras (salto de línea seguido
    de nombre de cabecera, sea CRLF real decodificado de `%0d%0a` o literal
    `\r\n`).
  - `log4shell`: `${jndi:…}` con sus ofuscaciones (`${${::-j}ndi:`,
    `${jndi:${lower:l}…}`), JNDI sin envoltorio y la cadena de lookups que
    exfiltra secretos (`${env:AWS_SECRET…}`).
  - `proto_pollution`: `__proto__` en cualquier posición y
    `constructor.prototype`.
- **Evasiones** que antes pasaban intactas:
  - **Entidades HTML nombradas** (`&lt;script`, `javascript&colon;`) resueltas
    como sus equivalentes numéricos, por rondas de decodificación.
  - **Esquema con tab o salto de línea** (`java\tscript:alert(1)`, `java&#9;script:`):
    el navegador descarta tab/NL/CR en cualquier punto de una URL (WHATWG), así
    que el esquema sigue siendo ejecutable. Solo se aceptan contenedores, no
    espacios: `java script:` en prosa no es un esquema y no salta.
  - **Comentarios versionados de MySQL** (`/*!50000union*/`) desenvueltos a su
    contenido (`union`) en lugar de borrarse: MySQL los ejecuta, y borrar el
    contenido convertía el payload en texto invisible para el inspector.
- `docs/amenazas.md`: **modelo de amenazas** con el desglose de las once familias,
  el supuesto de atacante, los transportes inspeccionados, las fronteras de falso
  positivo de cada firma y lo que NO cubre Gatekeeper.
- Detección de **entidades HTML numéricas** en `decode()`: `&#60;script&#62;`
  y `&#106;avascript:` ya no pasan intactos; rango acotado para que `&#99999999;`
  no reviente (protegido por test).
- Normalización de **UTF-8 sobre-long**: `%c0%af` → `/` y `%c0%ae` → `.` en sus
  formas porcentual (sustituida antes de decodificar) y de caracteres
  (`%u00c0%u00af`).
- Firma de SQLi **blind boolean**: `ASCII(SUBSTRING(nombre,1,1))>64`.
- `/WEB-INF/` como ruta sensible (por especificación Java EE es innaccesible
  desde un navegador; pedirla es exploración).
- **Inspección de cabeceras** con `inspect_headers` (por defecto `user-agent`,
  `referer`, `cookie` y `x-forwarded-for`): los payloads que viajan en
  `User-Agent`/`Referer`/`Cookie` ya no pasan sin revisarse.
- `blocked_ips` acepta **CIDR e IPv6** (`10.0.0.0/8`), además de IP exacta e
  identificador literal del peer; una máscara mal escrita es `ValueError` al
  arrancar, no un bloqueo ausente en silencio.
- `trusted_proxies` y `trusted_proxy_cidrs`: cuántos hops tuyos hay en la cadena
  XFF y desde qué redes se cree su valor.
- La auditoría de ataques añade **`field`** (JSON pointer o parámetro culpable),
  **`pattern`** (la regex que disparó) y **`entry`** (la red que bloqueó la IP);
  el contenido del payload sigue sin registrarse.

### Corregido
- **Actions fijadas a SHA completo** en todos los workflows (aviso de
  SonarCloud, `Security Rating on New Code`): un tag como `actions/checkout@v7`
  es una promesa móvil —quien mantiene la action puede re-apuntarlo a otro
  commit después de tu revisión— y en el job de publicación a PyPI eso es
  especialmente-sensitive. Los SHA se resolvieron contra la API de GitHub y
  cada pin lleva su comentario `# v7`, que es lo que lee Dependabot para seguir
  ofreciendo actualizaciones: el pin no te deja atrapado en una versión vieja.
- **Herramientas de CI fijadas a versión exacta** (`build==1.6.1`,
  `twine==7.0.0`, `mypy==2.4.0`, `pip-audit==2.10.1`) y con
  `--only-binary ":all:"` para que pip no ejecute scripts de instalación de un
  paquete comprometido (avisos de SonarCloud). Verificado que cada versión
  existe y que el pipeline de build funciona con ellas.
- **`permissions` explícitos en los workflows** (aviso de CodeQL
  `actions/missing-workflow-permissions`): sin ese bloque los workflows heredan
  los permisos del repositorio, que en repos anteriores a 2023 son read-write.
  Ahora es `contents: read` en todo lo que no publica, y solo el despliegue de
  docs y la publicación en PyPI piden `write`/`id-token`, declarados en su job.
- **Dependabot abría PRs duplicadas**: había dos entradas de pip y una estaba
  anidada dentro de la otra (`/gatekeeper-v0.3/gatekeeper` y
  `/…/gatekeeper/demo`), así que notificaba lo mismo dos veces — una pedía
  `fastapi>=0.146.0` y la otra `>=0.148.0`, y competían por el merge. Se elimina
  la entrada redundante y se agrupan las actualizaciones en una sola PR.
- **[seguridad]** `X-Forwarded-For` se tomaba de izquierda a derecha
  (`ips[0]`, un valor que escribe el cliente): rotándolo se evadían el rate
  limit y `blocked_ips`. Se lee de derecha a izquierda (`ips[-trusted_proxies]`)
  y, con `trusted_proxy_cidrs`, el XFF de un peer que no es tu proxy se ignora.
- **[seguridad]** Solo se inspeccionaban bodies JSON/form: un POST
  `text/plain` o sin `content-type` pasaba sin revisarse aunque
  `await request.json()` lo parseara igual. Ahora todo content-type textual se
  inspecciona (denylist de binarios; `multipart` queda para v0.4).
- **[seguridad]** Las cabeceras no pasaban por las reglas: `User-Agent`,
  `Referer` y `Cookie` admitían payloads sin salir del middleware
  (resuelto con `inspect_headers`, arriba).
- `blocked_ips` solo hacía coincidencia exacta; con un rango de red
  (`10.0.0.0/8`) el bloqueo no existía aunque la configuración lo dijera.

### Cambiado
- El benchmark mide percentiles por petición real (p50/p95/p99) en lugar de la
  media por ronda: una media mezcla la pausa del recolector de basura con el
  trabajo real del middleware y esconde la cola de latencia.
- Corpus propio: **148/148 (100.0%)**, 0 FP sin documentar, 5 FP documentados (los
  cuatro de antes más `benign-071`, búsquedas sobre `__proto__`). El gate de CI
  sube de ≥ 90% a **100%**: cualquier regresión de detección deja CI en rojo.
- Corpus CRS: **27.1% (308/1135)** con 4.7% de FP sobre sus negativos. El gate
  de detección externa se queda en ≥ 19% (es una guarda de regresión, no una
  promesa) y el de FP en ≤ 5%.
- Corpus CRS recalibrado con las cabeceras y los bodies textuales en alcance:
  **21.0% (238/1135)** con 3.9% de FP; los excluidos bajan de 212 a 12 (solo
  binarios y cabeceras fuera de `inspect_headers`). Gate de CI: ≥ 19%.

## [0.3.0] - 2026-10-21

### Añadido
- Rate limiting en Redis (`rate_backend="redis"`): ventana deslizante atómica con
  script Lua, cliente `redis.asyncio` (no bloquea el event loop) y opción `redis_url`.
- Política de fallo del backend: `rate_fail_open` (por defecto `True`) decide si se
  sigue admitiendo o se devuelve 503 cuando Redis no responde; ambos casos se auditan.
- Corpus público de evaluación en `corpus/`: 83 payloads de ataque y 62 peticiones
  benignas, con procedencia y límites documentados.
- **Corpus externo** `corpus/crs_payloads.json`: 1379 tests de regresión de
  [OWASP CRS](https://github.com/coreruleset/coreruleset) (Apache-2.0, commit
  `30cb436`), con licencia incluida e importador `tools/import_crs.py`. Sus
  umbrales entran en `evaluate.py --check` como guarda de regresión sobre la
  línea base medida (18.8% de detección, 4.3% de FP en las familias 930/941/942).
- Tests de propiedades con **hypothesis** (`tests/test_fuzz.py`): ninguna entrada
  arbitraria revienta `scan()`, `normalize()`, `extract_strings()` ni `Config`;
  `allow_paths` nunca exime una ruta con indicios de traversal.
- Documentación con **MkDocs Material** en `docs/` (guía de uso, detección y
  medición, seguridad, API y desarrollo), con `mkdocs build --strict` en CI y
  despliegue en GitHub Pages en cada push a `main`.
- Gobernanza en la raíz del repo: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  plantillas de issues y PR, y workflows movidos a `.github/` de la raíz
  (GitHub solo ejecuta los workflows y lee las plantillas de raíz).
- Demo desplegable en `demo/`: app FastAPI de juguete con playground de
  payloads, configs para Vercel y Docker, y el GIF de una sesión real
  (`docs/assets/demo.gif`, regenerable con `demo/make_gif.py`).
- `ARTICLE.md`: artículo listo para publicar (dev.to / blog personal) sobre la
  medición honesta con dos corpus y el ReDoS cuadrático de v0.3.
- `tools/evaluate.py`: mide tasa de detección y falsos positivos; `--check` sirve de
  umbral en CI y `--write-report` genera `corpus/REPORT.md`.
- `benchmarks/latency.py`: latencia añadida por petición, por escenario.
- Regla `sensitive_files` (`/etc/shadow`, `/proc/self/environ`, `win.ini`,
  `.ssh/id_rsa`, `.env`), ampliada en esta versión a `.ssh/*`, `.aws/credentials`,
  `.docker/secrets`, `.git/config` y `/etc/subuid`.
- Comprobación de tipos estricta con mypy y marcador `py.typed` (PEP 561).

### Cambiado
- Reglas `sqli` ampliadas con firmas genéricas: sondeo de columnas (`ORDER BY 10`),
  subconsultas (`EXISTS(SELECT`), time-based de SQL Server/PostgreSQL
  (`WAITFOR DELAY`, `pg_sleep`), error-based (`EXTRACTVALUE`, `UPDATEXML`,
  `CONVERT(int`), consultas apiladas con `SELECT/INSERT/UPDATE/EXEC` y `xp_cmdshell`,
  tautología canónica (`?a=1=1`) y con literales (`or 'a'='a'`).
- `decode()` entiende los escapes Unicode de IIS `%uXXXX` (mayúsculas o no) y
  `normalize()` aplica NFKC con un segundo pase de decodificación: `＜script` y
  `％Ｕ００２７` se convierten antes de evaluar.
- `normalize()` elimina los comentarios SQL de ofuscación (`/**/`) antes de evaluar.
- XSS: handlers de evento sin etiqueta delante (`"onmouseover=`, ` onload=`).
- `path_traversal` exige frontera de segmento: `foo../bar` es un nombre de fichero,
  no un salto de directorio.
- El límite de `benchmark()` se restaura (se había perdido en v0.2).

### Corregido
- 6 falsos negativos y 4 falsos positivos detectados con el nuevo corpus y corregidos.
- **ReDoS cuadrático** en las reglas de SQLi: dos cuantificadores de blancos
  adyacentes (`\s*[(']?\s*`) hacían O(n²) — `or` + 80.000 espacios tardaba 118 s.
  Todos los cuantificadores acotados (`\s{0,16}`), ahora lineal: <1 s con
  entradas de 1M de caracteres. Encontrado por la batería de rendimiento nueva.

### Conocido
- Falsos positivos y negativos documentados en `corpus/README.md`. No se ocultan:
  son límites aceptados y medibles.
- Sobre el corpus externo de CRS: los 8 FP son texto legítimo que cita vectores de
  inyección (sesgo inevitable de un WAF heurístico) y los misses restantes son
  obfuscación sin firma genérica; se listan completos en `corpus/REPORT.md`.

## [0.2.0] - 2026-10-21

### Añadido
- Inspección del body `application/json` y `application/x-www-form-urlencoded`
  (claves y valores, a cualquier profundidad) con `max_body_size` → 413.
- Reglas personalizadas (`custom_rules`) y configuración por YAML (`Config.from_yaml`).
- `allow_paths` con globs, resistente a traversal y codificación residual.

### Corregido
- ReDoS en la regla de XSS: cuantificadores acotados.
- Fuga de memoria en el rate limiter: se limpian las IPs inactivas.

## [0.1.0] - 2026-10-21

### Añadido
- Rate limiting en memoria con ventana deslizante y `Retry-After`.
- Cabeceras de seguridad por defecto (no pisa las de la app).
- Reglas `sqli`, `xss` y `path_traversal` sobre ruta y query string.
- Modo `monitor_only`, lista de IPs bloqueadas y auditoría en JSON.
