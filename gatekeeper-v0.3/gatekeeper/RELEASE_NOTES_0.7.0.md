# Gatekeeper 0.7.0

## Qué es

Convierte la detección en algo que **mide** en vez de suponer, y publica el
corpus con el que lo mide.

La Fase 3 cierra **cuatro falsos negativos** (vectores reales que no se
detectaban), **seis falsos positivos** (texto normal que un operador recibe
cada día) y añade **100 peticiones legítimas nuevas** en español e inglés:

| | Antes | Ahora |
|---|---:|---:|
| Vectores que no se detectaban (FN) | 4 abiertos | **0** |
| Falsos positivos de prosa | 6 abiertos | **2** (documentados) |
| Peticiones legítimas en el corpus | 171 | **271** |
| Corpus retenido (se mide, no se ajusta) | 109 + 90 | **109 + 140** |
| Corpus propio: FP sin documentar | 0 | **0** |

## Qué cambia

### 1 · Cuatro vectores que pasaban sin que el WAF se enterara

Cada uno se reprodujo contra el código **antes** de tocar nada
(`.audit/f3_probe.py`, 15 casos), y cada uno tiene su test de regresión.

- **Tautología con literales vacíos** (`' or ''=`). La firma exigía un literal
  con contenido (`['\"]\w+['\"]`), así que el atacante que cierra la comilla
  del valor y mete la comparación con cadena vacía se colaba.
- **Booleano ciego con la función de recorte primero**
  (`substring(version(),1,1)=5`). La firma solo veía la forma invertida
  (`ascii(substring(...))`).
- **SSRF con la IP de metadata en decimal, hex y octal**
  (`http://2852039166/`, `http://0xa9fea9fe/`, `http://0252.0376.0252.0376/`).
  El parser de URL del navegador las resuelve igual que `169.254.169.254`.
- **Comandos separados por un salto de línea** (`foo\nrm -rf /`). En shell, un
  salto de línea es un separador tan real como `;`.

### 2 · El `+` de un query string se perdía al decodificar

`decode()` traducía `+` a espacio en **cada** ronda, así que `sleep(10%2B6)`
llegaba a las reglas como `sleep(10 6)` y **no se detectaba**: el `+` (el
operador de MySQL) se comía el decodificador.

Ahora la traducción de `+` a espacio se aplica **una sola vez**, en la primera
ronda: el `+` que el servidor entrega al usuario se entrega también a
Gatekeeper.

### 3 · `<script>` en prosa ya no bloquea

«En el manual pone: `<script>` para incrustar código» es documentación, no un
ataque. Ahora `<script>` solo salta con **atributos**, con **etiqueta de
cierre**, o seguido de **algo que no puede ser prosa** (un token de código, un
carácter que no puede empezar una frase, o el final del valor).

Los XSS reales siguen bloqueados: `<script>alert(1)</script>`,
`<SCRIPT SRC=…>`, `<svg><script>…</script></svg>`, `%3Cscript%3E…`,
`</title><script>…</script>`.

### 4 · `sleep` exige un número

`sleep(8 hours)` es texto, no una función SQL. Ahora `sleep` exige un
argumento **numérico**, y admite las tres formas de blindaje reales: el número
solo (`sleep(5)`), la conversión (`sleep(20.to_i)`) y la operación aritmética
(`sleep(20 div 3)`).

### 5 · Cuatro firmas más dejan de saltar con la prosa

Cada una se endureció **midiendo** cuántos ataques dependían *solo* de ella
(`.audit/f3_ajustes.py`), y después se comparó el corpus externo de OWASP CRS
payload a payload: **0 detecciones perdidas, 0 ganadas**.

| Firma | Qué no bloquea ahora | Por qué |
|---|---|---|
| `union all` | `union all` sin contexto de consulta detrás | «union all» en un tutorial de SQL es de las búsquedas más frecuentes |
| `WAITFOR DELAY` | `waitfor delay` sin comilla ni dígito detrás | La forma real (`WAITFOR DELAY '0:0:5'`) siempre lleva el literal |
| `like null` | `like null` en mitad de una frase | La forma de ataque cierra el payload (`1 LIKE NULL--`) |
| NoSQL (`$ne`, `$nin`, `$where`, `$regex`, `$or`, `$exists`) | El operador suelto en un texto | El ataque va dentro de un objeto JSON o de un parámetro (`{"$ne": ""}`, `user[$ne]=x`) |

### 6 · 100 peticiones legítimas nuevas, en español y en inglés

Este es el fondo del asunto: un corpus de tráfico legítimo **publicado**, que
es lo que permite afirmar el «0 falsos positivos sin documentar» con datos y
no con buenas intenciones.

- **50 en el corpus de desarrollo** (`corpus/benign.json`, `benign-082`…
  `benign-131`): es el que se puede ajustar. Los 10 que saltaban motivaron las
  cuatro firmas endurecidas de arriba.
- **50 en el corpus retenido** (`corpus/heldout_benign.json`, `hob-091`…
  `hob-140`): escritos **después** de congelar las firmas y medidos **una vez**.
  Un falso positivo ahí no se corrige con una firma escrita para él: se
  documenta. De los tres que saltaron, dos los resolvieron los ajustes que
  motivó el corpus de desarrollo y el tercero (la IP de metadata citada en una
  explicación) sigue abierto y documentado.

Los cuatro límites que quedan abiertos están **publicados** con su motivo:
`{{config}}` (vector de Jinja2), `${env:…}`/`${jndi}` (familia Log4Shell), el
salto de línea seguido de cabecera (CRLF) y la IP de metadata citada en una
explicación (SSRF).

## Migración desde 0.6.0

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni
parámetros nuevos. `Config`, `GatekeeperMiddleware`, `custom_rules`,
`disabled_rules`, `rule_packs` y `exclude_fields` funcionan igual.

**Los cambios de comportamiento que sí pueden afectar** (todos verificados con
los cuatro corpus, y con el externo de OWASP CRS payload a payload):

1. **Un valor con `<script>` en prosa ya no se bloquea.** Si tu aplicación
   aceptaba (o rechazaba) tráfico con `<script>` citado en un texto, eso
   cambia. Los XSS reales siguen bloqueados.
2. **`sleep` con unidades ya no se bloquea.** `sleep(8 hours)` en un valor ya
   no dispara la regla `sqli`; `sleep(5)`, `sleep(20.to_i)` y `sleep(20 div 3)`
   sí.
3. **`union all`, `waitfor delay`, `like null` y los operadores NoSQL** exigen
   ahora su contexto (consulta, literal de tiempo, cierre del payload u objeto
   JSON). Los vectores que dependían **solo** de esas firmas se han medido uno
   a uno: **no se pierde ninguna detección**.
4. **El `+` de un query string llega a las reglas como `+`** y no como
   espacio. Es una corrección, pero cambia qué se ve en un valor con `%2B`.

```bash
pip install --upgrade gatekeeper-asgi
```

## Detección

Verificado con los cuatro corpus, antes y después:

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | 159/159 (100 %) | 0 no documentados (8 documentados) |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados (5 documentados) |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

El corpus retenido **no baja**: sigue en 94,5 %, que es la medida de
generalización (el corpus de desarrollo es la promesa, el retenido es la
medida). Las cifras del CRS son **exactamente las mismas** que en 0.6.0:
comparados payload a payload sobre los 1.379 tests importados, **0 perdidos y
0 ganados**.

## Qué NO cubre

- El **contenido** de los ficheros adjuntos (sí los nombres).
- Los **frames** de un WebSocket (sí el handshake).
- Binarios que no son JSON (imagen, PDF, zip…).
- El tráfico entre query y body si `inspect_cross_carrier=False`.
- Autenticación, autorización y consultas parametrizadas: eso va en tu app.
- El regex **dentro** de un mismo texto (un `timeout` de Python no puede
  interrumpir un regex que ya está corriendo): lo que se controla es el
  **número de campos**, no el coste de una única evaluación.
- Los cuatro límites de arriba (`{{config}}`, `${env:…}`/`${jndi}`, CRLF con
  cabecera citada, IP de metadata citada).

## Compatibilidad

Sin cambios: Python 3.10–3.14, Starlette 0.23.0–1.10.0, FastAPI
0.103.2–0.162.0, uvicorn/hypercorn/daphne y Redis 5.0/7.2. La matriz completa
y **medida** está en [docs/compatibilidad.md](docs/compatibilidad.md).

## Instalación

```bash
pip install gatekeeper-asgi          # núcleo
pip install "gatekeeper-asgi[yaml]"   # + configuracion desde YAML
pip install "gatekeeper-asgi[redis]"  # + rate limit distribuido
```

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

El DoS de disponibilidad de la 0.4.0 (corregido en la 0.4.1) está en
[SECURITY.md](SECURITY.md), en la sección «Vulnerabilidades corregidas».
