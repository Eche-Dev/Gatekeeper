# Gatekeeper — Plan **verificado** para llegar al 100 %

> Este documento **no sustituye** a `Gatekeeper_Auditoria_y_Plan_100.md` (el plan editorial de la comparativa de IAs), sino que lo **corrige y lo completa**: cada afirmación de los tres informes ha sido comprobada ejecutando el código, y aquí están los veredictos, los hallazgos que nadie encontró y las fases con criterios de aceptación medibles.
>
> **Fecha:** 25-10-2026 · **Base:** commit `744fbc7` · **Método:** lectura de código + ataque real contra la app ASGI + medición de coste con procesos aislados + verificación de las 13 páginas publicadas y la ficha de PyPI.

---

## 0. TL;DR para decidir

- Las **tres** auditorías aciertan en lo importante (el DoS es real) pero **se equivocan en cuatro cosas** que te harían perder tiempo si las persigues (ver §3).
- **Existe un segundo vector de DoS que ninguna IA encontró** y que **el parche no arregla**: el coste por petición escala con el **número de campos** del body (~67 µs/campo → 2,3 s por petición con 1 MiB).
- La **puntuación real es 73/100**, no 94 (Gemini), ni 82 (ChatGPT), ni 74 (Claude). El plan de abajo la lleva a **100/100** en 6 fases.
- **Fase 0 es hoy**: el DoS está publicado en PyPI sin corregir.

---

## 1. Verificación de las tres auditorías (cada afirmación, comprobada)

### 1.1 Claude — la más útil, y la que más acierta

| # | Afirmación | Veredicto | Evidencia |
|---|---|---|---|
| C-1 | DoS cuadrático en `normalize()` (`re.sub(r"/\*.*?\*/")`) | ✅ **CONFIRMADO** | `rules.py:521`. Medido: 8 KB→0,084 s · 16 KB→0,333 s · 32 KB→1,351 s · 64 KB→5,509 s · 128 KB→**23,587 s**. Duplicar el tamaño ×4 el tiempo. E2E: una POST de 64 KB → **5,5 s** y devuelve **200** |
| C-2 | "Pasan los 2.134 tests" | ⚠️ **Desfasado** | El repo tiene **2.457** (2.467 con el parche). Su cifra era de una versión anterior |
| C-3 | "1 MiB → ~20 minutos" | ✅ **CONFIRMADO** | Extrapolación: 23,587 s × 64 = **≈1.510 s (25 min)** de event loop bloqueado |
| C-4 | WebSocket sin protección ni rate limit | ✅ **CONFIRMADO** | `middleware.py:175`. 6/6 conexiones aceptadas con `rate_limit=1` |
| C-5 | `application/octet-stream` se salta | ✅ **CONFIRMADO** | `body.py:20-44`. JSON con SQLi → 200 |
| C-6 | Multipart sin inspeccionar | ✅ **CONFIRMADO** | `body.py:40`. `filename=../../etc/passwd` → 200 |
| C-7 | "JSON legítimo de 1 MiB tarda 2,2 s" | ⚠️ **Matizable** | En esta máquina: **0,81 s**. Sigue siendo caro, pero no 2,2 s |
| C-8 | Rate limiter: 300.000 IPs → 258 MB | ✅ **CONFIRMADO** | **245,8 MB** (859 bytes/IP) |
| C-9 | El log no cumple lo que promete | ✅ **CONFIRMADO, y es PEOR** | No solo la ruta: el **payload completo** llega al log (§2.1) |
| C-10 | Escape de terminal en `gatekeeper report` | ✅ **CONFIRMADO** | Reproducido en los **dos** formatos del CLI |
| C-11 | Puntero JSON roto a partir de 64 niveles | ✅ **CONFIRMADO** | `body.py:203`. Además `exclude_fields` deja de casar |
| C-12 | Claves JSON duplicadas → discrepancia | ❌ **REFUTADO** | `json.loads` y Starlette coinciden (gana la última). Solo INFO |
| C-13 | FN: `' or ''=` | ✅ **CONFIRMADO** | No se detecta |
| C-14 | FN: booleano ciego `substring(version(),1,1)=5` | ✅ **CONFIRMADO** | No se detecta |
| C-15 | FN: cmd con salto de línea | ⚠️ **PARCIAL** | `; cmd` y `\| cmd` con salto **sí** se detectan; solo falla la variante sin separador (`foo\nrm -rf /`) |
| C-16 | FN: IP decimal en SSRF | ✅ **CONFIRMADO** | `http://2130706433/` → no se detecta. También falla la hex `0x7f000001` |
| C-17 | FP: `<script>` en prosa | ✅ **CONFIRMADO** | Se detecta como `xss` |
| C-18 | FP: `1=1 in math` | ❌ **REFUTADO** | **No** se detecta. No lo persigas |
| C-19 | FP: `sleep(8 hours)` | ✅ **CONFIRMADO** | Se detecta como `sqli` |
| C-20 | Web y `SECURITY.md` desactualizadas (0.3.x, "no está en PyPI") | ✅ **CONFIRMADO** | 0.4.0 **sí** está publicado (verificado con provenance) |
| C-21 | Enlaces `corpus/` relativos rotos en PyPI | ✅ **CONFIRMADO** | En la **web publicada** sí: `/corpus/`, `/corpus/REPORT.md`, `/demo/` → **404 verificado**. En PyPI el anti-bot impide ver el 404, pero PyPI no aloja ficheros del repo |
| C-22 | Email personal expuesto | ✅ **CONFIRMADO** | Metadatos de PyPI + `docs/seguridad.md:95` |
| C-23 | Solo en español | ✅ **CONFIRMADO** | No hay README en inglés |
| C-24 | sdist de 430 KB con demo/corpus | ✅ **CONFIRMADO** | **422,9 KB**, 99 entradas: `demo/`, `corpus/`, `docs/`, `benchmarks/`, `app_servidor.py` |
| C-25 | `__init__.py` al 43 % | ✅ **CONFIRMADO** | Total **95 %** |
| C-26 | El parche arregla el DoS | ✅ **CONFIRMADO** | 128 KB: 23,587 s → **0,009 s** (×2.600). Escalado ×4 → ×2. **2.467 tests** pasan y los 3 corpus dan las mismas cifras |

### 1.2 ChatGPT — buena vista de producto, cero pruebas dinámicas

ChatGPT lo dice explícitamente (*"No he realizado pruebas de penetración"*). Su valor son las **preguntas que hace**, no sus hallazgos.

| # | Afirmación | Veredicto | Evidencia |
|---|---|---|---|
| G-1 | `custom_rules` puede introducir ReDoS | ✅ **CONFIRMADO** | `config.py:210` compila la regex sin ninguna validación. Una regla `(a+)+$` sobre 60 caracteres **no terminó en 20 s**. No hay timeout, ni límite de pasos, ni rechazo de estructuras peligrosas |
| G-2 | `max_body_size` no es un presupuesto de coste | ✅ **CONFIRMADO** | Ver §2.2: **no hay tope de número de campos** ni de longitud de valor; el coste es ~**67 µs por campo** |
| G-3 | Sin timeout de inspección por petición | ✅ **CONFIRMADO** | `Config` no expone ningún presupuesto de tiempo |
| G-4 | La cadena de confianza del proxy hay que probarla | ✅ **CONFIRMADO** (y sale un fallo) | Ver §2.3: **IPv4 mapeado en IPv6 no se bloquea** |
| G-5 | `exclude_fields` debe excluir exactamente el campo | ✅ **CONFIRMADO (bien implementado)** | Excluyendo `mensaje`, un payload en `otro` sigue bloqueando → 403. Correcto |
| G-6 | Query con valores repetidos/vacíos | ✅ **CONFIRMADO (bien implementado)** | 6/6 casos bloquean correctamente |
| G-7 | Cabeceras duplicadas | ⚠️ **PARCIAL** | Con dos `X-Forwarded-For` se usa la **primera**. No rompe, pero la política no está documentada |
| G-8 | Versiones y publicación inconsistentes | ✅ **CONFIRMADO** | `README.md:23`, `SECURITY.md:7-18`, `docs/instalacion.md:3-5` vs `RELEASE_NOTES_0.4.0.md:3` |
| G-9 | Falta una revisión independiente | ✅ **CONFIRMADO** | `SECURITY_REVIEW.md:9-14` ya lo declara; sigue siendo verdad |
| G-10 | "Puntuación 82 → 75 tras revisar" | ⚠️ **Inconsistente** | La primera tabla suma 82 y la segunda 75 con pesos distintos. Tomo **73/100** (ver §4) |

### 1.3 Gemini —UGH, mucho entusiasmo y cuatro afirmaciones sin verificar

| # | Afirmación | Veredicto | Evidencia |
|---|---|---|---|
| M-1 | "Chunked / `Content-Length` falso → el acumulador puede saturar la RAM" | ❌ **REFUTADO** | `body.py:67-69` acumula y **corta en cuanto `size > max_size`**. Probado: `Content-Length: 10485760` con 2 KB reales → **413** correcto. El límite se aplica a los bytes recibidos, no a la cabecera. **No hagas nada aquí** |
| M-2 | "Cabeceras de seguridad duplicadas si la app ya define las suyas" | ❌ **REFUTADO** | `middleware.py:341-344` usa `MutableHeaders(scope=message)` + `if key not in h`. Probado: la app define `X-Frame-Options: SAMEORIGIN` → la respuesta tiene **1 sola** cabecera con ese valor. Ya hace exactamente lo que Gemini recomienda |
| M-3 | "ReDoS por la complejidad de las regex" | ✅ **CONFIRMADO** | Y hay un caso concreto y medible (C-1) |
| M-4 | Puntuación 94/100 | ❌ **No sostenida** | Nunca ejecutó el código. Con el DoS abierto, 94 no es defendible |
| M-5 | "Redacción en PyPI: formaliza *'cruce query + body'*/* | ⚠️ **Opinión, no defecto** | El término es preciso para el dominio. No es un bug |

---

## 2. Hallazgos que **ninguna** de las tres auditorías encontró

### 2.1 🔴 El payload **completo** llega al log de auditoría

Las tres audits dicen "hay datos controlados por el atacante en el log" (Claude lo dice con más detalle). Lo que nadieNwrote es **cuánto** entra:

| Cómo llega el payload | `field` registrado | ¿Payload completo en el log? |
|---|---|---|
| form-urlencoded, en el **nombre** del parámetro | `/union select password from users` | 🔴 **SÍ** |
| JSON, en la **clave** | `/UNION SELECT password FROM users` | 🔴 **SÍ** |
| form-urlencoded, en el valor | `/q` | no |
| JSON normal | `/q` | no |
| text/plain | `` | no |

Causa: `body.py` construye el puntero como `"/" + nombre_del_parámetro`, y ese nombre **es texto del atacante**. Un body form-urlencoded sin `=` se interpreta como un parámetro cuyo *nombre* es el body entero.

**Por qué importa:** `SECURITY.md:68-71`, `docs/seguridad.md:69`, `README.md:51` y `docs/trafico-real.md:17-19` prometen que el log **nunca** lleva el payload. Esa promesa es la base jurídica que usas para mandar logs a un tercero o a un SIEM. **Hoy es falsa.** (El puntero sí está acotado a 256 chars por `MAX_POINTER_LENGTH`, así que la fuga está limitada a 256 caracteres por campo, no es infinita.)

### 2.2 🔴 Segundo vector de DoS: el coste escala con el **número de campos**, no con los bytes

**Medido end-to-end a través del middleware real** (sin `tracemalloc`, que infla las cifras):

| Campos | KiB del body | Segundos | Escala |
|---:|---:|---:|---|
| 2.500 | 55 | 0,233 | – |
| 5.000 | 111 | 0,338 | ×2,0 |
| 10.000 | 224 | 0,670 | ×2,0 |
| 20.000 | 458 | **1,339** | ×2,0 |
| 26.000 | 979 | **2,330** | – |

→ **~67 µs por campo**, lineal. Con `max_body_size` = 1 MiB (tu defecto), el peor caso es **~2,3 s de CPU por petición**. Cada campo se escanea **por separado** (`scan_detailed` por valor), así que el prefijo literal (206 literales) y las 117 regex se ejecutan 2 veces por campo (clave + valor).

**El parche NO lo arregla**: 8.000 campos → **0,406 s sin parche vs 0,404 s con parche**. Es otro problema, en otro sitio.

**Mitigación**: un presupuesto de campos por petición (p. ej. 1.000) o un escaneo conjunto del body en vez de campo a campo.

### 2.3 🟠 IPv4 mapeado en IPv6: `blocked_ips` no bloquea

```
blocked_ips={'127.0.0.1'}  +  cliente "::ffff:127.0.0.1"  ->  status 200 (esperado 403)
```

En servidores dual-stack (la mayoría hoy), la IP del peer llega como `::ffff:a.b.c.d`. Tu bloqueo por IP **no casa**, y tampoco el rate limit por IP agrupa de forma útil. Un operador que bloquee `1.2.3.4` cree que lo ha bloqueado y no lo ha.

### 2.4 🟠 `rl_backend_unavailable` no existe: el evento real es `rate_backend_error`

`middleware.py:195` emite `rate_backend_error`; el catálogo autoritativo `corpus/events.json:62` también. Pero el nombre equivocado está en **5 ficheros / 6 sitios**: `docs/api.md:103`, `docs/despliegue.md:74`, `docs/uso.md:51`, `docs/uso.md:169`, `docs/seguridad.md:43`. Solo `docs/operacion.md:18` usa el bueno.

**Consecuencia**: una alerta de on-call construida sobre el nombre documentado **nunca dispara**. Falla en silencio: lo peor que puede pasar en monitoring.

### 2.5 🟠 HSTS se envía también en `http://`

`docs/uso.md:177-179` afirma que HSTS *"solo se sirve sobre HTTPS (se omite en `http://`)"*. **Verificado empíricamente**: una petición `http://` real recibe `Strict-Transport-Security`. En `middleware.py` no hay ninguna comprobación de esquema. Un navegador que recibe HSTS por HTTP fija el origen a HTTPS → rompe el desarrollo local, justo lo que la doc dice evitar.

### 2.6 🟠 Dos patrones SQLi viven en la familia `sensitive_files`

`rules.py:246` y `:249` — `union\s+all` y `or\s+['\"]?(?:\{|\[|and|between|like|in|json)` están en `sensitive_files`, no en `sqli`.

```
'union all select 1' con only={'sqli'}           -> ('sqli', ...)
'union all select 1' con only={'sensitive_files'} -> ('sensitive_files', 'union\\s+all')
```

Con `disabled_rules=["sqli"]` **el payload sigue detectándose** y se reporta con el nombre de regla equivocado. Quien construya allowlists por nombre de regla se lleva la sorpresa. Además, `\.(?:sql|bak|old|orig|save|swp)\s*$` está **duplicado** dentro de la misma familia.

### 2.7 🟡 El ejemplo de `custom_rules` de la documentación lanza `TypeError`

`docs/amenazas.md:105-108` documenta `GatekeeperMiddleware(app, custom_rules={...})`. La firma real es `(self, app, config=None)` → **`TypeError`**. `custom_rules` es un campo de `Config`. Igual con `Config.validate()`, documentado en `docs/api.md:92` y **que no existe**.

### 2.8 🟡 No existe `AGENTS.md`

Dices que desarrollas con Open Code "según tus reglas". Esas reglas **no están en el repo**, así que no viajan con el proyecto, no las lee ninguna otra herramienta y no las ve nadie que colabore.

### 2.9 🟡 La política con cadenas XFF malformadas es implícita

6 cadenas malformadas probadas (`""`, `"   "`, `"no-es-una-ip"`, `"999.999.999.999"`, `"127.0.0.1, , 10.0.0.1"`, `"::1"`, `"127.0.0.1:8080"`): **ninguna rompe**, pero tampoco está documentado si se cae al peer o a la última IP válida.

---

## 3. Falsos leads: NO persigas esto

| Afirmación | Por qué es un falso lead |
|---|---|
| "Gemini: el acumulador del body puede saturar la RAM" | `body.py:67-69` corta la lectura al superar el límite. Probado: 413 correcto con `Content-Length` falso |
| "Gemini: las cabeceras de seguridad se duplican" | `middleware.py:341-344` comprueba `if key not in h`. Probado: 1 sola cabecera |
| "Claude: `1=1 in math` es un falso positivo" | No se detecta. No hay nada que arreglar |
| "Claude: las claves JSON duplicadas Causes discrepancia" | `json.loads` y Starlette coinciden (gana la última clave). Riesgo real solo con parsers no estándar |
| "Claude: FN de cmd con salto de línea" | Solo la variante **sin** `;`/`\|` falla. Las otras dos se detectan |
| "ChatGPT: el ejemplo de `custom_rules` es correcto" | Lanza `TypeError`. Arregla el ejemplo, no el código |
| "Comparativa: el trigger de publicación son los tags `v*`" | `publicar.yml:22-25` → `on: release: types: [published]`. Un tag solo **no** publica |
| "ChatGPT/Gemini: la nota es 82/94" | Ninguna ejecutó el código. La defendible es **73** |

---

## 4. Puntuación: de dónde sale el 73 y a dónde llega el 100

| Área | Ahora | Máximo | Por qué |
|---|---:|---:|---|
| Seguridad del propio código | 12 | 20 | DoS crítico abierto + 3 bypasses de superficie + 3 fugas/abusos |
| Calidad de detección y reglas | 15 | 20 | 6 FN y 3 FP reales; atribución de familias defectuosa |
| Tests, CI y tipado | 13 | 15 | Falta el test de complejidad temporal y el de WebSocket |
| Documentación | 9 | 15 | 6 afirmaciones falsas + web publicada obsoleta + solo español |
| Publicación y supply chain | 10 | 10 | **Impecable.** Provenance verificado en PyPI |
| Estructura y mantenibilidad | 5 | 10 | `v0.1/v0.2/v0.3` en raíz, sdist de 423 KB, sin `AGENTS.md` |
| Método de medición y honestidad | 9 | 10 | Su punto fuerte: "qué mide, no qué promete" |
| **TOTAL** | **73** | **100** | **+27 por las 6 fases de abajo** |

**Recorrido de puntos:** 73 → **79** (F0) → **84** (F1) → **90** (F2) → **93** (F3) → **96** (F4) → **98** (F5) → **100** (F6).

---

## 5. El plan por fases

### 🔴 FASE 0 — Contención · 1 día · **73 → 79**

**Objetivo:** que ningún servidor con Gatekeeper instalado pueda ser tumbado por una petición.

1. **Aplicar el parche** (verificado por mí: aplica limpio, corrige el DoS, no rompe nada):
   ```bash
   git apply fix-redos-comentarios-sql.patch
   python -m pytest -q          # 2.467 tests
   ```
2. **Añadir el test de complejidad temporal** que faltaba: para cada familia de entradas hostiles, que el tiempo crezca **linealmente** (no "que no tarde más de X"). Es el test que habría atrapado esto.
3. **Publicar 0.4.1** (tag `v0.4.1` → `publicar.yml` → Trusted Publishing).
4. **Abrir el GitHub Security Advisory** (`https://github.com/Eche-Dev/Gatekeeper/security/advisories/new`): DoS sin autenticación, red de alcance medio, impacto alto, parche disponible. Documentar que lo reportaste tú mismo y publicaste el fix.
5. **Actualizar `SECURITY.md`**: añadir una sección "Vulnerabilidades corregidas" con el advisory, la fecha y el commit.

> **Aceptación:** `git apply --check` limpio · 2.467 tests · un POST de 128 KB con `/*a` responde en **< 50 ms** · el advisory está publicado y enlazado desde el CHANGELOG.
> **Por qué +6:** elimina el único hallazgo crítico y añade el evidence trail que un revisor externo mira primero.

---

### 🟠 FASE 1 — Cerrar los bypasses de superficie · 3-5 días · **79 → 84**

**Objetivo:** que "Gatekeeper inspecciona el tráfico" sea verdad, o que el hueco esté escrito en grande.

1. **WebSocket** (`middleware.py:175`). Decide y **aplica** una política:
   - *Opción A (recomendada):* inspeccionar el handshake (query + cabeceras) y aplicar el rate limit al `websocket.connect`.
   - *Opción B (mínima):* dejarlo fuera **pero** documentarlo en `README.md`, `docs/amenazas.md`, `SECURITY.md` y en la **tabla de formatos** de `docs/deteccion.md`.
   - En cualquier caso: **añade la tabla de cobertura por protocolo** (HTTP ✅ / WebSocket ✅ o ❌) a la documentación.
2. **`application/octet-stream`** (`body.py:20-44`): *sniff* del primer byte (`{`, `[`) → si parece JSON, parsearlo e inspeccionarlo. Añade el caso al corpus.
3. **Multipart** (`body.py:40`): inspección mínima — **nombres de campo** y **`filename`** (path traversal, `../`, null bytes, longitud). Los ficheros binarios siguen sin inspeccionarse, pero los metadatos sí.
4. **Política de tipos desconocidos**: que quede explícita en `docs/deteccion.md` (una matriz: *tipo → ¿se inspecciona? → ¿se limita?*).

> **Aceptación:** WebSocket con SQLi en el handshake → 403 (o la doc dice que no); JSON como `octet-stream` → 403; multipart con `filename=../../etc/passwd` → 403; **18 controles de mi `.audit/config_probe.py` siguen en verde**; los 3 corpus sin regresión.
> **Por qué +5:** cierra la superficie que un atacante elige primero (elegir el content-type que no miras).

---

### 🟡 FASE 2 — Recursos, logs y operación · 3-4 días · **84 → 90**

**Objetivo:** que ningún atacante pueda convertir tu WAF en su vector de agotamiento, ni tu log en su canal de，我看 any.

1. **Presupuesto de campos por petición** (§2.2): tope configurable (p. ej. `max_fields=1000`); al superarlo, o se trunca (y se audita) o se rechaza con 413. **El parche no cubre esto.**
2. **Timeout de inspección por petición**: presupuesto en `Config` (p. ej. `max_inspection_ms`) con la política "fail-closed" o "fail-open" **explícita y documentada**.
3. **Coste legítimo**: bajar `max_body_size` por defecto (de 1 MiB a **256 KiB**) y documentar cómo subirlo por endpoint.
4. **Rate limiter**: tope de claves en `MemoryBackend` (con LRU y política al llegar al máximo), **agrupar IPv6 por /64** y **normalizar IPv4-mapped** (§2.3) → `::ffff:1.2.3.4` debe casar con `1.2.3.4`.
5. **Log sin payload** (§2.1): deja de meter el nombre del parámetro en `field` (usa un hash truncado o el índice) **o** cambia la promesa en la doc. **Decide una de las dos y aplícala en el mismo commit.**
6. **Sanear la salida del CLI**: `str.translate` sobre el rango C0 + ESC antes de imprimir (los dos formatos del CLI), y lo mismo al escribir el log.
7. **`custom_rules` con red de seguridad** (§1.2 G-1): documentar que se ejecutan sobre entrada no confiable + **rechazar** estructuras de alto riesgo detectable (`(a+)+`, `(a|a)+`, cuantificadores anidados) al arrancar, o ejecutar en un hilo con presupuesto. Recomiendo: **validar al arrancar + avisar** (no romper la compatibilidad).
8. **Corregir `_child_pointer`** (`body.py:203`): que añada el segmento al llegar al límite → atribución correcta y `exclude_fields` vuelve a casar.
9. **Mover los 2 patrones SQLi** de `sensitive_files` a `sqli` (`rules.py:246,249`) y borrar el duplicado.
10. **Renombrar `rl_backend_unavailable` → `rate_backend_error`** en los 5 ficheros (§2.4).
11. **HSTS condicional al esquema** (§2.5) o corregir la doc (elige una).

> **Aceptación:** 26.000 campos → < 200 ms o 413; `::ffff:127.0.0.1` bloqueado con `blocked_ips={'127.0.0.1'}`; el log **no** contiene el payload (o la doc dice la verdad); `gatekeeper report` con ESC en el log → **0 bytes ESC** en stdout; `disabled_rules=['sqli']` ya no deja pasar `union all`; el puntero JSON a 80 niveles apunta al campo real.
> **Por qué +6:** es donde están los riesgos de disponibilidad y los que rompen la promesa del producto.

---

### 🟡 FASE 3 — Detección: cerrar FN y FP · 5-7 días · **90 → 93**

**Objetivo:** subir la calidad de las reglas sin perder lo que ya funciona.

1. **Falsos negativos a cerrar** (verificados):
   - `' or ''=` (tautología con comillas vacías).
   - Booleano ciego: `substring(version(),1,1)=5` (hoy solo cubre `ascii|ord|length|char_length`).
   - SSRF: IP **decimal** (`2130706433`), **hex** (`0x7f000001`) y **octal** (`0177.0.0.1`) → normalizar con `ipaddress` antes de comparar.
   - `foo\nrm -rf /` (cmd sin separador tras salto de línea).
2. **Falsos positivos a cerrar**: `<script>` en prosa (exigir que no esté en un contexto de texto), `sleep(8 hours)` (exigir que el argumento sea un número **con** unidades de tiempo o que esté en contexto SQL).
3. **Corpus de falsos positivos en español e inglés** (~100 casos nuevos), con los FP **publicados** como haces ahora. Es tu ventaja competitiva: publícalo.
4. **Regla de regresión**: cada FN/FP nuevo entra como test antes de tocar la regex.

> **Aceptación:** los 4 FN y los 2 FP de la lista pasan a detectarse/no detectarse como corresponde; el corpus retenido **no baja** del 94,5 %; los FP nuevos del corpus no superan el umbral documentado; `tools/evaluate.py --check` en verde.
> **Por qué +3:** mejora la calidad de la detección sin tocar la arquitectura.

---

### 🔵 FASE 4 — Coherencia documental · 2-3 días · **93 → 96**

**Objetivo:** que GitHub, PyPI y la web digan **lo mismo**, y que digan la verdad.

1. **Eliminar las 4 afirmaciones de "no está en PyPI"**: `README.md:23`, `SECURITY.md:16-18`, `docs/instalacion.md:3-5`, `docs/inicio-rapido.md:6-8`. Añadir **sección "Desde PyPI"** en `docs/instalacion.md` (`pip install gatekeeper-asgi`, `[yaml]`, `[redis]`).
2. **Tabla de versiones** de `SECURITY.md:7-9`: `0.4.x` = Activa. `0.3.x` y anteriores = no publicadas.
3. **Enlaces absolutos** en el README (PyPI no sirve ficheros del repo) → apunta a `raw.githubusercontent.com` o a la web. **Y arregla los 404 de la web** (`/corpus/`, `/demo/`): o los construyes en `mkdocs` (copiando el corpus a `docs/`) o los quitas.
4. **Cuerpos de error reales**: `429` → `{"detail": "Too Many Requests"}`, `503` → `{"detail": "Service Unavailable"}` en `docs/api.md`, `docs/uso.md`, `docs/despliegue.md`.
5. **Arreglar el ejemplo de `custom_rules`** (a `Config`), **borrar `Config.validate()`**, **exportar o corregir la API pública** (`gatekeeper.scan`, `RULES`, `PACK_NAMES` no son importables: `__init__.py` solo exporta `Config` y `GatekeeperMiddleware`).
6. **Corregir la afirmación de HSTS** y la de `allow_paths` ("ni consuma rate limit" en `docs/despliegue.md:122-124`, contradicha 6 líneas después).
7. **Subir el umbral CRS de CI** a la línea base real (0,19 → **0,40**) o reescribir la frase del README que promete que el CI lo vigila.
8. **README en inglés** (o sección bilingüe) + **sacando el email personal** de la web y de los metadatos → GitHub Advisories.
9. **Higiene editorial**: *"aThird parties"*, *"functionality"*, *"consequences"*, la frase truncada de "Comparar rendimiento", *"exímino"*, `corpus/CROSS_REPORT.md` regenerado, `ROADMAP.md` y `SECURITY_REVIEW.md` al día (siguen en 0.3.1).
10. **Linter de Markdown en CI** (`vale` o `mdformat` con diccionario es) → atrapa lo anterior automáticamente para siempre.

> **Aceptación:** un script verifica que README, PyPI y docs dicen la misma versión; 0 enlaces rotos (script propio en CI); `mkdocs build --strict` en verde; el README de PyPI renderiza sin rutas locales rotas.
> **Por qué +3:** la coherencia es lo que separa "proyecto real" de "proyecto que parece real".

---

### 🔵 FASE 5 — Repo, distribución y proceso · 3-5 días · **96 → 98**

**Objetivo:** que el repo se parezca a un proyecto con 10.000 estrellas, porque es lo que quieres dentro de un año.

1. **Aplana el repo**: `src/` + `tests/` + `docs/` en la raíz; las versiones viejas, a tags. (Rompe enlaces y scripts: **hazlo antes de 1.0**.)
2. **Empaquetado**: excluye `demo/`, `corpus/`, `benchmarks/`, `docs/` y el `app_servidor.py` suelto del sdist → de **423 KB a ~60 KB**. Deja el corpus en GitHub y enlázalo.
3. **Limpia restos**: `anchor_check.py`, `link_check.py`, `PLAN-100-PUNTOS…md` sueltos en la raíz (o muévelos a `tools/`).
4. **Crea `AGENTS.md`** con las reglas con las que trabajas (las que hoy solo están en tu cabeza) + un `CONTRIBUTING.md` breve.
5. **Actualiza `__init__.py`** para bajar ese 43 % de cobertura (exporta `scan`, `scan_all`, `scan_detailed`, `RULES`, `PACK_NAMES` de forma explícita y testea el versionado).
6. **Mueve los comentarios que narran incidentes** al `CHANGELOG.md` / `SECURITY_REVIEW.md` (los que te señaló Claude y que también son ruido de lectura).
7. **Convierte `tools/metrics.py` y `compat_matrix.py` en jobs de CI** (ya están escritos y no se ejecutan).

> **Aceptación:** `pip install gatekeeper-asgi` desde un sdist nuevo tarda lo normal; el sdist < 100 KB; `import gatekeeper` expone lo que dice la doc; `AGENTS.md` existe y lo lee la herramienta.
> **Por qué +2:** mantenibilidad real, no cosmética.

---

### 🏆 FASE 6 — Validación externa · 2-4 semanas · **98 → 100**

**Objetivo:** el sello que solo puede dar alguien que no ha escrito el código.

1. **Revisión independiente** del código y de los resultados, por alguien que no haya ajustado las reglas (o por un revisor con conflicto de intereses declarado). Publica el informe.
2. **SAST/DAST en CI**: `bandit` ya está; añade `semgrep` (reglas propias), `zizmor` para GitHub Actions y `pip-audit` (ya está). Objetivo: **cero** hallazgos de severidad alta.
3. **Benchmarks reproducibles** en CI (no solo locales): p50/p95/p99, CPU y memoria, con inspección on/off, con `inspect_cross_carrier=True`, con carga grande y con Redis caído. **Umbrales en CI** que bloqueen regresiones de rendimiento.
4. **Tests diferenciales contra apps reales**: FastAPI y Starlette en varias versiones, con distintos comportamientos de parsing, para demostrar que el middleware y la app **interpretan el body igual** (o documentar dónde no).
5. **Publica el informe de revisión** en `SECURITY_REVIEW.md` con fecha, autor, alcance y conflictos de intereses.
6. **Actualiza `README.md`** con el estado real: "revisado por X el día Y" + enlace al informe.

> **Aceptación:** informe publicado; CI en verde con SAST/DAST y umbrales de rendimiento; el README dice quién revisó y cuándo.
> **Por qué +2:** con esto, tu nota de 100/100 es **defendible** frente a cualquiera que pregunte.

---

## 6. Definition of Done (el checklist de "100/100")

```
[ ]  No hay ningún DoS reproducible con una sola petición (DoS + coste por campo)
[ ]  Cada protocolo y cada content-type tiene una política EXPLÍCITA y TESTEADA
[ ]  El log NO contiene el payload, o la documentación dice la verdad
[ ]  La CLI no puede ser manipulada por bytes del atacante
[ ]  El rate limiter tiene tope de claves y normaliza IPv4/IPv6
[ ]  Custom rules no pueden colgar el proceso
[ ]  Las FN y FP conocidas están cerradas y documentadas
[ ]  README, PyPI, web y metadatos dicen la MISMA versión
[ ]  0 enlaces rotos, 0 afirmaciones técnicas falsas en la documentación
[ ]  README en inglés
[ ]  El sdist pesa < 100 KB y no lleva demo ni corpus
[ ]  Existe AGENTS.md y CONTRIBUTING.md
[ ]  Cobertura > 95 % en todos los módulos (hoy __init__.py al 43 %)
[ ]  Test de complejidad temporal por familia de entradas hostiles
[ ]  CI con SAST/DAST + umbrales de rendimiento + corpus con línea base real
[ ]  Revisión de seguridad independiente, publicada
```

---

## 7. Reglas de trabajo para las fases (para Open Code / cualquier agente)

1. **Una fase = un commit** (o dos: código + documentación). Nada de mezclar un fix de seguridad con un refactor.
2. **Antes de tocar una regla, escribe el test que falla.** El proyecto ya tiene el patrón (`tools/evaluate.py --check` + corpus).
3. **Ninguna fase termina sin los tres corpus en verde** y sin el **diff de las cifras** (detección, FP y tiempo) pegado en el PR.
4. **Si un cambio de reglas mueve el CRS, el retenido o el tiempo**, eso va en el CHANGELOG con el número antes/después.
5. **No subas la versión sin actualizar** README + SECURITY.md + docs + `corpus/events.json` + `SECURITY_REVIEW.md` en el **mismo** commit. Es el error que te，成本ó la incoherencia actual.
6. **Un hallazgo de seguridad = un test de regresión** con el nombre del advisory.

---

## 8. Lo que haría yo mañana

1. `git apply fix-redos-comentarios-sql.patch` → `pytest` → tag `v0.4.1` → publicar → **GitHub Advisory**. (Tarde en la tarde, con el advisory ya abierto, es el mejor momento: la comunidad valora mucho que el autor se adelante.)
2. Mañana: Fase 1 empezando por **WebSocket** (decide A o B en el primer commit) y **multipart** (el hueco de superficie más atacada).
3. La semana que viene: Fase 2 entera (recursos + logs + CLI), que es donde está el resto del valor y donde nadie más ha mirado.

---

*Todos los hallazgos de este documento están reproducidos con los scripts de `.audit/` (ver `AUDITORIA-2026-10-25.md`). Los tiempos son de esta máquina (Python 3.14.8, Windows); tu CI puede dar otros números, pero las relaciones (×4 por duplicación, ×2 campos) se mantienen.*
