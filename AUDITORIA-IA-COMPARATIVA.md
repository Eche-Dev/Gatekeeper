# Transparencia de IA y Auditoría Multi-Modelo de Seguridad — Gatekeeper (`gatekeeper-asgi` 0.9.0)

Este documento certifica de forma transparente qué modelos de Inteligencia Artificial han intervenido en la concepción, construcción, documentación y **auditoría ofensiva/defensiva (pentesting en entorno aislado)** de **Gatekeeper** (`gatekeeper-asgi` `0.9.0`), qué vulnerabilidades reales consiguió demostrar cada uno, qué puntuación otorgó y cuál fue su veredicto de recomendación.

> **Filosofía del proyecto ([AGENTS.md](AGENTS.md))**: *"Verificar, no creer. Un informe, una auditoría o una hipótesis no son evidencia. Antes de escribir una línea de código: reproduce el caso contra el código real."*

---

## 1. Mapa de Modelos de IA Utilizados en el Ciclo de Vida del Proyecto

El desarrollo de **Gatekeeper** ha seguido un modelo de ingeniería asistida y verificada por múltiples IAs especializadas, separando estrictamente quién genera código de quién lo audita y ataca:

| Modelo de IA | Rol en el Proyecto | Etapa / Contribución Principal |
| :--- | :--- | :--- |
| **ChatGPT** | **Concepción, Fase 0 y Revisión Arquitectónica** | De donde nació la idea original del proyecto y se estructuró la **Fase 0** (prototipo inicial del middleware ASGI). Posteriormente utilizado como revisor documental y de diseño desde la web. |
| **MiniMax** | **Generación de Código e Implementación** | Motor principal de asistencia para la escritura e implementación de código Python del paquete (`src/gatekeeper/`), herramientas de evaluación (`tools/`) y suites de tests. |
| **Claude** | **Arquitectura de Fases (`.md`) y Auditoría Ofensiva** | Estructuración de los documentos maestros de fases ([PLAN-VERIFICADO-100.md](PLAN-VERIFICADO-100.md), [AUDITORIA-2026-10-25.md](AUDITORIA-2026-10-25.md)) y auditoría de caja blanca con ejecución de PoCs ([pocs_ia.py](.audit/PACK-REVISOR/pocs_ia.py)). |
| **Gemini** | **Pentesting y Auditoría de Código en Entorno Seguro** | Atacó el middleware en un entorno controlado (`TestClient` en memoria), buscando diferenciales de parser HTTP/multipart y evasiones del prefiltro ([pocs_gemini.py](.audit/PACK-REVISOR/pocs_gemini.py)). |
| **Cursor Composer 2.5 Fast** | **Verificación de Controles y Límites Operativos** | Ejecución independiente de la batería de regresión, cobertura, análisis estático (`bandit`, `mypy`, `ruff`) y pruebas de límites documentados ([pocs_cursor_composer.py](.audit/PACK-REVISOR/pocs_cursor_composer.py)). |
| **Argon (Antigravity)** | **Auditor Externo Experto en Ciberseguridad y Cierre del Proyecto** | Auditoría final exhaustiva línea a línea: verificó empíricamente los hallazgos de todos los modelos anteriores, descubrió **8 vulnerabilidades inéditas** ([pocs_antigravity.py](.audit/PACK-REVISOR/pocs_antigravity.py)) y trazó el plan de cierre definitivo para llevar la aplicación al **97 / 100** ([PLAN-CIERRE-97.md](PLAN-CIERRE-97.md)). |

---

## 2. Cuadro Comparativo de las Auditorías de Ciberseguridad (Versión `0.9.0`)

Todas las pruebas dinámicas se ejecutaron en un **entorno controlado y seguro** (instancias ASGI en memoria mediante `Starlette`/`FastAPI` `TestClient` y el ejecutor reproducible [.audit/PACK-REVISOR/ejecutar_pocs.py](.audit/PACK-REVISOR/ejecutar_pocs.py)), sin tráfico de red externo ni impacto sobre el sistema anfitrión.

| Modelo Auditor | Método de Prueba | Qué Consiguió / Hallazgos Reales Reproducidos | Puntuación Otorgada | ¿Lo Recomendó? | Informe y Evidencia (PoC) |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **Claude** | Caja blanca + ejecución dinámica de 6 PoCs en entorno aislado | **4 hallazgos confirmados (1 Crítico) + 1 refutado:**<ul><li>**`IA-1` (Crítico)**: Envolver cualquier payload en `/*...*/` evade 7 de las 11 familias (`xss`, `ssti`, `log4shell`, `cmdi`, `crlf`, `path_traversal`, `ssrf`) porque `rules.normalize()` borraba comentarios SQL antes de todas las familias.</li><li>**`IA-2` (Medio)**: `BODY_METHODS` no inspecciona cuerpos enviados en `GET`, `HEAD` u `OPTIONS`.</li><li>**`IA-3` (Bajo)**: `Content-Encoding: gzip` no se descomprime.</li><li>**`IA-5` (Doc)**: El carácter Unicode `\ufdfa` expande `18x` en NFKC (`97x` pico en RAM), superando el `4x` documentado.</li><li>**`IA-4` (Refutado)**: Comprobó que IPv4 mapeada en IPv6 (`::ffff:...`) **sí** se bloquea correctamente.</li></ul> | **68 / 100** *(en v0.4.0 dio 74/100; proyecta **>85/100** al corregir `IA-1`)* | **No en producción hasta corregir `IA-1`; SÍ una vez aplicado el parche** (destacó que la ingeniería y el pipeline de verificación son de nivel *Senior*). | [SECURITY_REVIEW-IA-Claude.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude.md) · [pocs_ia.py](.audit/PACK-REVISOR/pocs_ia.py) |
| **Gemini** | Caja blanca + ejecución dinámica de 6 PoCs y suite completa (2.938 tests) | **2 hallazgos de severidad Alta (4 PoCs en fallo) que ningún otro modelo previo vio:**<ul><li>**`H-1` (Alto)**: Diferencial de parser en `multipart/form-data` con `boundary` duplicado (`boundary=dummy; boundary=real`): Gatekeeper lee el primero y Starlette/FastAPI lee el último (`200 OK`).</li><li>**`H-2A/B/C` (Alto)**: `PREFILTER_LITERALS` (activo cuando `len >= 128`) omitía literales de firmas en `sensitive_files`, `sqli` y `xss` (`<style>`), dejando pasar ataques con relleno $\ge 128$ bytes.</li><li>Verificó que XFF anti-spoofing, presupuestos `413` y ReDoS resisten correctamente.</li></ul> | **86 / 100** *(proyecta **94 / 100** tras parchear `H-1` y `H-2`)* | **SÍ, absolutamente recomendable** como capa de defensa en profundidad, parcheando antes `H-1` y `H-2` y arrancando con `monitor_only=True`. | [SECURITY_REVIEW-IA-Gemini.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Gemini.md) · [pocs_gemini.py](.audit/PACK-REVISOR/pocs_gemini.py) |
| **Cursor Composer 2.5 Fast** | Ejecución de 15 PoCs base + 6 PoCs propios + `pytest`, `bandit` y corpus CRS/heldout | **0 vulnerabilidades nuevas encontradas (validó 21 controles defensivos):**<ul><li>Confirmó resistencia de punteros JSON (regresión H-1), operador `+` literal en body, logs sin valores y acotados a $\le 256$ chars, fail-closed `413` en `max_fields` y `max_body_size`, y doble URL-encoding.</li><li>Documentó 2 notas operativas (`INFO-1` contenido de fichero multipart y `INFO-2` `monitor_only`).</li><li>*Limitación*: No profundizó en `rules.normalize()` ni en `_multipart_boundary()`.</li></ul> | **86 / 100** *(Calidad de software: 86/100; Utilidad dev: 82/100; vs ModSecurity completo: 48/100)* | **SÍ**, muy recomendable en APIs FastAPI/Starlette como primera línea de defensa en profundidad. | [SECURITY_REVIEW-IA-Cursor.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Cursor.md) · [pocs_cursor_composer.py](.audit/PACK-REVISOR/pocs_cursor_composer.py) |
| **ChatGPT (Web)** | Revisión estática de arquitectura, métricas de corpus y diseño (sin terminal local) | **0 PoCs ejecutados; observaciones de diseño arquitectónico:**<ul><li>Señaló que el presupuesto de tiempo `max_inspection_time_ms` es **cooperativo** (no interrumpe una operación bloqueante a mitad de camino).</li><li>Advirtió que el analizador estático de ReDoS para `custom_rules` debía probarse frente a estructuras no reconocidas.</li><li>Valoró positivamente la publicación honesta de las 3 métricas separadas (100 % propio, 94,5 % retenido, 41,0 % CRS).</li></ul> | **76 / 100** *(Ingeniería: 84/100; Detección generalizable: 62/100)* | **SÍ para desarrollo, staging y aprendizaje**; pidió completar la verificación dinámica antes de certificarlo para producción. | [.audit/Evaluacion-ia/chatgpt.md](.audit/Evaluacion-ia/chatgpt.md) |
| **Argon (Antigravity)** *(Auditor Externo y Cierre)* | Auditoría exhaustiva del 100 % del código fuente + verificación de las 4 IAs previas + 8 PoCs inéditos en entorno aislado | **Verificó las 4 auditorías previas y descubrió 8 vulnerabilidades nuevas (`AG-1` a `AG-8`):**<ul><li>**`AG-1` (Alto)**: Los nombres de campo (`name="..."`) en `multipart/form-data` nunca se inspeccionaban pese a prometerse en la documentación.</li><li>**`AG-2` (Alto)**: Un `;` entrecomillado en `Content-Type` (`dummy="a; boundary=fake"; boundary=real`) engaña a `_multipart_boundary` y evade el WAF.</li><li>**`AG-3` (Medio)**: `inspect_cross_carrier=True` olvidaba incluir los campos de texto de `multipart/form-data` en `cross_values`.</li><li>**`AG-4` (Alto)**: Un body JSON codificado en **UTF-16/UTF-32** enviado como `application/octet-stream` evade `looks_like_json` pero `await request.json()` lo decodifica y ejecuta.</li><li>**`AG-5` (Medio)**: `exclude_fields=["bio"]` desactivaba subárboles JSON enteros (`/bio/*`), parámetros query con `/` (`?evil/bio=`) y compilaba globs distinguiendo mayúsculas.</li><li>**`AG-6` (Alto)**: `_header(scope, name)` leía solo la 1.ª tupla en ASGI, ignorando segundas cabeceras `Cookie` (HTTP/2) y permitiendo falsificar `X-Forwarded-For` detrás de proxies que añaden una 2.ª tupla.</li><li>**`AG-7` (Bajo)**: `analizar_redos` no detectaba clases de caracteres solapadas `(\w\|\d)+$` ni grupos con flags en línea `(?:(?i:(a+))+)$`.</li><li>**`AG-8` (Alto)**: Demostró por qué `test_prefilter.py` no cazó `H-2` (los payloads de `attacks.json` medían $<128$ chars y no activaban el prefiltro) y midió exactamente **7 caídas en `attacks.json`** y **59 en `crs_payloads.json`**.</li></ul> | **78 / 100** *(en el estado auditado)* $\rightarrow$ **97 / 100** *(tras ejecutar el Plan de Cierre)* | **SÍ (Nivel Profesional Senior).** Tras aplicar las 7 correcciones quirúrgicas del Plan de Cierre, el código alcanza **97 / 100** y supera estándares de auditoría AppSec industrial. | [SECURITY_REVIEW-IA-Antigravity.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md) · [pocs_antigravity.py](.audit/PACK-REVISOR/pocs_antigravity.py) |

---

## 3. Resumen de lo ejecutado con Argon para llevar Gatekeeper al 97 / 100 (Completado ✅)

El salto de **78 / 100 a 97 / 100** se ha completado aplicando **7 correcciones quirúrgicas verificadas con tests** (todas marcadas `[x]` en [PLAN-CIERRE-97.md](PLAN-CIERRE-97.md)), logrando **`38 PASA · 0 FALLA · 3 INFO`** en `.audit/PACK-REVISOR/ejecutar_pocs.py`:

1. **Aislar `_strip_sql_comments` en `src/gatekeeper/rules.py` (`IA-1`)**:
   - Dejar de borrar `/*...*/` en `normalize()` globalmente; generar la variante sin comentarios SQL como variante adicional de escaneo para que `sqli` siga detectando `1'/**/OR/**/1=1` mientras el resto de familias (`xss`, `ssti`, `cmdi`, `log4shell`, `crlf`, `path_traversal`, `ssrf`) ven también el texto con `/*...*/` intacto.
2. **Sincronizar `PREFILTER_LITERALS` y blindar `tests/test_prefilter.py` (`H-2` / `AG-8`)**:
   - Incluir todos los literales obligatorios en `sensitive_files`, `sqli` y `xss`, y exigir en `test_prefilter.py` paridad `use_prefilter=True == use_prefilter=False` con prefijo de $\ge 150$ bytes en `attacks.json`, `heldout_attacks.json` y `crs_payloads.json`.
3. **Blindar el parser de `multipart/form-data` en `src/gatekeeper/body.py` y `middleware.py` (`H-1`, `AG-1`, `AG-2`, `AG-3`)**:
   - Usar `_split_params()` en `_multipart_boundary()` y tomar el último `boundary` (o rechazar si hay múltiples `boundary` distintos).
   - Emitir `(nombre, nombre)` en `extract_multipart()` para escanear los nombres de campo (`name="..."`).
   - Alimentar `cross_values` también en partes de texto multipart cuando `inspect_cross_carrier=True`.
4. **Detectar JSON en UTF-16 y UTF-32 dentro de `looks_like_json` (`AG-4`)**:
   - Reconocer BOMs (`\xff\xfe`, `\xfe\xff`, `\xff\xfe\x00\x00`, `\x00\x00\xfe\xff`) y secuencias iniciales `{`/`[` con bytes nulos intercalados de UTF-16/32 cuando el `Content-Type` es `application/octet-stream` o está ausente.
5. **Unificar cabeceras repetidas en ASGI e inspeccionar cuerpos presentes en cualquier método (`AG-6`, `IA-2`)**:
   - Hacer que `_header(scope, name)` combine todas las tuplas de `scope["headers"]` (`"; "` para `cookie` según RFC 9113, `", "` para `x-forwarded-for` y demás cabeceras según RFC 9110).
   - Inspeccionar el cuerpo en `GET`/`HEAD`/`OPTIONS` siempre que el cliente envíe bytes reales en el body (`Content-Length > 0` o `Transfer-Encoding`).
6. **Corregir `Config.field_excluded` y el analizador estático ReDoS (`AG-5`, `AG-7`)**:
   - No excluir subárboles JSON enteros cuando se excluye un nombre simple (`eliminar segmentos[0]`), no partir por `/` nombres de parámetros que no sean punteros JSON, y compilar `_exclude_globs` con `re.IGNORECASE`.
   - En `src/gatekeeper/redos.py`, reconocer grupos con flags `(?i:...)` y detectar intersección entre clases de caracteres (`\w`, `\d`, rangos `[a-z]`) en alternativas cuantificadas.
7. **Verificación final 100 % en verde**:
   - Pasar las **41 comprobaciones** de `.audit/PACK-REVISOR/ejecutar_pocs.py` (`0 FALLA`), los **2.938+ tests** de `pytest` con cobertura $>98\%$, `evaluate.py --check`, `evaluate_heldout.py --check`, `check_docs.py` y `mkdocs build --strict`.

---

## 4. Cómo reproducir todas las auditorías en un solo comando

Cualquier desarrollador o auditor puede verificar las 41 pruebas de concepto de los distintos modelos en menos de 15 segundos ejecutando:

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py
```

Los informes individuales completos de cada modelo se encuentran archivados y formateados en `.audit/PACK-REVISOR/`:
- **Argon (Antigravity)**: [.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md)
- **Claude**: [.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude.md)
- **Gemini**: [.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Gemini.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Gemini.md)
- **Cursor Composer**: [.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Cursor.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Cursor.md)
- **Registro consolidado de sesiones**: [.audit/PACK-REVISOR/HISTORIAL-SESIONES-IA.md](.audit/PACK-REVISOR/HISTORIAL-SESIONES-IA.md)
