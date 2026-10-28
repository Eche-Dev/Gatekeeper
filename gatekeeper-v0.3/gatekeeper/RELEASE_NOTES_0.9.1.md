# Gatekeeper 0.9.1 — Cierre de Auditoría de Ciberseguridad Multi-IA (97 / 100)

Esta versión cierra el ciclo completo de **auditoría ofensiva/defensiva multi-modelo** ([`AUDITORIA-IA-COMPARATIVA.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/AUDITORIA-IA-COMPARATIVA.md), [`PLAN-CIERRE-97.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/PLAN-CIERRE-97.md) y [`PLAN-CIERRE-100.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/PLAN-CIERRE-100.md)), incluyendo la segunda ronda adversarial de Claude (`pocs_ia_final.py`), con todas las pruebas de concepto reproducibles en entorno aislado (`.audit/PACK-REVISOR/ejecutar_pocs.py`).

| Métrica | Antes (`0.9.0`) | Ahora (`0.9.1`) |
| :--- | :---: | :---: |
| Batería de PoCs de seguridad (`ejecutar_pocs.py`) | `22 PASA · 16 FALLA · 3 INFO` | **`42 PASA · 0 FALLA · 3 INFO`** |
| Detección en corpus propio (`attacks.json`, con y sin relleno $\ge 128$ B) | `160 / 160` (`100 %`) | **`160 / 160` (`100 %`, `0` caídas por prefiltro)** |
| Detección en corpus retenido (`heldout_attacks.json`) | `103 / 109` (`94,5 %`, `0 %` FP) | **`103 / 109` (`94,5 %`, `0 %` FP)** |
| Detección en OWASP CRS (`crs_payloads.json`) | `465 / 1135` (`41,0 %`, `4,7 %` FP) | **`465 / 1135` (`41,0 %`, `4,7 %` FP, `0` caídas por prefiltro)** |
| Cobertura de tests (`pytest --cov=gatekeeper`) | `98,65 %` | **`98,45 %` (2.990+ tests)** |
| Puntuación de auditoría AppSec | `78 / 100` | **`97 / 100`** |

## Qué se ha corregido

1. **Doble lectura con y sin comentarios SQL en las 11 familias (`IA-1`, `NUEVO-1`)**: `_scan_detailed` evalúa primero la vista sin comentarios SQL (`uni/**/on/**/select` y `/*!50000...*/` sin tope de 200 caracteres cuando están cerrados) y después la vista con `/*...*/` intactos en las **11 familias incluida `sqli`** (bloqueando `/*x' UNION SELECT ... -- */`), manteniendo el `4,7 %` de FP en CRS.
2. **Sincronización completa de `PREFILTER_LITERALS` y fuzzing diferencial de 20.000 muestras (`H-2A/B/C`, `AG-8`)**: añadidos todos los literales obligatorios de `sensitive_files`, `sqli`, `xss` y `cmdi`, verificados con relleno $\ge 150$ bytes sobre los 2.088 textos de los tres corpus más 20.000 muestras pseudoaleatorias.
3. **Blindaje de `multipart/form-data` y modo cruzado (`H-1`, `AG-1`, `AG-2`, `AG-3`)**: `_multipart_boundary` respeta comillas (`_split_params`) y usa el último `boundary=` como Starlette/FastAPI; `extract_multipart` inspecciona también `name="..."`; e `inspect_cross_carrier=True` incluye campos de texto multipart.
4. **Sniffing de JSON UTF-16 y UTF-32 bajo `application/octet-stream` (`AG-4`)**: `looks_like_json` detecta la codificación mediante `json.detect_encoding(body)`.
5. **Cabeceras ASGI repetidas, cuerpos en `GET`/`HEAD`/`OPTIONS` y `Content-Encoding` multicapa (`AG-6`, `IA-2`, `IA-3`, `NUEVO-2`)**: `_header` combina múltiples tuplas `Cookie` y `X-Forwarded-For`; se inspeccionan cuerpos presentes en cualquier método HTTP; y se descomprimen hasta **3 capas anidadas** de `gzip`/`deflate` aplicando `max_body_size` en cada capa (`413` ante bombas simples o multicapa).
6. **Ampliación de binarios en `cmdi` (`IA-6`)**: añadidos `touch`, `echo`, `tee`, `awk`, `find`, `xargs`, `nohup`, `timeout`, `busybox`, `php`, `node`, `telnet` y `ssh` tras separador de comando (`;`, `|`, `&&`, `$(`, `` ` ``) con `0` falsos positivos nuevos (`0/13 no detectados`).
7. **Exclusión de campos y analizador estático ReDoS (`AG-5`, `AG-7`, Fase 5)**: `field_excluded` ya no desactiva subárboles JSON enteros ni parámetros query con `/`, compila globs con `re.IGNORECASE`, y `analizar_redos` detecta clases solapadas, prefijos de grupo (`?:`, `?i:`, `?P<name>`), cuantificadores perezosos (`+?`, `*?`) y rangos internos variables (`{1,2}`), validado contra 21 patrones catastróficos.

## Migración desde 0.9.0

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni parámetros obligatorios nuevos. `Config`, `GatekeeperMiddleware`, `custom_rules`, `disabled_rules`, `rule_packs` y `exclude_fields` funcionan igual.

**Qué tener en cuenta al actualizar:**

1. **`exclude_fields` para subárboles JSON**: si excluías un nombre simple (`exclude_fields=["bio"]`), ahora solo se excluye `/bio` (o un puntero recortado `/bio/…/x`), no las claves hijas de un objeto anidado `/bio/subcampo`. Si quieres excluir todo el subárbol, usa un glob explícito: `exclude_fields=["/bio/*"]`.
2. **Inspección de `name="..."` en `multipart/form-data`, cuerpos comprimidos (`gzip`/`deflate` hasta 3 capas) y nuevos binarios tras separador en `cmdi`**: si un cliente enviaba nombres de campo multipart, cuerpos comprimidos o alguno de los 13 binarios nuevos tras `;`/`|` que coincidan con una regla, ahora se inspeccionan tal como declara el modelo de amenazas.
