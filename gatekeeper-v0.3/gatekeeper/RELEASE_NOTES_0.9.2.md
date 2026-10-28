# Gatekeeper 0.9.2 — Cierre Definitivo de Re-Auditoría Adversarial (`PLAN-CIERRE-100` · 97 / 100)

Esta versión cierra la **segunda ronda adversarial (re-auditoría final de Claude contra `0.9.1`)** documentada en [`AUDITORIA-IA-COMPARATIVA.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/AUDITORIA-IA-COMPARATIVA.md), [`.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-FINAL.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-FINAL.md) y [`PLAN-CIERRE-100.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/PLAN-CIERRE-100.md), llevando las 45 pruebas de concepto de `.audit/PACK-REVISOR/ejecutar_pocs.py` a **`42 PASA · 0 FALLA · 3 INFO`** (`0/13` binarios pendientes en `IA-6`).

| Métrica | Antes (`0.9.1`) | Ahora (`0.9.2`) |
| :--- | :---: | :---: |
| Batería completa de PoCs (`ejecutar_pocs.py` + `pocs_ia_final.py`) | `40 PASA · 2 FALLA · 3 INFO` | **`42 PASA · 0 FALLA · 3 INFO`** |
| Observación `IA-6` (binarios comunes tras separador en `cmdi`) | `12/13 no detectados` | **`0/13 no detectados` (`0` FP nuevos)** |
| Detección en corpus propio (`attacks.json`, corto y $\ge 128$ B) | `160 / 160` (`100 %`, `0 %` FP) | **`160 / 160` (`100 %`, `0 %` FP)** |
| Detección en corpus retenido (`heldout_attacks.json`) | `103 / 109` (`94,5 %`, `0 %` FP) | **`103 / 109` (`94,5 %`, `0 %` FP)** |
| Detección en OWASP CRS (`crs_payloads.json`) | `465 / 1135` (`41,0 %`, `4,7 %` FP) | **`465 / 1135` (`41,0 %`, `4,7 %` FP)** |
| Campaña de fuzzing diferencial del prefiltro (`test_prefilter.py`) | `2.088` textos | **`2.088` textos + `20.000` muestras (`0` divergencias)** |
| Patrones catastróficos validados en `redos.py` | `12` | **`21`** |
| Puntuación final de auditoría AppSec (techo técnico por IA) | `86 / 100` | **`97 / 100`** |

## Qué se ha corregido en 0.9.2

1. **`NUEVO-1` — Segunda lectura sin quitar `/*...*/` extendida también a `sqli` (`src/gatekeeper/rules.py`)**:
   - `_scan_detailed` ejecuta primero la vista con `_strip_sql_comments` (para detectar `1'/**/OR/**/1=1` y `/*!50000...*/`) y, si no hay coincidencia, evalúa la vista con `/*...*/` intactos en **las 11 familias incluida `sqli`**, bloqueando payloads SQLi envueltos por completo en un comentario (`/*x' UNION SELECT password FROM users -- */`, comentarios anidados `/*/*...*/*/`, combinaciones con `+` literal y ataques cross-carrier).
   - Además, los comentarios SQL versionados cerrados (`/*!50000...*/`) de más de 200 caracteres se desenvuelven igualmente en tiempo $O(n)$, y `RULES["xss"]` usa `(?<!/)\bdocument\s{0,8}\.` para no marcar como XSS segmentos de ruta URL como `/manual/document.cookie` (`crs-941180-t7-s1`).
2. **`NUEVO-2` — Descompresión `Content-Encoding: gzip / deflate` multicapa (`src/gatekeeper/middleware.py`)**:
   - El middleware descomprime hasta **3 capas anidadas** (`gzip(gzip(...))`) mientras el resultado empiece por cabecera mágica gzip (`\x1f\x8b`), aplicando en cada capa el mismo tope `max_body_size` y devolviendo `413 Payload Too Large` ante bombas de descompresión de una o varias capas.
3. **`IA-6` — Ampliación de la lista cerrada de binarios en `cmdi` (`src/gatekeeper/rules.py`)**:
   - Añadidos `touch`, `echo`, `tee`, `awk`, `find`, `xargs`, `nohup`, `timeout`, `busybox`, `php`, `node`, `telnet` y `ssh` tras separador de comando (`;`, `|`, `&&`, `$(`, `` ` ``) tanto en `RULES["cmdi"]` como en `PREFILTER_LITERALS["cmdi"]`, con **0 falsos positivos nuevos** en los tres corpus.
4. **Fase 5 — Endurecimiento de `redos.py` y campaña de 20.000 muestras en `test_prefilter.py`**:
   - `analizar_redos` reconoce prefijos sintácticos de grupo (`?:`, `?i:`, `?P<nombre>`), cuantificadores perezosos (`+?`, `*?`, `{m,}?`) y rangos internos variables (`{1,2}`, `{1,3}`) dentro de grupos repetidos sin cota, validado frente a **21 patrones catastróficos**.

## Migración desde 0.9.1

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni parámetros obligatorios nuevos. La actualización desde `0.9.1` (o `0.9.0`) es directa:

```bash
pip install -U gatekeeper-asgi
```

**Qué tener en cuenta al actualizar:**

1. **Payloads SQLi dentro de `/*...*/` y cuerpos con doble/triple `gzip`**: ahora son inspeccionados y bloqueados con `403` (o `413` si cualquier capa descomprimida supera `max_body_size`).
2. **Nuevos binarios tras separador en `cmdi`**: valores que contengan `; echo`, `| tee`, `; awk`, `; find`, `; xargs`, `; php`, `; node`, `; ssh`, etc. ahora se detectan en la familia `cmdi`. Si un campo legítimo recibe fragmentos de scripts shell, exclúyelo con `exclude_fields`.
