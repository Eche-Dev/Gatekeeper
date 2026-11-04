# Gatekeeper 0.9.3 — Cierre de Rondas 3, 4 y 5 de Auditoría Adversarial (`NUEVO-3`, `NUEVO-5`, `NUEVO-6`, `NUEVO-7` · `49 PASA · 0 FALLA · 3 INFO`)

Esta versión cierra en orden las **rondas 3, 4 y 5 de la re-auditoría independiente de Claude** contra `0.9.1` y `0.9.2` documentadas en [`.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R3.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R3.md), [`.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R4.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R4.md), [`.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R5.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-R5.md) y [`AUDITORIA-IA-COMPARATIVA.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/AUDITORIA-IA-COMPARATIVA.md), llevando las 52 pruebas de concepto ejecutables de `.audit/PACK-REVISOR/ejecutar_pocs.py` a **`49 PASA · 0 FALLA · 3 INFO`** y elevando la detección sobre OWASP CRS a **`471 / 1135` (`41,5 %`)** con `0` falsos positivos nuevos.

| Métrica | Antes (`0.9.2`) | Ahora (`0.9.3`) |
| :--- | :---: | :---: |
| Batería completa de PoCs (`ejecutar_pocs.py` + R3 + R4 + R5) | `44 PASA · 3 FALLA · 3 INFO` | **`49 PASA · 0 FALLA · 3 INFO`** |
| Detección en corpus propio (`attacks.json`, corto y $\ge 128$ B) | `160 / 160` (`100 %`, `0 %` FP) | **`160 / 160` (`100 %`, `0 %` FP)** |
| Detección en corpus retenido (`heldout_attacks.json`) | `103 / 109` (`94,5 %`, `0 %` FP) | **`103 / 109` (`94,5 %`, `0 %` FP)** |
| Detección en OWASP CRS (`crs_payloads.json`, familias 930/941/942) | `465 / 1135` (`41,0 %`, `4,7 %` FP) | **`471 / 1135` (`41,5 %`, `4,7 %` FP, `+6` en `xss`)** |
| Suite completa de regresión (`pytest`) | `2.752` tests | **`2.844` tests (`0` fallos)** |
| Puntuación final de auditoría AppSec (techo técnico por IA) | `97 / 100` | **`97 / 100`** |

## Qué se ha corregido en 0.9.3

1. **`NUEVO-3` y `NUEVO-7` (Rondas 3, 4 y 5) — Acceso DOM XSS por corchetes `[]`, *optional chaining* `?.` y *template literals* sin falsos positivos en código Python/JS (`src/gatekeeper/rules.py`)**:
   - El patrón `xss[6]` exigía punto literal inmediato (`document.`, `window.`, `top.`) o paréntesis en `eval(`. Variantes válidas de JavaScript como `document['cookie']`, `document?.cookie`, `document?.['cookie']`, `window['eval']`, `self.document['cookie']`, `globalThis['document']['cookie']`, `top?.location` o ``eval`alert(1)` `` pasaban con `200`.
   - Se amplía `RULES["xss"]` y `PREFILTER_LITERALS["xss"]` para cubrir `.`, `[`, `?.`, `?.[` y `` ` `` sobre `document`, `window` (excluyendo `window.addEventListener`), `globalThis`, `top` y `location` (`=`, `?.`, `[`, `.href`, `.replace`, `.assign`), llamadas `eval`/`setTimeout`/`setInterval` con `?.(` o *template literals*, y sobre `self`, `parent` y `frames` únicamente cuando acceden a globales/sinks DOM (`.document`, `.window`, `.eval`, `.location`…) o indexan mediante literal de cadena/template (`self['eval']`, `self["alert"]`), evitando bloquear código Python (`self.nombre`, `self.assertEqual`, `self[i]`) o JS legítimo (`parent.postMessage`, `frames.length`, `NUEVO-7`).
   - **Impacto medido**: **+6 detecciones nuevas en OWASP CRS** (`xss` sube de `100/204` a `106/204`, total CRS de `41,0 %` a **`41,5 %`**) y **0 falsos positivos nuevos** en los tres corpus y en fragmentos de código fuente.
2. **`NUEVO-5` (Ronda 4) — Corrección aritmética de los literales octales de metadata cloud en `ssrf` (`src/gatekeeper/rules.py`)**:
   - El literal octal para `169.254.169.254` tenía `0252` (`0o252 == 170`) en lugar de `0251` (`0o251 == 169`).
   - Se corrige en `RULES["ssrf"]` y `PREFILTER_LITERALS["ssrf"]` a `0251.0376.0251.0376` y entero octal `025177524776` (AWS/GCP IMDS), `0251.0376.0252.0002` y `025177525002` (AWS ECS `169.254.170.2`), y hex por octeto `0xa9.0xfe.0xa9.0xfe`, con test de regresión calculado aritméticamente mediante `oct()`.
3. **`NUEVO-6` (Ronda 4) — Loopback `127.0.0.1` ofuscado en decimal, hexadecimal y octal en `ssrf` (`src/gatekeeper/rules.py`)**:
   - `docs/amenazas.md` prometía bloquear `http://2130706433/` y sus equivalentes hexadecimales y octales mientras mantenía permitidos `localhost` y `127.0.0.1` en texto plano, pero `RULES["ssrf"]` no incluía los literales de loopback ofuscado.
   - Se añaden bajo esquema de URL (`http://`, `https://`, `ftp://`, `ftps://`) los literales `2130706433`, `0x7f000001`, `0x7f.0x0.0x0.0x1`, `0177.0.0.1`, `0177.0000.0000.0001` y `017700000001` tanto en `RULES["ssrf"]` como en `PREFILTER_LITERALS["ssrf"]` (`0` falsos positivos nuevos).
4. **Decodificación de escapes Unicode `\uXXXX` (JS/JSON) en `decode()` (`src/gatekeeper/rules.py`)**:
   - `_UNICODE_ESCAPE` resuelve también secuencias `\uXXXX` además de `%uXXXX` (IIS), bloqueando evasiones como `\u005f\u005fproto\u005f\u005f` o `\u0064ocument['cookie']` incluso cuando llegan en `text/plain` o query string (`0` falsos positivos en los tres corpus).

## Migración desde 0.9.2

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni parámetros obligatorios nuevos. La actualización desde `0.9.2` (o cualquier `0.9.x` anterior) es directa:

```bash
pip install -U gatekeeper-asgi
```

**Qué tener en cuenta al actualizar:**

1. **Accesos DOM XSS con corchetes u *optional chaining***: entradas que contengan `document[...]`, `window[...]`, `globalThis[...]`, `document?.`, `window?.`, `location[...]` o `eval?.(` ahora son bloqueadas por la familia `xss`. Si un campo legítimo transporta código fuente JavaScript, exclúyelo con `exclude_fields`.
2. **Loopback ofuscado en URLs**: `http://127.0.0.1` y `http://localhost` siguen permitidos para desarrollo local y OAuth, pero las formas ofuscadas (`http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`) ahora se bloquean como `ssrf`.
