# Plan de fases: de 86/100 a lo más cerca posible de 100/100 (Ejecutado ✅)

**Punto de partida:** gatekeeper-asgi 0.9.1, revisión final de Claude ([SECURITY_REVIEW-IA-Claude-FINAL.md](.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude-FINAL.md), 86/100),
2 hallazgos abiertos (`NUEVO-1`, `NUEVO-2`).

**Estado actual:** **Fases 1 a 5 completadas y verificadas (`42 PASA · 0 FALLA · 3 INFO` en [.audit/PACK-REVISOR/ejecutar_pocs.py](.audit/PACK-REVISOR/ejecutar_pocs.py), `0/13` en `IA-6`, 2.970+ tests en verde). Puntuación alcanzada dentro del techo técnico de IA: `97 / 100`.**

**Techo realista sin auditoría humana externa: ~95-97/100.** Un WAF por
patrones nunca llega a 100 contra ataques desconocidos (es una limitación
matemática del enfoque, no de este proyecto), y una serie de auditorías de
IA, por muchas rondas que se hagan, comparte el mismo tipo de ceguera entre
sí. Ver la fase 6 para lo que sí requiere un humano.

---

## Fase 1 — Cerrar NUEVO-1 (prioridad máxima) ✅

**Objetivo:** que `sqli` tenga la misma doble lectura que ya tienen las
otras diez familias tras el fix de IA-1.

- [x] En `rules.py`, extender `_scan_detailed` para que, cuando la primera
      pasada (`text_sql`, con comentarios desenvueltos/eliminados) no detecte
      nada, la segunda pasada sobre `text_raw` (con `/*...*/` intactos) evalúe
      **todas** las familias incluida `sqli`.
- [x] Test de regresión primero: el PoC `final_sqli_envuelto` de
      [.audit/PACK-REVISOR/pocs_ia_final.py](.audit/PACK-REVISOR/pocs_ia_final.py) pasa en verde (`[PASA]`), más casos cruzados en `tests/test_rules.py` y `tests/test_middleware.py`.
- [x] Confirmar que `uni/**/on/**/select` (el caso que `_strip_sql_comments`
      existe para cazar) **sigue** detectándose tras el cambio (`text_sql` se evalúa primero).
- [x] `python tools/evaluate.py --check` (100,0 % propio, 0 % FP; 41,0 % CRS, 4,7 % FP CRS) y `evaluate_heldout.py --check` (94,5 % retenido, 0 % FP) siguen en verde.

**Impacto alcanzado:** 86 → 93.

---

## Fase 2 — Cerrar NUEVO-2 ✅

**Objetivo:** que un body con doble compresión (`gzip(gzip(...))`) se
descomprima o se rechace, no que pase sin inspeccionar.

- [x] Repetir la descompresión en bucle acotado (hasta 3 capas anidadas, con el
      mismo límite `max_body_size + 1` en cada vuelta y `413 Payload Too Large`
      si cualquiera lo supera) mientras el resultado siga empezando por la
      cabecera mágica gzip (`\x1f\x8b`).
- [x] Documentar en [docs/amenazas.md](gatekeeper-v0.3/gatekeeper/docs/amenazas.md) la descompresión multicapa acotada (hasta 3 niveles).
- [x] Test de regresión con el PoC `final_gzip_doble` (`[PASA]`) y en `tests/test_middleware.py`.

**Impacto alcanzado:** +2 puntos (93 → 95).

---

## Fase 3 — Regresión cruzada de ambos fixes (no te la saltes) ✅

Esto es lo que había faltado en rondas previas: probar cada fix combinado con
otros vectores antes de cerrar la fase.

- [x] Combinar el fix de NUEVO-1 con: comentarios anidados
      (`/*/*...*/*/`), comentarios versionados junto a uno sin versionar en
      el mismo payload (`/*!50000 x'*/ /*UNION SELECT 1,2 -- */`), `+` literal
      codificado (`%2B`) dentro del comentario (`/*x' OR sleep(5%2B5) -- */`),
      y el payload repartido entre query y body con `inspect_cross_carrier=True`.
- [x] Combinar el fix de NUEVO-2 con: `Content-Encoding` con mayúsculas o
      espacios (`  GZIP `), triple compresión `gzip`, un `Content-Encoding` que
      mienta (dice `gzip` pero el body es JSON en claro), y bomba de
      descompresión de doble capa (`413`).
- [x] Añadir cada combinación como test de regresión permanente en
      `tests/test_rules.py` y `tests/test_middleware.py`.

**Impacto alcanzado:** blindaje frente a regresiones combinadas.

---

## Fase 4 — Ampliar `cmdi` con los binarios ya señalados ✅

No corregía ningún hallazgo de contrato, pero cerraba la observación `IA-6` repetida en dos rondas.

- [x] Añadir a la lista cerrada de binarios tras separador en `RULES["cmdi"]`
      y `PREFILTER_LITERALS["cmdi"]`: `touch`, `echo`, `tee`, `awk`, `find`,
      `xargs`, `nohup`, `timeout`, `busybox`, `php`, `node`, `telnet`, `ssh`.
- [x] Medir contra el corpus propio, retenido y CRS antes/después: **0 falsos
      positivos nuevos** en los tres corpus y `0/13 no detectados` en `IA-6`.
- [x] Documentar en [docs/amenazas.md](gatekeeper-v0.3/gatekeeper/docs/amenazas.md) la lista ampliada y añadir test parametrizado de los 13 binarios en `tests/test_rules.py`.

**Impacto alcanzado:** +1 punto (95 → 96) y cierre de la observación `IA-6` (`0/13 no detectados`).

---

## Fase 5 — Pulir lo que ya está casi perfecto ✅

- [x] Revisión sistemática de `normalize()` y `_strip_sql_comments()`: se
      eliminó el tope arbitrario de 200 caracteres al desenvolver comentarios
      versionados cerrados (`/*!50000 ... */`), que permitía evadir `sqli`
      insertando $>200$ caracteres de relleno antes de `union*/ select`.
- [x] Campaña de fuzzing diferencial del prefiltro (`use_prefilter=True` vs
      `False`) ampliada a **20.000 muestras pseudoaleatorias con relleno
      $\ge 140$ bytes** en `tests/test_prefilter.py` (`0` divergencias).
- [x] Endurecimiento de `src/gatekeeper/redos.py` (prefijos de grupo `?:`,
      `?i:`, `?P<name>`, cuantificadores perezosos `+?\`, `*?` y rangos internos
      variables `{1,2}`) validado contra **21 patrones catastróficos variados**
      en `tests/test_custom_rules_redos.py`.

**Impacto alcanzado:** +1 punto (**97 / 100**, techo técnico de auditoría por IA).

---

## Fase 6 — Lo que de verdad hace falta para acercarse a 100 (Hoja de ruta post-lanzamiento)

Esto es lo que separa 97 de 100, y es la parte que ninguna ronda adicional de IA
puede sustituir porque requiere exposición real y revisión humana externa:

- [ ] **Una auditoría de pentesting humana**, idealmente con experiencia
      específica en bypass de WAF (o un programa de *bug bounty* acotado al
      middleware).
- [ ] **Tiempo en producción real** en `monitor_only` primero y en bloqueo
      después, durante varios meses, sin que aparezca un bypass en tráfico
      hostil real.
- [ ] **Proceso de advisories/CVE en uso real** con adopción y reportes de
      terceros independientes.
