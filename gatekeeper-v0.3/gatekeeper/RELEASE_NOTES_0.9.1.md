# Gatekeeper 0.9.1 — Cierre de Auditoría de Ciberseguridad Multi-IA (Ronda 1)

Esta versión cierra la primera ronda de **auditoría ofensiva/defensiva multi-modelo** ([`AUDITORIA-IA-COMPARATIVA.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/AUDITORIA-IA-COMPARATIVA.md) y [`PLAN-CIERRE-97.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/PLAN-CIERRE-97.md)), corrigiendo los 16 hallazgos reproducibles (`IA-1/2/3/5`, `H-1`, `H-2A/B/C` y `AG-1..8`) en `.audit/PACK-REVISOR/ejecutar_pocs.py` (`38 PASA · 0 FALLA · 3 INFO`).

## Qué se corrigió en 0.9.1

1. **Aislamiento inicial de `_strip_sql_comments` (`IA-1`)** en las 10 familias no-SQL.
2. **Sincronización de `PREFILTER_LITERALS` a partir de 128 caracteres (`H-2A/B/C`, `AG-8`)**.
3. **Blindaje de `multipart/form-data` y modo cruzado (`H-1`, `AG-1`, `AG-2`, `AG-3`)**.
4. **Sniffing de JSON UTF-16 y UTF-32 bajo `application/octet-stream` (`AG-4`)**.
5. **Cabeceras ASGI repetidas, cuerpos en `GET`/`HEAD`/`OPTIONS` y descompresión `gzip`/`deflate` de 1 nivel (`AG-6`, `IA-2`, `IA-3`)**.
6. **Exclusión de campos (`exclude_fields`) y analizador estático ReDoS (`AG-5`, `AG-7`)**.

## Migración desde 0.9.0

**Sin cambios en la API pública**: `exclude_fields=["bio"]` excluye únicamente `/bio` (usa `exclude_fields=["/bio/*"]` para subárboles enteros) y los nombres de campo `multipart/form-data` y cuerpos comprimidos pasan a inspeccionarse.
