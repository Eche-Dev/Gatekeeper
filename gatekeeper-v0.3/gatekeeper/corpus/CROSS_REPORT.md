# Informe de Evaluación Cross-Carrier (v0.3)

## Resumen Ejecutivo

Modo | Ataques bloqueados | Benignos bloqueados (FP) | FP no documentados | Ataques ganados solo en modo cruzado
--- | --- | --- | --- | ---
| Por defecto | 0/7 (0%) | 0/15 (0%) | 0 | 0
| Cruzado | 7/7 (100%) | 0/15 (0%) | 0 | 7

## Métricas por Familia de Reglas

Las siguientes métricas miden la detección por tipo de ataque (firma) en modo `inspect_cross_carrier=True`:

| Regla | Ataques Esperados | Detectados | Falsos Positivos Documentados | Tasa de Detección |
|---|---|---|---|---|
| `sqli` | 4 | 4/4 (100%) | 0 | 100% |
| `nosql` | 1 | 1/1 (100%) | 0 | 100% |
| `crlf` | 2 | 2/2 (100%) | 0 | 100% |

**Total:** 7/7 ataques detectados (100%), 0 falsos positivos documentados.

## Análisis Detalle

- **sqli (4 ataques)**: Todos los ataques de inyección SQL se detectan cuando el objetivo y body aparecen juntos. Patrones: `UNION SELECT`, inyecciones `UNION ALL SELECT`.
- **nosql (1 ataque)**: Falsos inyecciones NoSQL detectadas mediante patrones `$ne`, `$where`, `$regex`, `$nin` combinados con el objetivo.
- **crlf (2 ataques)**: Payloads CRLF inyectados en target+body que provocan cabeceras de respuesta manipulables.

### Falsos Positivos (0 documentados)

Todos los 15 payloads benignos pasan limpiamente sin bloqueo en modo cruzado. Ningún texto legítimo (tutoriales SQL, acentos, JSON normal, etc.) genera falso positivo.

## Modos de Evaluación

- **`--check`**: Sale con código 1 si alguna métrica empeora (usado en CI).
- **`--json`**: Salida JSON con todos los números para procesamiento automático.
- **`--write-report`**: Genera este informe markdown.

## Nota Importante

Este corpus es **opt-in**, **de solo desarrollo** y **no es un conjunto de retención de seguridad** para producción. No afecta las métricas del modo individual (`inspect_cross_carrier=False`). Para activar en producción, revisar primero los falsos positivos con tráfico real en modo `monitor_only`.

---

*Generado con `python tools/evaluate_cross.py --write-report`*