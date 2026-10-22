# Informe de detección

> Generado con `python tools/evaluate.py --write-report`. No lo edites a mano.

| Métrica | Valor |
|---|---|
| Payloads de ataque | 83 |
| Detectados | 83 (100.0%) |
| Detectados por la regla esperada | 83 (100.0%) |
| Falsos negativos no documentados | 0 |
| Falsos negativos documentados | 0 |
| Requests benignos | 62 |
| Falsos positivos no documentados | 0 (0.0%) |
| Falsos positivos documentados | 4 |

## Detección por regla

| Regla | Detectados / total |
|---|---|
| path_traversal | 13 / 13 |
| sensitive_files | 8 / 8 |
| sqli | 32 / 32 |
| xss | 30 / 30 |

## Falsos positivos

| id | regla | motivo | payload |
|---|---|---|---|
| benign-009 | sqli | bloquea una búsqueda legítima sobre time.sleep; es la firma de blind time-based | `/search?q=what+is+sleep(5)+in+python` |
| benign-011 | xss | sitios de documentación que permiten buscar por nombre de etiqueta | `/search?q=<script>+tag+in+html` |
| benign-012 | xss | misma familia que la anterior: texto técnico que cita el vector | `/search?q=javascript:+scheme+in+urls` |
| benign-049 | path_traversal | coincide con la firma de traversal tras decodificar; es el coste de decodificar varias veces | `/search?q=%252e%252e%252f+pruebas+de+codificacion` |

## Umbrales de CI

- detección ≥ 100%: ✅ (100.0%)
- falsos positivos no documentados ≤ 0%: ✅ (0.0%)

## Corpus externo: OWASP Core Rule Set

> Fuente: [OWASP Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset), commit `30cb436b261a`, licencia Apache-2.0. Extraído con `tools/import_crs.py`; alcance, exclusiones y límites en [README.md](README.md).

| Familia (familias CRS 930/941/942) | Detectados / total |
|---|---|
| path_traversal | 17 / 49 |
| sqli | 135 / 789 |
| xss | 33 / 144 |
| **total en alcance** | **185 / 982 (18.8%)** |

| Métrica externa | Valor |
|---|---|
| Negativos de CRS en alcance | 185 |
| Falsos positivos sobre esos negativos | 8 (4.3%) |
| Excluidos: payload en body con content-type no inspeccionado | 92 |
| Excluidos: payload solo en cabeceras (no inspeccionadas) | 120 |

### Falsos positivos sobre los negativos de CRS

| id | regla | payload |
|---|---|---|
| crs-941140-t14-s1 | xss | `/get/bar?test=url%28javascript%3Aalert%281%29%29` |
| crs-942101-t11-s1 | sqli | `/post/foo/24+union+all+select+1,2,3+from+aa/bar` |
| crs-942160-t12-s1 | sqli | `/BENChmARk(2999/**/999,Md5(/` |
| crs-942350-t9-s1 | sqli | `/get?test=%2F%2A%27%3BINSERT%20INTO%20category%28id%29%20VALUES%20%283%29--%20-%2A%2F` |
| crs-942360-t30-s1 | sqli | `'\|\|(select(pg_sleep(15))where(true))\|\|'/investigate` |
| crs-942360-t31-s1 | sqli | `UNION ALL SELECT NULL,NULL,CONCAT(CONCAT('qqkjq','mxTSrPILRz'),'qvxvq')-- sqCV` |
| crs-942521-t16-s1 | sqli | `var=Incorrectly%20constructed%20SQL%20statements%0AThis%20form%20of%20injection%20relies%2…` |
| crs-942522-t8-s1 | sqli | `var=Incorrectly%20constructed%20SQL%20statements%0AThis%20form%20of%20injection%20relies%2…` |

### Muestra de falsos negativos (12 de 797)

| id | familia | payload |
|---|---|---|
| crs-930120-t5-s1 | path_traversal | `/get?/sys/class=test` |
| crs-930120-t6-s1 | path_traversal | `/get?test=/sys/class` |
| crs-930120-t9-s1 | path_traversal | `/get?code=>/tmp/curl` |
| crs-930120-t14-s1 | path_traversal | `/get?code=backup.sql.zip` |
| crs-930120-t18-s1 | path_traversal | `/get?file=node_modules/some-package/package.json` |
| crs-930130-t1-s1 | path_traversal | `/get/sys/class` |
| crs-930130-t2-s1 | path_traversal | `/get/proc/interrupts` |
| crs-930130-t3-s1 | path_traversal | `/get/backup.sql.zip` |
| crs-930130-t6-s1 | path_traversal | `/@id/__x00__?import` |
| crs-930130-t7-s1 | path_traversal | `/wp-content/debug.log` |
| crs-930130-t8-s1 | path_traversal | `/wp-content/error.log` |
| crs-930130-t9-s1 | path_traversal | `/wp-content/errors.log` |

### Umbrales del corpus externo (guarda de regresión sobre la línea base)

- detección CRS ≥ 18%: ✅ (18.8%)
- FP CRS ≤ 5.0%: ✅ (4.3%)

