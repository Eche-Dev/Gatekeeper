# Informe de detección

> Generado con `python tools/evaluate.py --write-report`. No lo edites a mano.

| Métrica | Valor |
|---|---|
| Payloads de ataque | 159 |
| Detectados | 159 (100.0%) |
| Detectados por la regla esperada | 158 (99.4%) |
| Falsos negativos no documentados | 0 |
| Falsos negativos documentados | 0 |
| Requests benignos | 81 |
| Falsos positivos no documentados | 0 (0.0%) |
| Falsos positivos documentados | 5 |

## Detección por regla

| Regla | Detectados / total |
|---|---|
| cmdi | 9 / 9 |
| crlf | 4 / 4 |
| log4shell | 6 / 6 |
| nosql | 7 / 7 |
| path_traversal | 13 / 13 |
| proto_pollution | 3 / 3 |
| sensitive_files | 11 / 11 |
| sqli | 52 / 52 |
| ssrf | 7 / 7 |
| ssti | 7 / 7 |
| xss | 40 / 40 |

## Falsos positivos

| id | regla | motivo | payload |
|---|---|---|---|
| benign-009 | sqli | bloquea una búsqueda legítima sobre time.sleep; es la firma de blind time-based | `/search?q=what+is+sleep(5)+in+python` |
| benign-011 | xss | sitios de documentación que permiten buscar por nombre de etiqueta | `/search?q=<script>+tag+in+html` |
| benign-012 | xss | misma familia que la anterior: texto técnico que cita el vector | `/search?q=javascript:+scheme+in+urls` |
| benign-049 | path_traversal | coincide con la firma de traversal tras decodificar; es el coste de decodificar varias veces | `/search?q=%252e%252e%252f+pruebas+de+codificacion` |
| benign-071 | proto_pollution | búsquedas legítimas sobre proto-pollution: `__proto__` literal en el valor | `/search?q=que+es+__proto__+en+javascript` |

## Umbrales de CI

- detección ≥ 100%: ✅ (100.0%)
- falsos positivos no documentados ≤ 0%: ✅ (0.0%)

## Corpus externo: OWASP Core Rule Set

> Fuente: [OWASP Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset), commit `30cb436b261a`, licencia Apache-2.0. Extraído con `tools/import_crs.py`; alcance, exclusiones y límites en [README.md](README.md).

| Familia (familias CRS 930/941/942) | Detectados / total |
|---|---|
| path_traversal | 30 / 62 |
| sqli | 267 / 869 |
| xss | 97 / 204 |
| **total en alcance** | **394 / 1135 (34.7%)** |

| Métrica externa | Valor |
|---|---|
| Negativos de CRS en alcance | 232 |
| Falsos positivos sobre esos negativos | 11 (4.7%) |
| Excluidos: payload en body con content-type no inspeccionado | 3 |
| Excluidos: payload en cabeceras fuera de inspect_headers | 9 |

### Falsos positivos sobre los negativos de CRS

| id | regla | payload |
|---|---|---|
| crs-941100-t5-s1 | xss | `/get` |
| crs-941140-t14-s1 | xss | `/get/bar?test=url%28javascript%3Aalert%281%29%29` |
| crs-941180-t7-s1 | xss | `/get/javascript-manual/document.cookie` |
| crs-942101-t11-s1 | sqli | `/post/foo/24+union+all+select+1,2,3+from+aa/bar` |
| crs-942160-t12-s1 | sqli | `/BENChmARk(2999/**/999,Md5(/` |
| crs-942350-t9-s1 | sqli | `/get?test=%2F%2A%27%3BINSERT%20INTO%20category%28id%29%20VALUES%20%283%29--%20-%2A%2F` |
| crs-942360-t29-s1 | sqli | `\|\|(SELECT(DBMS_LDAP.INIT('169.1.1.1',19))FROM(DUAL))/investigate` |
| crs-942360-t30-s1 | sqli | `'\|\|(select(pg_sleep(15))where(true))\|\|'/investigate` |
| crs-942360-t31-s1 | sqli | `UNION ALL SELECT NULL,NULL,CONCAT(CONCAT('qqkjq','mxTSrPILRz'),'qvxvq')-- sqCV` |
| crs-942521-t16-s1 | sqli | `var=Incorrectly%20constructed%20SQL%20statements%0AThis%20form%20of%20injection%20relies%2…` |
| crs-942522-t8-s1 | sqli | `var=Incorrectly%20constructed%20SQL%20statements%0AThis%20form%20of%20injection%20relies%2…` |

### Muestra de falsos negativos (12 de 741)

| id | familia | payload |
|---|---|---|
| crs-930100-t5-s1 | path_traversal | `<?xml version="1.0"?><root><a probe="0x5c0x2e.%00/"></a></root>` |
| crs-930120-t9-s1 | path_traversal | `/get?code=>/tmp/curl` |
| crs-930120-t14-s1 | path_traversal | `/get?code=backup.sql.zip` |
| crs-930120-t18-s1 | path_traversal | `/get?file=node_modules/some-package/package.json` |
| crs-930121-t2-s1 | path_traversal | `/get` |
| crs-930121-t3-s1 | path_traversal | `/get` |
| crs-930121-t4-s1 | path_traversal | `/get` |
| crs-930121-t8-s1 | path_traversal | `/get` |
| crs-930121-t9-s1 | path_traversal | `/get` |
| crs-930130-t1-s1 | path_traversal | `/get/sys/class` |
| crs-930130-t2-s1 | path_traversal | `/get/proc/interrupts` |
| crs-930130-t3-s1 | path_traversal | `/get/backup.sql.zip` |

### Umbrales del corpus externo (guarda de regresión sobre la línea base)

- detección CRS ≥ 19%: ✅ (34.7%)
- FP CRS ≤ 5.0%: ✅ (4.7%)

