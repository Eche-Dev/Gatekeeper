# Informe de detección

> Generado con `python tools/evaluate.py --write-report`. No lo edites a mano.

| Métrica | Valor |
|---|---|
| Payloads de ataque | 83 |
| Detectados | 78 (94.0%) |
| Detectados por la regla esperada | 78 (94.0%) |
| Falsos negativos no documentados | 0 |
| Falsos negativos documentados | 5 |
| Requests benignos | 62 |
| Falsos positivos no documentados | 0 (0.0%) |
| Falsos positivos documentados | 4 |

## Detección por regla

| Regla | Detectados / total |
|---|---|
| path_traversal | 12 / 13 |
| sensitive_files | 7 / 8 |
| sqli | 31 / 32 |
| xss | 28 / 30 |

## Falsos negativos documentados (límites conocidos)

| id | por qué se escapa | payload |
|---|---|---|
| sqli-032 | blind boolean carácter a carácter | `1' AND ASCII(SUBSTRING(nombre,1,1))>64--` |
| xss-029 | entidades HTML | `&#60;script&#62;alert(1)&#60;/script&#62;` |
| xss-030 | entidad en javascript: | `<a href=&#106;avascript:alert(1)>x</a>` |
| trav-013 | UTF-8 sobre-long | `..%c0%af..%c0%afetc/passwd` |
| files-008 | configuración Java | `web-inf/web.xml` |

## Falsos positivos

| id | regla | motivo | payload |
|---|---|---|---|
| benign-009 | sqli | bloquea una búsqueda legítima sobre time.sleep; es la firma de blind time-based | `/search?q=what+is+sleep(5)+in+python` |
| benign-011 | xss | sitios de documentación que permiten buscar por nombre de etiqueta | `/search?q=<script>+tag+in+html` |
| benign-012 | xss | misma familia que la anterior: texto técnico que cita el vector | `/search?q=javascript:+scheme+in+urls` |
| benign-049 | path_traversal | coincide con la firma de traversal tras decodificar; es el coste de decodificar varias veces | `/search?q=%252e%252e%252f+pruebas+de+codificacion` |

## Umbrales de CI

- detección ≥ 90%: ✅ (94.0%)
- falsos positivos no documentados ≤ 0%: ✅ (0.0%)
