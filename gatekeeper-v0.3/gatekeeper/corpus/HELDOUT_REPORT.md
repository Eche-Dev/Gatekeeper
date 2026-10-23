# Informe del corpus retenido

> Generado con `python tools/evaluate_heldout.py --write-report`.
> No lo edites a mano.

Este corpus se usa para **medir**, no para ajustar: se escribio una vez,
sin mirar las firmas de las reglas, y a partir de ahi no se ha tocado para
hacer que las reglas passen. Por eso su cifra es mas baja que la del
corpus de desarrollo, y esa diferencia es informacion, no un defecto.

| Metrica | Valor |
|---|---|
| Payloads de ataque | 109 |
| Detectados | 103 (94.5%) |
| Falsos negativos no documentados | 0 |
| Falsos negativos documentados (limites conocidos) | 6 |
| Requests benignos | 90 |
| Falsos positivos no documentados | 0 (0.0%) |
| Falsos positivos documentados | 4 |

## Deteccion por regla

| Regla | Detectados / total |
|---|---|
| cmdi | 10 / 10 |
| crlf | 4 / 4 |
| log4shell | 5 / 5 |
| nosql | 6 / 7 |
| path_traversal | 13 / 14 |
| proto_pollution | 3 / 3 |
| sensitive_files | 12 / 12 |
| sqli | 17 / 20 |
| ssrf | 6 / 7 |
| ssti | 7 / 7 |
| xss | 20 / 20 |

## Falsos negativos documentados (limites conocidos)

| id | por que se escapa | payload |
|---|---|---|
| ho-sqli-002 | cierre de parentesis + comparacion de literales | `') OR ('x'='x` |
| ho-sqli-013 | comparacion con literales hex | `1' AND 0x20 LIKE 0x20-- -` |
| ho-sqli-017 | extraccion de version con SUBSTRING | `1' AND SUBSTRING(@@version,1,1)='5'` |
| ho-pt-009 | byte nulo tras los puntos | `..%00/` |
| ho-nosql-002 | comparacion $gt vacia | `password[$gt]=` |
| ho-ssrf-006 | IPv6 loopback | `http://[::1]:8080/admin` |

## Falsos positivos

| id | regla | motivo | payload |
|---|---|---|---|
| hob-049 | sqli | endpoint de pruebas que devuelve payloads como valor: bloquearlo es correcto | `/api/test?input=1%3D1` |
| hob-050 | sqli | endpoint de pruebas que devuelve payloads como valor: bloquearlo es correcto | `/api/test?input=%27%20or%20%271%27%3D%271%27` |
| hob-051 | xss | endpoint de pruebas que devuelve payloads como valor: bloquearlo es correcto | `/api/test?input=%3Cscript%3Ealert(1)%3C/script%3E` |
| hob-052 | path_traversal | endpoint de pruebas que devuelve payloads como valor: bloquearlo es correcto | `/api/test?input=..%2F..%2Fetc%2Fpasswd` |

## Umbrales de CI

- deteccion >= 85%: OK (94.5%)
- falsos positivos no documentados <= 0%: OK (0.0%)
