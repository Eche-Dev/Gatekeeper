# Corpus de evaluación

Dos ficheros que miden, de forma reproducible, lo que las reglas de Gatekeeper
bloquean y lo que dejan pasar:

| Fichero | Qué contiene |
|---|---|
| `attacks.json` | 83 payloads de ataque reales (SQLi, XSS, path traversal, ficheros sensibles), cada uno con la regla que se espera que lo detecte |
| `benign.json` | 62 peticiones legítimas que **no** deben bloquearse, incluidos casos difíciles (texto técnico que cita un vector, SQL de tutorial, acentos, JSON normal) |

Se ejecutan con:

```bash
python tools/evaluate.py              # resumen
python tools/evaluate.py --write-report   # regenera REPORT.md
python tools/evaluate.py --check      # umbral de CI (sale con 1 si empeora)
```

`tests/test_corpus.py` corre lo mismo dentro de pytest: si una regla nueva rompe
detección o mete falsos positivos, falla la suite y falla el workflow.

## Procedencia y licencia de los payloads

Los payloads **no se han copiado de un repositorio con licencia restrictiva**.
Están redactados para este proyecto a partir de técnicas documentadas públicamente
en las guías de OWASP (WSTG) y en los cheat sheets de PortSwigger, que describen
fórmulas como `UNION SELECT`, `sleep()` o `../` sin que ninguna sea propiedad de
nadie. Cada payload lleva una nota que explica qué técnica representa.

Si en el futuro se importan payloads de un corpus de terceros (por ejemplo el
OWASP Core Rule Set, con licencia Apache 2.0), debe añadirse aquí la atribución
correspondiente antes de mergear.

## Falsos positivos y falsos negativos documentados

Un middleware de seguridad que dijera "detecta todo y nunca falla" estaría mintiendo.
Por eso el corpus marca explícitamente sus límites:

- `known_fp` en `benign.json`: peticiones legítimas que **sí** bloquea, con el
  motivo. Hoy son 4, todas de la misma familia: texto técnico que contiene la
  firma literal (`sleep(5)`, `<script>`, `javascript:`, codificación doble).
  Es el coste de decodificar y buscar firmas: un buscador de documentación
  técnica puede encontrarlos.
- `documented_miss` en `attacks.json`: ataques que **se escapan** hoy, con el
  motivo. Hoy son 5: blind boolean sin comilla pegada al comentario, entidades
  HTML (`&#60;script&#62;`), UTF-8 sobre-long (`%c0%af`) y `web-inf/web.xml`.

Regla de mantenimiento: si añades una firma, añade también payloads benignos que
demuestren que no rompe nada; si aceptas un falso positivo nuevo, documéntalo en
el corpus, no en el commit.
