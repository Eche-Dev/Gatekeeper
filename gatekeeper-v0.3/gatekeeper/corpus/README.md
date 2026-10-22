# Corpus de evaluación

Tres ficheros que miden, de forma reproducible, lo que las reglas de Gatekeeper
bloquean y lo que dejan pasar:

| Fichero | Qué contiene |
|---|---|
| `attacks.json` | 148 payloads de ataque redactados para este proyecto (SQLi, XSS, path traversal, ficheros sensibles, NoSQL, comandos, SSRF, SSTI, CRLF, Log4Shell, proto-pollución), cada uno con la regla que se espera que lo detecte |
| `benign.json` | 76 peticiones legítimas que **no** deben bloquearse, incluidos casos difíciles (texto técnico que cita un vector, SQL de tutorial, filtros Mongo legítimos, acentos, JSON normal) |
| `crs_payloads.json` | 1379 tests extraídos del corpus **externo** de OWASP Core Rule Set (Apache-2.0): ataques con su expectativa y negativos de CRS para medir falsos positivos |

Se ejecutan con:

```bash
python tools/evaluate.py              # resumen (corpus propio + externo)
python tools/evaluate.py --write-report   # regenera REPORT.md
python tools/evaluate.py --check      # umbral de CI (sale con 1 si empeora)
python tools/import_crs.py --crs-dir <checkout>   # reimporta el corpus de CRS
python tools/import_crs.py --check     # valida procedencia del JSON de CRS
```

`tests/test_corpus.py` y `tests/test_crs_corpus.py` corren lo mismo dentro de
pytest: si una regla nueva rompe detección o mete falsos positivos, falla la
suite y falla el workflow.

## Corpus externo: OWASP Core Rule Set (Apache-2.0)

`crs_payloads.json` **no es nuestro**: procede de
[coreruleset/coreruleset](https://github.com/coreruleset/coreruleset),
commit `30cb436b261a9f5ec32a5a0677e17f3cfa1a8739` (2026-10-17), licencia
Apache-2.0 — el texto completo está en `LICENSE-APACHE-2.0.txt`. Cambios
aplicados: solo conversión de sus YAML de regresión a JSON con
`tools/import_crs.py` (payload, expectativa y transportador); **los payloads no
se editan**. El JSON guarda commit, fecha de importación y estadísticas para que
la procedencia sea verificable.

Alcance y política de puntuación (para que el número sea defendible):

- Solo las familias que Gatekeeper afirma cubrir: **930 (LFI/traversal),
  941 (XSS) y 942 (SQLi)**. El resto de CRS (protocolo, RCE, PHP…) queda fuera:
  no lo prometemos, no lo medimos.
- `expect=attack` cuando CRS espera que salte su regla (`expect_ids`);
  `expect=benign` cuando CRS espera que **nada** salte (`no_expect_ids`) y sirve
  de negativo para medir nuestros falsos positivos.
- **Exclusiones declaradas** (se cuentan en el informe y tienen techo en los
  tests): payloads que viven solo en cabeceras y bodies con content-type no
  inspeccionado (XML, multipart) son límites de diseño documentados en
  SECURITY.md, no fallos. Un test cuyo payload sí dispara en un campo
  inspeccionable cuenta como detectado aunque su transportador principal esté
  fuera de alcance.
- Sin content-type se asume `application/x-www-form-urlencoded` (el navegador
  lo hace por defecto), igual que un body real llegaría al middleware.
- Los umbrales de CI sobre este corpus (`DEFAULT_MIN_CRS_DETECTION`,
  `DEFAULT_MAX_CRS_FP`) son **guardas de regresión sobre la línea base medida**,
  no una promesa de cobertura: se recalculan al reimportar. La detección sobre
  CRS es ~27% frente a 100% del corpus propio, y es así a propósito: CRS está
  diseñado para un WAF con 500+ reglas y paga con falsos positivos que nosotros
  no aceptamos. Publicar ese número entero es el punto.

## Procedencia y licencia de los payloads propios

Los payloads de `attacks.json` y `benign.json` **no se han copiado de un
repositorio con licencia restrictiva**. Están redactados para este proyecto a
partir de técnicas documentadas públicamente en las guías de OWASP (WSTG) y en
los cheat sheets de PortSwigger, que describen fórmulas como `UNION SELECT`,
`sleep()` o `../` sin que ninguna sea propiedad de nadie. Cada payload lleva una
nota que explica qué técnica representa.

Para el corpus externo, ver la sección anterior: OWASP CRS se importa con
atribución y licencia Apache-2.0 incluida.

## Falsos positivos y falsos negativos documentados

Un middleware de seguridad que dijera "detecta todo y nunca falla" estaría mintiendo.
Por eso el corpus marca explícitamente sus límites:

- `known_fp` en `benign.json`: peticiones legítimas que **sí** bloquea, con el
  motivo. Hoy son 5, todas de la misma familia: texto técnico que contiene la
  firma literal (`sleep(5)`, `<script>`, `javascript:`, codificación doble,
  `__proto__`). Es el coste de decodificar y buscar firmas: un buscador de
  documentación técnica puede encontrarlos.
- `documented_miss` en `attacks.json`: ataques que **se escapan** hoy, con el
  motivo. Hoy son **0**: los cinco que había (blind boolean, entidades HTML,
  UTF-8 sobre-long y `WEB-INF`) se cerraron en 0.3.1 con firmas medidas. Si algo
  se cuelga, se documenta aquí antes que en un commit.

Regla de mantenimiento: si añades una firma, añade también payloads benignos que
demuestren que no rompe nada; si aceptas un falso positivo nuevo, documéntalo en
el corpus, no en el commit.
