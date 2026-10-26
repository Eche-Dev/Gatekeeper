# Corpus de Gatekeeper

Cuatro conjuntos de datos, cada uno con un propósito distinto. La diferencia
importa: **medir** y **ajustar** no son lo mismo.

| Corpus | Fichero | Para qué | Tamaño |
|---|---|---|---|
| Desarrollo | `attacks.json` + `benign.json` | ajustar las reglas | 159 + 131 |
| Retenido | `heldout_attacks.json` + `heldout_benign.json` | **medir** si las reglas generalizan | 109 + 140 |
| Retenido cruzado | `heldout_cross.json` | **medir** el modo opt-in fuera del corpus de desarrollo | 20 + 20 |
| Cruzado | `cross.json` | medir el modo opt-in `inspect_cross_carrier=True` | 7 + 15 |
| Externo | `crs_payloads.json` | medir contra un corpus escrito por terceros | 1379 |

## Desarrollo

`attacks.json` y `benign.json` son el corpus de trabajo. Se **pueden editar**
cuando se añade una firma: para eso están.

- `attacks.json`: cada payload declara la `rule` que se espera que lo detecte.
  Un payload con `documented_miss` es un límite conocido y aceptado (se explica
  en `note`).
- `benign.json`: tráfico legítimo. Un payload con `known_fp` es un falso
  positivo **aceptado y documentado** (por ejemplo, una búsqueda que cita
  `sleep(5)` a propósito). Los que no lo tienen deben pasar siempre.

Informe: [`REPORT.md`](REPORT.md).

## Retenido

`heldout_attacks.json` y `heldout_benign.json` se escribieron **una vez**,
sin mirar las firmas de las reglas, y a partir de ahí solo se miden. Es lo que
distingue "las reglas detectan esto" de "las reglas detectan lo que se
escribieron para ellas".

`heldout_benign.json` tiene **dos lotes**: 90 casos escritos antes de v0.4.0 y
50 más escritos en la Fase 3, ya con las firmas congeladas. Los dos se miden
igual: un falso positivo ahí no se arregla con una firma escrita para él, se
documenta. Los detalles, en [`HELDOUT.md`](HELDOUT.md).

Metodología completa: [`HELDOUT.md`](HELDOUT.md). Informe:
[`HELDOUT_REPORT.md`](HELDOUT_REPORT.md).

## Retenido cruzado

`heldout_cross.json` es lo mismo para el modo opt-in
`inspect_cross_carrier=True`: firmas **partidas** entre la ruta/query y los
valores textuales del body, escritas una vez sin mirar las firmas.

Se mide con `python tools/evaluate_cross.py --heldout`. Resultado: **20/20**
ataques bloqueados en modo cruzado y **0/20** benignos bloqueados, frente a
**10/20** en el modo por defecto (la mitad de las firmas partidas se escapan
sin el modo cruzado).

Informe: [`HELDOUT_CROSS_REPORT.md`](HELDOUT_CROSS_REPORT.md).

## Cruzado

`cross.json` mide el modo **opt-in** `inspect_cross_carrier=True`: firmas
partidas entre la ruta/query y los valores textuales del body.

**No se mezcla** con las cifras del modo individual: son otra medición, con
sus propios denominadores. Es un corpus de desarrollo, no una evaluación
retenida.

Informe: [`CROSS_REPORT.md`](CROSS_REPORT.md).

## Externo: OWASP Core Rule Set

`crs_payloads.json` es la colección de regresión de
[OWASP CRS](https://github.com/coreruleset/coreruleset), **importada**, no
escrita: `tools/import_crs.py` la extrae de los YAML de regresión del proyecto
upstream y registra el commit de procedencia.

- Alcance: las familias que Gatekeeper afirma cubrir (930 LFI, 941 XSS,
  942 SQLi).
- Licencia: Apache-2.0. Se conserva el texto en
  [`LICENSE-APACHE-2.0.txt`](LICENSE-APACHE-2.0.txt) y la atribución aquí.
- No se edita a mano: se reimporta.

Su porcentaje **no es comparable** con el de un WAF completo: CRS está diseñado
para 500+ reglas y muchos más casos ofuscados.

## Comandos

```bash
python tools/evaluate.py --check              # desarrollo + CRS
python tools/evaluate_heldout.py --check       # retenido
python tools/evaluate_cross.py --check         # cruzado (desarrollo)
python tools/evaluate_cross.py --heldout --check  # cruzado (retenido)
python tools/import_crs.py --check             # procedencia del corpus externo
python tools/measure_rules.py                  # efecto de un cambio de reglas
```

Los cinco entran en CI. Un cambio de reglas que rompa una cifra pone el
pipeline en rojo.
