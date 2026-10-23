# Informe del corpus retenido (modo cruzado)

> Generado con `python tools/evaluate_cross.py --heldout --write-report`.
> No lo edites a mano.

Mide el modo opt-in `inspect_cross_carrier=True` sobre el corpus **retenido**:
firmas partidas entre la ruta/query y los valores textuales del body.

Se escribio una vez, sin mirar las firmas de las reglas, y desde entonces
solo se mide (ver [HELDOUT.md](HELDOUT.md)).

| Modo | Ataques bloqueados | Benignos bloqueados (FP) | FP no documentados |
|---|---|---|---|
| Por defecto | 10/20 | 0/20 | 0 |
| Cruzado | 20/20 | 0/20 | 0 |

**La mitad de las firmas partidas se escapan sin el modo cruzado.** Con
`inspect_cross_carrier=True` se detectan todas, sin un solo falso positivo
sobre las peticiones legitimas.

## Por que el retenido da mas que el de desarrollo

El corpus de desarrollo del modo cruzado tiene 7 ataques y 15 benignos.
El retenido tiene mas, con las firmas repartidas de formas distintas (la
etiqueta abierta en la query y el cierre en el body, el separador de shell
en la query y el binario en el body, la plantilla partida, el lookup JNDI
partido...). El retenido confirma que el modo cruzado generaliza y no solo
se acordaba de los casos con los que se escribio.

## Nota

Este corpus es **opt-in** y **de solo desarrollo**: medirlo no lo convierte
en evidencia de que el modo cruzado sea seguro en produccion. Antes de
activarlo, revisa los falsos positivos con trafico real en `monitor_only`.

---

*Generado con `python tools/evaluate_cross.py --heldout --write-report`*