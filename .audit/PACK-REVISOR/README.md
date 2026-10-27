# Paquete de revisión de seguridad independiente

Material para que **alguien que no haya desarrollado el proyecto** pueda
revisar el middleware `gatekeeper-asgi` sin tener que reconstruir el contexto
desde cero.

## Por qué existe

Las seis fases de auditoría del proyecto tienen **mediciones
independientes**: los PoC se ejecutan contra el código real y cada hallazgo
tiene una regresión que falla sin el arreglo. Lo que **no** es independiente
es el **juicio** de quien ajustó las reglas: para cerrar el último punto del
plan (100/100) hace falta una revisión hecha por alguien ajeno.

## Qué hay aquí

| fichero | qué es |
|---|---|
| [`ALCANCE.md`](ALCANCE.md) | **Empieza por aquí.** El alcance, las fronteras de confianza por orden de prioridad, los datos medidos, los límites conocidos y cómo reproducirlo todo. |
| [`PLANTILLA-SECURITY-REVIEW.md`](PLANTILLA-SECURITY-REVIEW.md) | La plantilla del informe: qué campos tiene que llevar, qué es un hallazgo y qué es una observación. |
| [`ejecutar_pocs.py`](ejecutar_pocs.py) | 15 comprobaciones ejecutables sobre el código real. El punto de partida, y el sitio donde añadir las tuyas. |

## Cómo empezar

```bash
# 1. Las 15 comprobaciones: el estado actual, medido
python .audit/PACK-REVISOR/ejecutar_pocs.py

# 2. Los nombres, para ejecutar solo una
python .audit/PACK-REVISOR/ejecutar_pocs.py --listar
python .audit/PACK-REVISOR/ejecutar_pocs.py mas redis
```

Salida esperada (en el commit `9724daf`):

```
[PASA] H-1 punteros JSON: sin amplificacion cuadratica
[PASA] el `+` literal se detecta (form con %2B)
...
RESUMEN: 15 pasan · 0 fallan · 0 notas
```

Un `FALLA` **no es un veredicto sobre el código**: es un síntoma que hay que
confirmar, explicar y decidir. Y que todos pasen tampoco significa que no
haya nada: el paquete cubre lo que ya se conoce, no lo que se busca.

## Dónde va el informe

A `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md` (sustituyendo el informe
de la 0.3.1, que es el registro de aquella revisión), con la plantilla de
este paquete. Si lo publicas en otra rama o en otro sitio, da igual: lo que
importa es que quede **publicado** y que el README diga **quién revisó y
cuándo**.

## El resto del material

- El código: `gatekeeper-v0.3/gatekeeper/src/gatekeeper/`
- La revisión anterior (la de la 0.3.1): `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md`
- Los límites conocidos: `gatekeeper-v0.3/gatekeeper/docs/amenazas.md`
- El registro de todo lo corregido: `gatekeeper-v0.3/gatekeeper/CHANGELOG.md`
- La evidencia de las fases: `.audit/`
