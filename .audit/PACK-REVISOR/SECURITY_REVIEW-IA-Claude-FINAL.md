# Revisión de seguridad — Gatekeeper 0.9.1 (independiente, por IA — revisión final)

**Fecha:** 2026-10-28 · **Autor/a:** Claude (Anthropic), a petición de Ángel Echenique
**Commit revisado:** `a2ef6d9` (`main`, tras el merge del PR #47)
**Versión del paquete:** gatekeeper-asgi 0.9.1

---

## Conflicto de intereses

- [x] No he participado en el desarrollo del código revisado.
- [x] No he ajustado ni creado reglas de detección de este proyecto.
- Nota de transparencia: en una sesión anterior de esta misma conversación
  revisé el commit `dc691ca` (0.9.0) y encontré el hallazgo **IA-1**
  (bypass universal por `/*...*/`). Esa corrección y las de otros cuatro
  modelos (Gemini, Cursor, ChatGPT, Argon/Antigravity) ya están aplicadas en
  este commit. Esta revisión parte de ahí, verifica que el cierre sea real y
  busca específicamente lo que un fix reciente suele dejar: casos de borde
  del propio parche.

---

## Alcance

**Revisado:** los 10 módulos de `src/gatekeeper/`, con foco en los diffs
desde `dc691ca` (body.py, middleware.py, config.py, redos.py, rules.py);
`docs/amenazas.md`, `AUDITORIA-IA-COMPARATIVA.md` y `PLAN-CIERRE-97.md`
para contrastar lo arreglado contra lo reclamado; el paquete instalado desde
un entorno limpio (no solo el repo).

**No revisado:** Redis real (sin servidor disponible en el entorno de
revisión; sí leí el código de `RedisBackend` y el guion Lua), la matriz de
compatibilidad completa, y cada expresión regular una por una (me centré en
el pipeline compartido, que es donde un fallo afecta a más de una familia).

**Método:** las 38 PoC de los cinco auditores anteriores
(`ejecutar_pocs.py`), más 4 propias nuevas en `pocs_ia_final.py` que
combinan el fix de IA-1 con otras transformaciones del pipeline
(comentarios anidados/versionados, doble compresión, cabeceras duplicadas,
`exclude_fields`), y tres apps Starlette reales (SQLite con consulta cruda,
doble descompresión gzip) para medir impacto real, no solo `scan() ==
None`.

---

## Resumen

| | |
|---|---|
| Hallazgos de revisiones anteriores (IA-1/2/3/5, H-1/2, AG-1 a AG-8) | **16/16 corregidos, verificados de nuevo por mí** |
| Hallazgos **nuevos** en esta revisión | 2 (ambos de severidad baja-media) |
| Bypass con ejecución real confirmada | Sí — NUEVO-1 (SQLi) |

Los 16 hallazgos de las cuatro revisiones previas siguen cerrados: los
comprobé yo mismo, no solo leí que lo estaban. El fix de IA-1 (el bypass
universal por `/*...*/`) es sólido para las diez familias que no son
`sqli`. Pero al combinar ese mismo fix con otros vectores encontré **dos
casos nuevos, mucho más estrechos que el original**: uno en la propia
familia `sqli` (el fix de IA-1 no le añadió la segunda lectura que sí dio a
las demás) y uno en la descompresión de `Content-Encoding` recién añadida
(solo deshace un nivel). Ninguno de los dos tiene el alcance del hallazgo
original — uno afecta a una sola familia, el otro requiere una
infraestructura con doble compresión, poco habitual—, pero ambos son reales
y están demostrados con ejecución.

---

## Hallazgos

### NUEVO-1 — Un SQLi que cabe entero dentro de un comentario `/*...*/` sin versionar se blanquea

**Gravedad:** Media · **Vector:** query, body o cabecera, familia `sqli` únicamente

**Qué pasa**

El fix de IA-1 le dio a diez familias una segunda lectura sobre el texto
**sin** pasar por `_strip_sql_comments` (para que `<script>`, `{{7*7}}`,
etc. sigan siendo visibles aunque estén envueltos en un comentario SQL). A
la familia `sqli` **no** se le añadió esa segunda lectura, porque
normalmente necesita ver el comentario desenvuelto para cazar
`uni/**/on/**/select`. El problema aparece cuando el atacante envuelve el
**payload entero** en un `/*...*/` no versionado (uno que no empieza por
`!`): `_strip_sql_comments` lo sustituye por un único espacio, y como
`sqli` solo mira esa vista «stripped», no le queda nada que detectar.

**Impacto (medido)**

Contra una app con una consulta SQL cruda por concatenación (`SELECT name
FROM users WHERE name = '{q}'`, SQLite en memoria):

```
name=' OR '1'='1                                    -> 403 (control)
name=/*x' UNION SELECT password FROM users -- */     -> 200 (pasa el middleware)
```

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python .audit/PACK-REVISOR/ejecutar_pocs.py final_sqli_envuelto
```

**Qué se rompe**

Un atacante que sepa del fix de IA-1 (o simplemente pruebe la misma
técnica que ya le funcionó para las otras diez familias antes del parche)
sigue teniendo una vía para `sqli` específicamente, aunque mucho más
estrecha que el bypass universal original.

**Corrección propuesta**

Aplicar a `sqli` el mismo patrón de doble lectura que ya tienen las otras
diez: evaluarla también sobre el texto sin desenvolver cuando la primera
pasada (con comentarios desenvueltos) no detecta nada. Es extender a la
familia que faltó la misma solución que el proyecto ya aplicó a las otras
diez, no una regla nueva.

**Estado:** pendiente

---

### NUEVO-2 — `Content-Encoding: gzip`/`deflate` solo deshace un nivel de compresión

**Gravedad:** Baja · **Vector:** body con doble compresión

**Qué pasa**

La descompresión añadida tras IA-3 (`middleware.py`, alrededor de la línea
478) llama a `zlib.decompressobj()` una sola vez. Un body comprimido dos
veces (`gzip(gzip(payload))`) se descomprime a datos que siguen siendo
binarios no-JSON, así que no se inspecciona ningún campo.

**Impacto (medido)**

```
gzip(ataque) simple                    -> 403 (control: la descompresión de 1 nivel funciona)
gzip(gzip(ataque))                     -> 200
```

Contra una app que también descomprime dos veces (infraestructura con doble
compresión, poco habitual pero posible con ciertos proxies/CDN mal
configurados), el ataque llega intacto: lo comprobé reconstruyendo el JSON
original tras el doble `gzip.decompress()`.

**PoC**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py final_gzip_doble
```

**Qué se rompe**

Nada en el caso normal (Starlette/FastAPI no descomprimen el body por
cuenta propia, con o sin middleware de por medio). Solo importa si tu
propia infraestructura aplica compresión doble, lo cual es inusual y
normalmente un error de configuración en sí mismo.

**Corrección propuesta**

Repetir la descompresión en un bucle acotado (máximo 2-3 iteraciones,
mismo límite de tamaño en cada una) hasta que el resultado deje de empezar
por una cabecera gzip/zlib reconocible, o documentar explícitamente que
solo se deshace un nivel.

**Estado:** pendiente (severidad baja; no bloquea el veredicto)

---

## Lo que esta revisión confirmó que sigue bien (verificado por mí, no solo leído)

- **IA-1 sigue cerrado en las 7 familias no-sqli**, incluso combinado con
  comentarios anidados (`/*/*...*/*/ `) y con la variante versionada
  (`/*!00000...*/`, que correctamente se desenvuelve y sí se detecta).
- **La bomba de descompresión de un nivel está bien acotada**: 50 MB
  descomprimidos de un body de 51 KB comprimidos se cortan en 8 ms con un
  pico de memoria de 0,3 MB (`zlib.decompressobj().decompress(body,
  max_length)` limita la salida, no solo la entrada).
- **`exclude_fields` (AG-5) ya no excluye subárboles enteros**: un ataque
  bajo `bio.nested` se bloquea, el propio `bio` se excluye como se pide, y
  `biography` (nombre parecido) no se excluye por error.
- **El analizador de ReDoS de `custom_rules` (`redos.py`) rechazó las 6
  variantes de patrón catastrófico que le probé**: `(a+)+$`, alternancia
  solapada, clases de caracteres solapadas, grupos con *flags* en línea,
  anidamiento `(a*)*b` y referencias hacia atrás repetidas.
- **La fusión de cabeceras duplicadas (AG-6) no introduce falsos
  positivos**: dos `Cookie` benignas que, concatenadas, podrían parecer un
  ataker (`x=javascript` + `:alert(1)`) no disparan ninguna regla.
- **Los JSON en UTF-16/UTF-32 (con y sin BOM) ya se detectan** (AG-4),
  mandados como `application/octet-stream`.
- **El CLI (`gatekeeper report`) sigue sin emitir bytes de control** con un
  log que lleva secuencias ANSI y de título de terminal.
- Un *boundary* multipart con comilla mal escapada que a primera vista
  parecía una divergencia resultó no serlo: Starlette tampoco puede parsear
  ese body (500), así que no hay ninguna app real a la que explotarle esa
  diferencia.

---

## Veredicto

**Puntuación: 86/100.**

No es 97: dos hallazgos nuevos siguen abiertos, uno de ellos con ejecución
de SQLi real demostrada. Pero son hallazgos de un calibre muy distinto al
que motivó la revisión anterior — uno afecta a una familia de las once, el
otro a una configuración de infraestructura poco común — y el proyecto
tiene ahora cinco auditorías independientes, 38 PoC históricas en verde y
una disciplina de verificación que pocos proyectos de una persona alcanzan.

**¿Lo recomiendo a otros desarrolladores?** Sí, con una condición: arreglar
NUEVO-1 antes de depender de la familia `sqli` contra inyecciones SQL
reales (es el hallazgo que de verdad importa de los dos). Mientras tanto,
`monitor_only=True` durante una o dos semanas, como ya recomienda vuestra
propia documentación, dejaría ver si ese patrón concreto aparece en tráfico
real antes de depender de él en bloqueo.

Dadle el mismo tratamiento que a los 16 anteriores: test de regresión
primero, parche después, y verificación con `ejecutar_pocs.py` en verde.
Con NUEVO-1 cerrado, no tengo reparo en poner esto por encima de 90.
