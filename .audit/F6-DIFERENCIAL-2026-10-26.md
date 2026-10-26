# F6.4 — Tests diferenciales del body (y el bypass del `+` que encuentras)

**Fecha:** 2026-10-26 · **Fase:** 6 (validación externa), punto 4

## Qué se quería

El plan (punto 4 de la fase 6) pide:

> Tests diferenciales contra apps reales: FastAPI y Starlette en varias
> versiones, con distintos comportamientos de parsing, para demostrar que el
> middleware y la app **interpretan el body igual** (o documentar dónde no).

Nadie lo comprobaba. El middleware lee el body para inspeccionarlo y se lo
reinyecta a la aplicación (`read_body` + `replay`). Si los dos interpretaran
el body de forma distinta, el middleware inspeccionaría una cosa y la app usaría
otra: eso es un **bypass** (el payload pasa por el campo que el middleware no
vio) o un **falso positivo** (el middleware bloquea lo que la app no iba a
usar).

## El bypass

Lo encontró el propio test diferencial, en su segunda comprobación (la del
**marcador**).

El `+` significa **espacio** en una query string: así lo parsea el servidor, y
así se trataba desde la 0.7.0 (la traducción ocurre solo en la primera ronda
de decodificación, para que `sleep(10%2B6)` llegue a las reglas con su `+`).

En un **body** o en una **cabecera** no es así: para la aplicación, un `+` es un
carácter **literal**, y el operador de MySQL en `sleep(10+6)` lo es. El
middleware lo traducía igual, así que inspeccionaba `sleep(10 6)` mientras la
app usaba `sleep(10+6)`.

Reproducción (`.audit/f6_bypass_mas.py`, contra el código real):

| entrada | lo que ve la app | lo que inspeccionaba el middleware | antes |
|---|---|---|---|
| form `q=sleep(10%2B6)` | `sleep(10+6)` | `sleep(10 6)` | **200 (bypass)** |
| json `{"q":"sleep(10+6)"}` | `sleep(10+6)` | `sleep(10 6)` | **200 (bypass)** |
| query `?q=sleep(10%2B6)` | `sleep(10+6)` | `sleep(10+6)` | 403 (ya bien) |

Un `sleep(10+6)` en MySQL duerme 16 segundos: el time-based SQLi funcionaba.

La causa, en el código: `body.py` extrae los valores del formulario con
`parse_qsl` (que ya decodificó el `%2B` a `+`), y `rules.normalize()` volvía a
aplicar `unquote_plus` sobre ese texto ya decodificado: el `+` se convertía en
espacio por segunda vez.

## El arreglo

El `+` se lee de las **dos** formas —como espacio y como literal— en todo lo
que no viene de una query string:

- `normalize(value, plus=False)`: no traduce el `+`;
- `scan_detailed()` (la API pública) lee las dos formas, porque un `scan()`
  no sabe de dónde sale el valor;
- el middleware usa `scan_plus_as_space()` para la ruta y la query (la lectura
  de siempre) y `scan_detailed()` para el body y las cabeceras.

## Medido (no supuesto)

| corpus | antes | después |
|---|---|---|
| propio | 159/159 (100 %) | **160/160 (100 %)** (el payload nuevo es `sleep(10+6)`) |
| retenido | 103/109 (94,5 %) | 103/109 (94,5 %) |
| CRS (externo) | 465/1135 (41,0 %) | 465/1135 (41,0 %) |
| FP sobre los negativos de CRS | 11/232 (4,7 %) | 11/232 (4,7 %) |

**No se pierde ninguna detección.**

### Coste

El segundo escaneo solo ocurre si el valor tiene un `+`. Medido en la misma
máquina, antes y después (`f6_bench_mas_antes.json` /
`f6_bench_mas_despues.json`):

| escenario | antes | después | delta |
|---|---|---|---|
| body con un `+` | 209,3 µs | 244,6 µs | **+17 %** |
| inspección de body JSON | 231,4 µs | 232,2 µs | +0 % |
| solo cabeceras | 18,4 µs | 18,7 µs | +2 % |
| carga grande (100 KB) | 8233,4 µs | 8125,9 µs | −1 % |

El benchmark tiene ese escenario, así que el guard del CI lo vigila.

## El test diferencial

`gatekeeper-v0.3/gatekeeper/tools/diferencial_body.py` es la **fuente única**.
Tres comprobaciones, contra Starlette y FastAPI:

1. **IGUALDAD** — la app ve **exactamente** lo mismo con y sin middleware (26
   cuerpos borde: JSON con BOM, JSON malformado, forms con campos duplicados,
   multipart con fichero, `text/plain`, sin `content-type`, `octet-stream`…).
2. **MARCADOR** — el middleware inspecciona el valor que la app usa. Se mide
   con una regla propia que solo casa con el valor que la app ha declarado y
   con **todas las reglas integradas desactivadas**: si el middleware
   inspeccionara otra cosa, la petición pasaría. **Es la que encontró el
   bypass.**
3. **ATAQUES** — 12 payloads bloqueados, con la regla esperada y su evento de
   auditoría.

El test de pytest llama a las mismas funciones, y la **matriz de compatibilidad**
lo ejecuta dentro de un venv con cada versión de Starlette y FastAPI: el
diferencial se mide **en cada versión**, no solo con la última.

### En cada versión

`.audit/f6_compat_diferencial.json` (matriz completa, 10/10 con el diferencial
en verde):

| framework | versiones |
|---|---|
| Starlette | 0.23.0, 0.27.0, 0.37.0, 0.41.3, 0.46.2, última |
| FastAPI | 0.103.2, 0.110.3, 0.115.6, última |

### Verificado que el test NO es vacío

Contra el código **sin** el arreglo (`git stash` de `rules.py` y
`middleware.py`), el diferencial falla con **10 fallos** (5 por framework):

```
  - starlette/form con %2B (el mas es literal): el middleware NO ha inspeccionado
    el valor que usa la app ('sleep(10+6)'); el patron 'sleep\\(10\\+6\\)' no casaba
  - starlette/json con + crudo: el middleware NO ha inspeccionado ...
  - starlette/text/plain con +: ...
  - starlette/sqli con el mas literal en un form: el middleware dejo pasar el
    payload (estado 200)
  - starlette/sqli con el mas literal en json: ...
  (+ los 5 de fastapi)
```

## El límite que queda (y no es un bypass)

Una aplicación que parsea el body por su cuenta de una forma que el
`Content-Type` no anuncia ve cosas que el middleware no puede ver: el
content-type es lo único que le dice cómo inspeccionar. Eso no lo arregla un
test, lo arregla decir el content-type correcto. Está documentado en
`docs/amenazas.md`.

En los venv viejos, `request.form()` exige `python-multipart` incluso para un
formulario urlencoded: sin él, la propia app no sabe parsear el body y el caso
no es medible. El diferencial lo **dice** (no lo cuenta como fallo ni como
verde) y la matriz instala `python-multipart` para que sí se mida.

## Cómo reproducirlo

```bash
cd gatekeeper-v0.3/gatekeeper
python tools/diferencial_body.py            # el diferencial, sin pytest
python tools/compat_matrix.py --json        # la matriz (crea un venv por versión)
python .audit/f6_bypass_mas.py               # la reproducción del bypass
```

## Lo que NO cubre

- La **revisión de seguridad independiente** (los puntos 1, 5 y 6 de la fase 6):
  la tiene que escribir alguien que no haya ajustado las reglas.
- El modo **cruzado** (`inspect_cross_carrier`): ahí el texto del body se une
  al de la query y se normaliza una sola vez, así que el `+` del body se
  traduce a espacio en ese paso. Los valores del body se escanean igual en
  individual (con las dos lecturas), así que un payload que depende solo del
  body no se escapa; lo que se podría escapar es un payload **repartido**
  entre query y body que necesite el `+` literal del body. Es un modo opt-in
  y apagado por defecto.
