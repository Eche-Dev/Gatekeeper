# Corpus retenido (held-out)

Este corpus existe para una sola cosa: **medir si las reglas generalizan**, no
si las reglas se acuerdan de los casos con los que se escribieron.

## El problema que resuelve

El corpus de desarrollo (`attacks.json`, `benign.json`) se puede usar para
**ajustar** las reglas. Cada vez que se añade una firma, se comprueba que
detecta el caso que motivó la firma. Al final, el 100% de ese corpus mide
memoria: las reglas se han literally escritos para pasar esos casos.

Un corpus retenido rompe ese bucle. Se escribe **una vez**, sin mirar las
firmas de las reglas, y a partir de ahí **solo se mide**.

## Los ficheros

| Fichero | Contenido | Tamaño |
|---|---|---|
| `heldout_attacks.json` | Ataques que las reglas deberían detectar | 109 |
| `heldout_benign.json` | Tráfico legítimo que no debería bloquearse | 90 |

Informe generado: [`HELDOUT_REPORT.md`](HELDOUT_REPORT.md).

## Cómo se escribieron

- **Sin consultar las firmas.** Los payloads se escribieron desde las
  *técnicas* de ataque (no desde los patrones de Gatekeeper): qué hace un
  `GROUP BY 3` para enumerar columnas, qué es un `INTO OUTFILE`, cómo se ve
  una Expression Language de Spring.
- **Sin copiar el corpus de desarrollo.** Las técnicas se solapan (las reglas
  tienen que cubrir clases de ataque, no instancias), pero los payloads
  concretos son distintos: no se reutilizó ninguno.
- **Con cobertura de las 11 familias** que Gatekeeper afirma cubrir, y con
  **codificación, bypass y variantes** que el corpus de desarrollo no tenía:
  `%uXXXX`, doble codificación, backticks, `onerror` sin comillas, `mutación
  mXSS`, `PROCEDURE ANALYSE`, `INTO OUTFILE`, `GROUP BY n`, `HAVING`, `$or`,
  `$exists`, `T(java.lang.Runtime)`, `constructor`/`prototype` separados por
  una clave JSON, logs de nginx, `docker.sock`, `pg_hba.conf`, `.htpasswd`.
- **Tráfico benigno realista**: filtros, paginación, órdenes, consultas de
  búsqueda, URLs de blog, emails, emojis, acentos, fechas en la ruta, y
  endpoints que devuelven payloads **como valor** (un `/api/test`).

## Cifras

| Métrica | Corpus de desarrollo | Corpus retenido |
|---|---|---|
| Ataques detectados | 159/159 (100%) | **103/109 (94,5%)** |
| Falsos positivos no documentados | 0 | **0** |
| Falsos positivos documentados | 5 | 4 |
| Falsos negativos documentados | 0 | 6 |

!!! info "Por qué el retenido da 94,5% y no 100%"
    Porque es **más difícil a propósito**: incluye técnicas que las reglas no
    cubren, y esas están marcadas con `documented_miss` y con su motivo. Un
    100% aquí significaría que el corpus retenido se ajustó, que es
    exactamente lo que no debe pasar.

    El umbral de CI está en **85%**, no en 100%, por la misma razón: es una
    guarda de regresión, no una promesa. Si alguien añade un payload nuevo al
    retenido, CI no debe ponerse rojo por eso.

## Reglas de uso

1. **No se ajusta para que pase.** Si una regla nueva hace bajar la detección
   en el retenido, se documenta el motivo (como los 6 `documented_miss`) o se
   acepta el coste en el informe. No se añaden payloads nuevos para "cubrir"
   un fallo: el retenido se congela.
2. **Los payloads que se escapan van con motivo.** Un `documented_miss` sin
   explicación no vale: o se arregla la regla, o se explica por qué no se
   puede.
3. **Los FP de tráfico legítimo se arreglan.** Un falso positivo sobre tráfico
   real (no sobre un payload servido como valor) es un bug de las reglas, no un
   límite. Uno de esos apareció aquí y se corrigió (ver abajo).
4. **El informe se regenera**, no se edita a mano:
   `python tools/evaluate_heldout.py --write-report`.

## Lo que este corpus ya encontró

Al aplicarlo sobre las reglas de v0.3.1 aparecieron **13 detecciones que
fallaban** y **1 falso positivo sobre tráfico legítimo**:

- **13 huecos de detección**: `GROUP BY n` y `HAVING` (sondeo de columnas),
  `INTO OUTFILE`, `IF()` condicional, `PROCEDURE ANALYSE`, logs de nginx,
  `docker.sock`, `pg_hba.conf`, `.htpasswd`, `$or` y `$exists` de MongoDB,
  Expression Language de Spring (`${T(java.lang.Runtime)...}`) y
  `constructor`/`prototype` separados por una clave JSON.
  Todos se corrigieron **midiendo**: `+13` detecciones en el retenido, `+0`
  falsos positivos en el corpus de desarrollo y en los negativos de CRS.

- **1 falso positivo real**: la regla `\d{4}/\d{2}/\d{2}/` (que busca volcados
  con fecha en la ruta) saltaba con **cualquier ruta con fecha**, incluidos los
  slugs de blog (`/blog/2026/01/15/titulo`). Eso habría bloqueado artículos
  legítimos en cualquier blog. El corpus de desarrollo no lo detectó porque no
  tenía ni un caso con fecha en la ruta. Corregido exigiendo que la ruta
  parezca un volcado (`backup/2024/01/15/`, `.../2024/01/15/x.sql`).

!!! warning "Esto no es una promesa de que no haya más"
    El corpus retenido mide sobre **109 ataques y 90 peticiones legítimas**.
    Es una muestra, no un censo. Un corpus retenido pequeño no cubre todas las
    técnicas ni todos los patrones de tráfico real: la conclusion honesta es
    "estas 109 técnicas y estos 90 patrones se comportan así", no "el
    detection es completo".

## Diferencia con el corpus de desarrollo

| | Desarrollo | Retenido |
|---|---|---|
| Para qué | ajustar las reglas | medirlas |
| Se puede editar | sí, al añadir una firma | **no**: se congela |
| Attacas a las reglas | no | **sí**: es su trabajo |
| Cifra publica | 100% (es la promesa) | **94,5%** (es la medida) |

El corpus de desarrollo se publica como la promesa del proyecto ("nuestro
corpus: 159/159"). El retenido se publica como la **medida de generalización**,
que es un número más bajo y más informative.

## Relacionado

- [`README.md`](README.md) — procedencia y licencia de los corpus.
- [`REPORT.md`](REPORT.md) — informe del corpus de desarrollo.
- [`CROSS_REPORT.md`](CROSS_REPORT.md) — informe del modo cruzado (opt-in).
- [`HELDOUT_REPORT.md`](HELDOUT_REPORT.md) — informe de este corpus.
