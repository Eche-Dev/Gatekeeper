# Borrador del GitHub Security Advisory — 0.4.1

> Para pegar en <https://github.com/Eche-Dev/Gatekeeper/security/advisories/new>.
> El advisory se puede guardar como **borrador** (privado) mientras se
> publica el fix, y se publica cuando la 0.4.1 esté en PyPI.

---

## Título (summary)

`DoS cuadrático en la normalización de comentarios SQL (Gatekeeper 0.4.0)`

## Descripción

`normalize()` en `gatekeeper/rules.py` eliminaba los comentarios SQL con:

```python
re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
```

El cuantificador `.*?` es *no greedily* pero la búsqueda **no está acotada**: por
cada `/*` **sin cierre**, el motor de regex recorre el resto del texto hasta
encontrar un `*/` o llegar al final. Como no hay cierre, **cada `/*` recorre el
texto entero**, de modo que el coste total crece como **O(n²)**.

Como el motor `re` de CPython **no suelta el GIL**, el cálculo no se puede
ejecutar en un hilo aparte: **bloquea el event loop completo** del worker
ASGI mientras dura.

Una petición HTTP basta paraarlo. El caso más simple es un `POST` con
`Content-Type: text/plain` y el cuerpo formado por `/*a` repetido, que es
texto perfectamente válido para cualquier aplicación.

La petición **no se bloquea**: el middleware responde `200`. El ataque no
evita la inspección, simplemente congela el servicio mientras el regex
recorre.

Este fallo **no estaba en las reglas** de detección, sino en la
*normalización* previa, que es la etapa que se aplica a **todo** lo que entra
(la ruta, la query, las cabeceras y el body). Por eso le afecta cualquier
petición, no solo las que parecen un ataque.

## Impacto

- **Disponibilidad**: un atacante **sin autenticación** puede bloquear el
  event loop de un worker durante minutos con una sola petición.
- Con el `max_body_size` por defecto de **1 MiB**, el peor caso medido es de
  **~25 minutos de CPU por petición**.
- Con varios workers, una única petición puede bloquearlos **todos** a la vez.
- **Sin impacto** en confidencialidad ni integridad: no se ejecuta código, no
  se modifican datos y no se devuelven secretos.

### Mediciones (Python 3.14.8, CPU de portátil)

| Tamaño del body | 0.4.0 | 0.4.1 | Factor |
|---|---:|---:|---:|
| 8 KB | 0,084 s | 0,000 s | — |
| 16 KB | 0,333 s | 0,001 s | ×333 |
| 32 KB | 1,351 s | 0,002 s | ×675 |
| 64 KB | 5,509 s | 0,005 s | ×1.100 |
| 128 KB | **23,587 s** | **0,009 s** | **×2.620** |

Duplicar el tamaño multiplicaba el tiempo por **4** (curva cuadrática); con el
arreglo lo multiplica por **2** ( lineal). End-to-end, una sola `POST` de 64 KB
pasaba de **5,5 s** a **0,008 s**.

## PoC

```bash
python - <<'PY' > /tmp/poc.bin
import sys
sys.stdout.buffer.write(b"/*a" * 21845)   # ~64 KB
PY

time curl -s -o /dev/null -w 'HTTP %{http_code} en %{time_total}s\n' \
  --data-binary @/tmp/poc.bin \
  -H 'Content-Type: text/plain' \
  http://127.0.0.1:8000/
```

Con la 0.4.0 la respuesta es `HTTP 200` tras ~5,5 s (y ~25 s con 128 KB), con
el servidor congelado mientras tanto.

## Mitigación

**Actualizar a 0.4.1.** Es la solución real: el coste pasa a ser lineal y
128 KB dejan de tardar 23 s.

Si no se puede actualizar de inmediato:

1. Bajar `max_body_size` (por ejemplo a 64 KiB) — acota el peor caso.
2. Limitar el ritmo de peticiones con el rate limit.
3. Rechazar en el proxy los cuerpos con `Content-Type: text/plain` en las rutas
   que solo aceptan JSON.

## Corrección

Los dos `re.sub` se sustituyen por un barrido **lineal** con `str.find`
(`_strip_sql_comments()` en `gatekeeper/rules.py`), que conserva la semántica
original:

- `/*!50000union*/` se sigue **desenvolviendo** a ` union ` (MySQL ejecuta el
  contenido de los comentarios versionados: borrarlo lo volvería invisible);
- `/*!50000` con más de 200 caracteres de contenido se trata como comentario
  normal;
- un `/*` **sin cierre** se deja tal cual y se deja de buscar;
- `/**/` se convierte en un espacio.

La regresión está cubierta por `tests/test_redos_comentarios.py`, que exige
que el coste crezca **linealmente** con el tamaño de la entrada (y no solo que
«no tarde mucho»).

Las cifras de detección **no cambian**: corpus propio 159/159, corpus retenido
94,5 % con 0 falsos positivos no documentados, OWASP CRS 41,0 % de detección y
4,7 % de falsos positivos, modo cruzado 7/7.

## Versiones afectadas

- `= 0.4.0` (única versión publicada hasta la fecha; 0.3.x nunca se publicó).

## Versión corregida

- `0.4.1`

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → **7.5 (Alta)**

## Referencias

- Corrección: <https://github.com/Eche-Dev/Gatekeeper/commit/c81f023>
- Notas de la release: <https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/RELEASE_NOTES_0.4.1.md>
- Política de seguridad: <https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md>
- Paquete: <https://pypi.org/project/gatekeeper-asgi/>

## Créditos

Detectado y corregido por el autor del proyecto durante una revisión interna
de seguridad, con el informe completo y los scripts de reproducción en el
repositorio (`AUDITORIA-2026-10-25.md` y `.audit/`).
