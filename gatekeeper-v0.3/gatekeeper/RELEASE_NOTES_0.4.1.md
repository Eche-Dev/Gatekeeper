# Gatekeeper 0.4.1

## Qué es

Una release **de seguridad**. Corrige un DoS de disponibilidad sin
autenticación que afectaba a la 0.4.0 (publicada en PyPI el 25 de octubre de
2026). No cambia la API ni el comportamiento de la detección: **los números
de detección son idénticos**.

## Qué cambia

### Corregido: DoS cuadrático al normalizar comentarios SQL

`normalize()` eliminaba los comentarios SQL con
`re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)`. Por cada `/*` **sin
cierre**, el motor de regex recorría el resto del texto, así que el coste
crecía como **O(n²)**. Como `re` no suelta el GIL, el **event loop completo
quedaba bloqueado**.

Medido sobre la 0.4.0:

| Body | CPU por petición | Estado HTTP |
|---|---:|---|
| 8 KB | 0,084 s | 200 |
| 32 KB | 1,351 s | 200 |
| 64 KB | **5,509 s** | **200** |
| 128 KB | **23,587 s** | **200** |

Duplicar el tamaño multiplicaba el tiempo por **4** (curva cuadrática limpia).
Con el `max_body_size` de 1 MiB por defecto, una sola petición podía bloquear
el servidor **~25 minutos**. Y lo peor: **la petición devolvía 200**, así que
el ataque no se bloqueaba, simplemente congelaba el servicio.

**Reproducción mínima:**

```bash
# 64 KB de "/*a" sin cerrar -> ~5,5 s de CPU y un 200
curl -s -o /dev/null -w '%{time_total}\n' \
  --data-binary @<(python -c "print('/*a'*21845, end='')") \
  -H 'Content-Type: text/plain' https://tu-servidor/
```

**La corrección**: los dos `re.sub` se sustituyen por un barrido **lineal** con
`str.find` (`_strip_sql_comments()`). Conserva la semántica original:

- `/*!50000union*/` se sigue **desenvolviendo** a ` union ` (MySQL ejecuta el
  contenido: borrarlo lo volvería invisible);
- `/*!50000` con más de 200 caracteres de contenido se trata como comentario
  normal;
- un `/*` **sin cierre** se deja tal cual y se deja de buscar;
- `/**/` se convierte en un espacio.

**El resultado**: 128 KB pasan de **23,587 s a 0,009 s** (×2.600) y el tiempo
crece de forma **lineal** (×2 por duplicación, antes ×4). Un body legítimo de
1 MiB se sigue procesando en ~0,78 s: no se ha tocado el camino caliente.

**La regresión** (`tests/test_redos_comentarios.py`) no solo comprueba que
«no tarde mucho»: exige que el coste **crezca linealmente** con el tamaño de
la entrada, que es lo que habría atrapado este fallo.

### Sin cambios en la detección

Verificado con los tres corpus, antes y después del arreglo:

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | 159/159 (100 %) | 0 no documentados |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

## Migración desde 0.4.0

**No hay nada que hacer.** La API pública no cambia, no hay deprecaciones y no
hay migraciones de configuración. Es un `pip install --upgrade`:

```bash
pip install --upgrade gatekeeper-asgi
```

Si usas `requirements.txt` o `pyproject.toml` con la versión fijada, actualiza
el pin a `gatekeeper-asgi==0.4.1`.

### Si no puedes actualizar todavía

1. Baja `max_body_size` (por ejemplo a 64 KiB) — reduce mucho el peor caso.
2. Limita el número de peticiones por segundo con el rate limit.
3. **Descarta el `Content-Type: text/plain`** en las rutas que acepten JSON: el
   caso más fácil de explotar es un `POST` textual con el cuerpo formado por
   `/*a` repetido.

## Compatibilidad

Sin cambios: Python 3.10–3.14, Starlette 0.23.0–1.10.0, FastAPI
0.103.2–0.162.0, uvicorn/hypercorn/daphne y Redis 5.0/7.2. La matriz completa
y **medida** está en [docs/compatibilidad.md](docs/compatibilidad.md).

## Instalación

```bash
pip install gatekeeper-asgi          # núcleo
pip install "gatekeeper-asgi[yaml]"   # + configuracion desde YAML
pip install "gatekeeper-asgi[redis]"  # + rate limit distribuido
```

Desde el repositorio: `pip install ./gatekeeper-v0.3/gatekeeper`.

## Qué NO cubre

Sin cambios respecto a 0.4.0, y conviene tenerlo presente al desplegar:

- **WebSocket**: el middleware solo aplica a peticiones `http`. Los handshakes
  y los frames de WebSocket **no se inspeccionan ni se limitan**.
- **`multipart/form-data`**: no se inspecciona el cuerpo.
- **Tipos MIME binarios** (`application/octet-stream`, imágenes, etc.): no se
  inspeccionan.
- Las reglas son **detección de patrones**, no sustituto de consultas
  parametrizadas, validación de entrada ni autorización.

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

Este DoS ya está corregido y publicado; su ficha está en
[SECURITY.md](SECURITY.md), en la sección «Vulnerabilidades corregidas».
