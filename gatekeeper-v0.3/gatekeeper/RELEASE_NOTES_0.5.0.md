# Gatekeeper 0.5.0

## Qué es

Cierra **tres bypasses** de la auditoría de seguridad: tres superficies que el
atacante elige (el protocolo, el content-type y el formato del body) por las
que la inspección se esquivaba entera. No añade reglas nuevas ni cambia los
números de detección: **cierra el alcance de las que ya había**.

## Qué cambia

### 1 · WebSocket: el handshake se inspecciona y tiene rate limit

Antes, el middleware salía con `scope["type"] != "http"` y dejaba pasar todo lo
que no fuera HTTP. Un WebSocket no tenía **ni inspección ni rate limit**: con
`rate_limit=1` entraban 6 conexiones de 6, y un handshake como
`/ws?q=union%20select%20password%20from%20users` se aceptaba sin mirar.

Ahora, del handshake se revisan la **ruta, la query y las cabeceras**; la IP
cuenta igual que en HTTP (bloqueo por IP y rate limit); y el handshake
rechazado se cierra con el código **1008** (el servidor responde 403 y el
cliente no entra).

**Lo que sigue fuera**: los **frames**. Llegan después de aceptar la conexión,
y revisarlos exigiría interceptar cada mensaje. Queda documentado como
límite conocido.

```python
Config(inspect_websockets=False)   # vuelve al comportamiento anterior
```

### 2 · `application/octet-stream` se sniffea

El content-type lo controla el atacante, así que no puede ser el que decide.
Un JSON enviado como `application/octet-stream` no se escaneaba, y una app con
`await request.json()` lo parsea igual.

Ahora se mira el **primer byte no blanco** del cuerpo: si es `{` o `[`, el body
se inspecciona como JSON. Los binarios de verdad (`image/png`, `application/pdf`,
`application/zip`…) no se leen: son binarios, y leerlos sería gastar CPU y
memoria a cambio de nada.

### 3 · Multipart: se inspeccionan los nombres de campo y de fichero

Un `multipart/form-data` no se inspeccionaba, y ahí viven los
`filename=../../etc/passwd` y los payloads escondidos en un nombre de campo.

Ahora se revisan los **nombres** (de campo y de fichero) y el **valor de los
campos de texto**. El **contenido** del fichero no: es binario.

El parser es mínimo y conservador, y **no añade dependencias**: si el
multipart no se entiende, devuelve la lista vacía en vez de inventarse una
estructura. Para un parser de RFC 7578 completo está `python-multipart`.

```python
Config(inspect_multipart=False)   # vuelve al comportamiento anterior
```

## Migración desde 0.4.1

**Sin cambios en la API pública**: no hay deprecaciones ni renombrados. La
mayoría de las apps no tienen que tocar nada.

**Un cambio de comportamiento que sí puede afectar**: los bodies
`multipart/form-data` **ahora se leen**, así que les aplica el
`max_body_size` (1 MiB por defecto) como a los demás. Una subida de más de
1 MiB recibe un **413** donde antes pasaba intacta.

Si tu app acepta ficheros grandes, sube el límite:

```python
Config(max_body_size=20 * 1024 * 1024)   # 20 MiB
```

o deja el multipart como estaba:

```python
Config(inspect_multipart=False)
```

Los WebSockets ahora pasan por el rate limit: si tu app legitimately abre
muchas conexiones a la vez desde la misma IP, sube `rate_limit` o pon
`inspect_websockets=False`.

```bash
pip install --upgrade gatekeeper-asgi
```

## Detección: sin cambios

Verificado con los tres corpus, antes y después:

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | 159/159 (100 %) | 0 no documentados |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

**Ninguna regla nueva.** Lo que se ha cerrado es el alcance: las mismas reglas
se aplican ahora a tres superficies más.

## Qué NO cubre

Sin cambios respecto a 0.4.1:

- El **contenido** de los ficheros adjuntos.
- Los **frames** de un WebSocket (sí el handshake).
- Binarios que no son JSON (imagen, PDF, zip…).
- El tráfico entre query y body si `inspect_cross_carrier=False`.
- Autenticación, autorización y consultas parametrizadas: eso va en tu app.

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

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

El DoS de disponibilidad de la 0.4.0 (corregido en la 0.4.1) está en
[SECURITY.md](SECURITY.md), en la sección «Vulnerabilidades corregidas».
