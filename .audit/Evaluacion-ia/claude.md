# Auditoría de Gatekeeper 0.4.0 — 74/100

> ## Veredicto
> Es un proyecto muy por encima de la media para una sola persona, pero hoy no lo recomendaría en producción. Un solo request de 128 KB bloquea el servidor 21 segundos, y con el tamaño de body que admites por defecto (1 MiB) serían unos 20 minutos. Está corregido en un parche que te dejo, y con él el proyecto pasa de 74 a unos 83.

Instalé el `0.4.0` desde PyPI en un entorno limpio y lo ataqué como caja negra, además de pasar todos los controles de calidad sobre el código del repo. Leí a fondo la ficha de PyPI y tres páginas de la web (inicio, inicio rápido y seguridad). El resto de las páginas solo las vi en el menú. No pude abrir GitHub Pages por `curl` desde mi sandbox.

---

## Puntuación

| Área | Nota |
| :--- | ---: |
| Seguridad del propio código (DoS, bypasses) | `11/20` |
| Calidad de detección y reglas | `15/20` |
| Tests, CI y tipado | `14/15` |
| Documentación | `11/15` |
| Publicación y supply chain | `9/10` |
| Estructura del repo y mantenibilidad | `5/10` |
| Método de medición y honestidad | `9/10` |
| **Total** | **`74/100`** |

---

## ✅ Lo que tienes muy bien

1. **Pipeline de publicación de nivel profesional:** Trusted Publishing, attestations verificadas en PyPI, actions fijadas por SHA, comprobación de que el tag coincide con la versión y `--only-binary`.

2. **2.436 tests pasando**, más `hypothesis`, `mypy` estricto, `bandit`, y un test diferencial del prefiltro que garantiza que no se pierden detecciones.

3. **Tres corpus** (propio, retenido y OWASP CRS) con un 41 % externo publicado sin maquillar. Eso te distingue de casi todo lo parecido.

4. **Mejoras desde mi revisión anterior:** `X-Forwarded-For` se lee ya de derecha a izquierda, se inspeccionan cabeceras, hay packs de reglas, `exclude_fields` y `gatekeeper report`. Con `text/plain` ya no hay bypass.

5. **Cobertura de familias:** NoSQL, comandos, SSRF, SSTI, CRLF, Log4Shell y proto-pollución detectan bien en mis pruebas.

---

## 🐛 Fallos reales (todos reproducidos)

### 🔴 Crítico

**DoS cuadrático con una sola petición.**

En `normalize()`, `re.sub(r"/\*.*?\*/", ..., DOTALL)` recorre el resto del texto por cada `/*` sin cierre. Medí **5,2 s con 64 KB** y **20,9 s con 128 KB** de `/*a`, frente a **0,077 s** con texto normal. La petición ni siquiera se bloquea (devuelve `200`) y bloquea el event loop. Contradice tu página de Seguridad, que dice que todos los cuantificadores están acotados.

- **Cómo arreglarlo:** el parche sustituye la regex por un barrido lineal con `str.find`. En 1 MiB hostil el peor caso baja a `0,62 s`. Pasan los 2.134 tests y los tres corpus dan exactamente las mismas cifras (100 %, 0 FP, 41,0 %, 4,7 %).
- **Qué hacer:** publica `0.4.1` y abre un GitHub Security Advisory, porque es un DoS sin autenticación en un paquete de seguridad ya publicado.

### 🟠 Alto

**WebSocket sin protección.**

El handshake con SQLi se acepta y no se aplica rate limit: con `rate_limit=1` entraron 6 conexiones. Pasa porque `scope["type"] != "http"` se deja pasar sin tocar.

**`application/octet-stream` se salta la inspección.**

Un JSON enviado así no se escanea, y una app con `request.json()` lo parsea igual. Haz un *sniff* del primer byte (`{`, `[`).

**Multipart sin inspeccionar** (documentado, pero es una de las superficies más atacadas).

`filename=../../etc/passwd` y los campos de texto pasan.

**Coste con tráfico legítimo.**

Un JSON de 1 MiB sin ataque tardó 2,2 s en mi sandbox, y `re` no suelta el GIL, así que un hilo no lo arregla. Baja el `max_body_size` por defecto y pon un presupuesto de strings por petición.

### 🟡 Medio

**Memoria del rate limiter.** 300.000 IPs distintas ocuparon 258 MB, sin tope. Añade un máximo de claves y agrupa IPv6 por `/64`.

**El log no cumple lo que promete la web.** Dice *"nunca el contenido del payload"*, pero `path` se escribe entero y `field` incluye claves JSON controladas por el atacante.

**Inyección en la terminal del operador.** `gatekeeper report` imprime los bytes ESC/BEL del log tal cual, y una clave JSON maliciosa puede cambiar el título de la terminal. Hay que sanitizar la salida.

**Puntero JSON incorrecto con más de 64 niveles.** `_child_pointer` nunca añade el segmento, así que la atribución del campo es errónea y `exclude_fields` no casa (falso positivo). No encontré bypass de seguridad.

**Claves JSON duplicadas:** `json.loads` descarta la primera, lo que da una discrepancia si algo aguas abajo usa la primera.

**Falsos negativos:** `' or ''=`, booleano ciego (`substring(version(),1,1)=5`), inyección de comandos con salto de línea e IP decimal en SSRF.

**Falsos positivos:** `<script>` en prosa, *"1=1 in math"* y `sleep(8 hours)`.

---

## 📚 Documentación

### Bien

- Estructura clara, tono honesto y un inicio rápido con prueba `200`/`403`.
- Modelo de amenazas por familia y guías de despliegue y operación.

### Mal

- **Páginas desactualizadas:** el inicio rápido dice *"todavía no está en PyPI"* y Seguridad lista la `0.3.x` como activa.
- **Enlaces de la ficha de PyPI:** los del README apuntan a `pypi.org/project/gatekeeper-asgi/corpus/...`, y PyPI no sirve archivos del repo. El anti-bot de PyPI me impidió comprobarlo con `curl`, pero es lo esperable. Usa URLs absolutas.
- **Frase cortada y typo:** *"Comparar rendimiento… en la misma máquina:"* termina sin bloque de código, y hay un *"exímino"*.
- **Solo en español:** para que sirva a la comunidad global necesita un README en inglés.
- **Email personal (gmail) expuesto** en la web y en los metadatos. Usa GitHub Advisories.
- **README de PyPI demasiado largo:** deja lo esencial y mueve el resto a la web.

---

## 📦 Repo y mantenibilidad

- Siguen las carpetas `v0.1`, `v0.2` y `v0.3` en la raíz. Lo normal es `src/`, `tests/` y `docs/` en la raíz y las versiones en tags.
- Hay restos sueltos: `anchor_check.py` y `link_check.py` en la raíz, `PLAN-100-PUNTOS…md`, y `app_servidor.py` dentro del sdist. El sdist pesa 430 KB porque incluye demo, corpus y artículos.
- Los comentarios del código narran incidentes enteros, y eso va en el CHANGELOG o en `SECURITY_REVIEW`.
- Mezclas *pointer* con segmentos y puntero en los identificadores, y el puntero JSON ocupa unas 120 líneas. Basta con el último segmento y la profundidad.
- `__init__.py` tiene un 43 % de cobertura.

---

## 🛠️ Orden que seguiría

1. Aplicar el parche, publicar `0.4.1` y el advisory.
2. Cerrar WebSocket, `octet-stream`, claves duplicadas y el multipart (al menos `filename` y nombres de campo).
3. Poner límites de coste: `max_body_size` por defecto más bajo, presupuesto de strings, tope de IPs en memoria y agrupación IPv6.
4. Sanitizar la salida del CLI y corregir las frases falsas de la web.
5. Refrescar la documentación, hacer el README en inglés y limpiar el repo.
6. Añadir un test de complejidad para cada familia de entradas hostiles, para que el tiempo crezca de forma lineal. Habría atrapado el DoS de arriba.

> **Con 1 a 3 hechos, el proyecto ya sería fiable para producción.**
> Aplícalo con `git apply fix-redos-comentarios-sql.patch`, que lleva incluido su test de regresión.
