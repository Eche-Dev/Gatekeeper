# Seguridad

## Modelo de amenazas

**En alcance** — lo que Gatekeeper intenta mitigar:

- Fuerza bruta y abuso de API a nivel de IP (rate limiting).
- Once familias de inyección con firma reconocible en query, cabeceras
  inspeccionadas y body textual: SQLi, XSS, path traversal, ficheros
  sensibles, NoSQL, comandos del sistema, SSRF, SSTI, CRLF, Log4Shell y
  proto-pollución de JavaScript. La combinación opcional entre ruta/query y
  valores textuales del body requiere `inspect_cross_carrier=True`.
- Content sniffing y secuestro de framing (cabeceras).

**Fuera de alcance** — para lo que NO sirve, dicho claro:

- Autenticación, autorización y lógica de negocio.
- Ataques al propio servidor ASGI, a la red o a la base de datos.
- Validación semántica de entradas (eso es de tu app).
- Firma de peticiones, CSRF tokens, gestión de secretos.
- Ataques repartidos entre query y body cuando `inspect_cross_carrier=False`,
  entre query y cabeceras, o dentro de bodies multipart.

El desglose **familia a familia, con la frontera de falsos positivos de cada
una**, está en [Modelo de amenazas](amenazas.md).

Gatekeeper es una capa más de defensa en profundidad. Tu app sigue necesitando
consultas parametrizadas y validación.

## Capas de defensa

| Capa | Mecanismo |
|---|---|
| Red/proxy | `trust_proxy` con lectura XFF de derecha a izquierda (`trusted_proxies` / `trusted_proxy_cidrs`) y `blocked_ips` (IP o CIDR) |
| Abuso | Rate limiting por IP, memoria o Redis atómico |
| Transporte | Límite de body (256 KiB → 413 si el tamaño declarado o leído lo supera) y presupuestos de campos y de tiempo de inspección |
| Contenido | Normalización (3 rondas, `%uXXXX`, NFKC) + reglas acotadas |

## Políticas de fallo

| Fallo | Política | Efecto |
|---|---|---|
| Redis no responde | `rate_fail_open=True` (defecto) | Se admite y se audita `rate_backend_error` |
| Redis no responde | `rate_fail_open=False` | 503, disponibilidad sacrificada |
| Configuración inválida | Siempre | `ValueError` al arrancar, nunca protección silenciosamente ausente |
| Body sin `Content-Length` | Se lee con límite | 413 solo si el stream supera `max_body_size` |

La decisión de *fail open* o *fail closed* es tuya y está en la configuración,
no escondida en el código.

## ReDoS: la historia honesta

**v0.3** midió un **backtracking cuadrático real**: dos cuantificadores de
blancos adyacentes (`\s*[(']?\s*`) en las reglas de SQLi hacían que `or` +
80.000 espacios consumiera **118 s de CPU por petición** — un DoS con bodies
de 1 MiB. La respuesta fue:

- acotar **todos** los cuantificadores de las reglas integradas (`\s{0,16}`) → lineal;
- test de regresión con entradas patológicas de 1M de caracteres;
- tests de propiedades con **hypothesis** (`tests/test_fuzz.py`) que fallan si
  alguien reintroduce `\s*` adyacente o mete una excepción nueva.

**v0.4.0 tenía un segundo cuadrático, y no estaba en las reglas.** El
`normalize()` eliminaba los comentarios SQL con
`re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)`: por cada `/*` **sin cierre**
el motor recorría el resto del texto. Medido sobre 0.4.0: **23,6 s con
128 KB** y **5,5 s con una sola petición de 64 KB**, que además devolvía 200 y
bloqueaba el event loop; con el `max_body_size` de 1 MiB eran **~25 minutos de
CPU por petición**. El caso más fácil es un `POST` con
`Content-Type: text/plain` y el cuerpo formado por `/*a` repetido.

Por qué lo pasó por alto el arreglo de v0.3: aquel iba sobre los
**cuantificadores de las reglas**, y este estaba en la **normalización**, que
no es una regla. La lección que queda escrita aquí: *"acotar todos los
cuantificadores"* no es una garantía si el coste puede crecer en otro sitio.

**v0.4.1** sustituye los dos `re.sub` por un barrido **lineal** con `str.find`
(`_strip_sql_comments()`), conservando la semántica: los comentarios
versionados de MySQL (`/*!50000union*/`) se siguen **desenvolviendo** porque
MySQL los ejecuta, y un `/*` sin cierre se deja tal cual. Con el arreglo,
128 KB tardan **0,009 s** y el tiempo crece de forma lineal. La regresión
(`tests/test_redos_comentarios.py`) exige que el coste crezca **linealmente**,
no solo que «no tarde mucho». Detalle completo y PoC en
[SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md).

Las reglas personalizadas del usuario se **validan al arrancar**: el riesgo
de backtracking exponencial se rechaza con `ValueError` y el cuadrático se
avisa en el log. Si necesitas un patrón que no se puede acotar, pon
`allow_unsafe_custom_rules=True` (queda avisado).

## Auditoría sin fugas

El logger `gatekeeper` registra eventos (regla, ruta, IP, tamaño del body)
pero **nunca los valores de los payloads**: no se vuelca el texto que|matcheó|
la regla, así que un log de Gatekeeper no se puede usar para robar tokens
interceptados. En modo monitor puedes medir falsos positivos sin bloquear y
sin volcar credenciales.

!!! warning "El nombre del campo sí es dato del atacante"
    El evento incluye `field`: el **nombre** del parámetro o el puntero JSON.
    Ese nombre lo elige el atacante, así que puede acabar en el log (acotado a
    256 caracteres). Los **valores** no se registran nunca; los **nombres** sí.
    Si vas a mandar estos logs a un tercero, tenlo en cuenta.

    Todo el texto que se registra va además **saneado**: sin ESC ni otros
    caracteres de control. Sin eso, un `\x1b[2J` en la URL podría borrar la
    pantalla del operador que abre el log (o reescribir el título de su
    ventana).

!!! note "El puntero JSON se recorta"
    El campo que aparece en la auditoría es un puntero JSON (`/users/0/bio`).
    Si la ruta es muy profunda, se recorta a 256 caracteres y se marca con
    `…`: se conservan el primer segmento (la clave exterior) y el último (el
    campo concreto), pero el tramo intermedio se pierde.

    El motivo es un DoS medido: sin recorte, un body de 83 KiB con 14.100
    niveles de anidamiento consumía **193,6 MiB** por petición. Ver
    [SECURITY_REVIEW.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md).

    `exclude_fields` sigue funcionando con punteros recortados: compara por el
    último segmento y por el primero.

## Versiones soportadas

| Versión | Estado |
|---|---|
| 0.4.x | Activa |
| 0.3.x, 0.2.x, 0.1.x | Históricas, sin soporte (0.3.x nunca se publicó en PyPI) |

## Reportar una vulnerabilidad

Usa **[GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new)**
para reportar de forma privada: es la vía que permite corregir y publicar el
fix antes de que el fallo sea público. No abras un issue con un fallo
explotable. Ver también
[SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md)
en el repo.

---

Siguiente: [Referencia (API) →](api.md)
