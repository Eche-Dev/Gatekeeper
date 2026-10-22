# Política de seguridad

## Versiones soportadas

| Versión | Soportada |
|---|---|
| 0.3.x | ✅ |
| < 0.3.0 | ❌ (sin publicar en PyPI aún) |

## Cómo reportar una vulnerabilidad

Usa [GitHub Security Advisories](../../security/advisories/new) para reportar de
forma privada. No abras un issue público con un fallo explotable.

Contesta dentro de 72 horas y coordino el fix y la publicación contigo. Si
prefieres, incluye un payload que reproduzca el fallo y el escenario en el que
salta (query, body, backend Redis, etc.).

## Modelo de amenazas: qué defiende Gatekeeper

Gatekeeper es una **capa adicional** delante de tu app ASGI. Su objetivo es
detección y registro, no sustitución de controles fundamentales.

**En alcance:**

- Ataques HTTP automatizados que llegan por ruta, query string o body
  JSON/form-urlencoded: SQLi, XSS, path traversal y descubrimiento de ficheros
  sensibles. `inspect_cross_carrier=True` combina ruta/query con valores
  textuales del body; está desactivado por defecto.
- Abuso de recursos por volumen: rate limiting por IP (memoria o Redis).
- Exposición de información por cabeceras de respuesta.

**Fuera de alcance (no lo intenta, no lo promete):**

- Autenticación, autorización o gestión de sesiones.
- Consultas parametrizadas: **si concatenas SQL con entradas del usuario, ninguna
  capa de detección te salva**. Es el control nº 1 y va en tu código.
- Contenido `multipart/form-data`, tráfico cifrado, ataques a nivel de red,
  ataques de denegación de servicio distribuidos, o lógica de negocio.
- Ataques repartidos entre query y body si `inspect_cross_carrier=False`,
  entre query y cabeceras, o dentro de bodies multipart.

## Decisiones de diseño y su porqué

- **`trust_proxy=False` por defecto**: confiar en `X-Forwarded-For` sin un proxy
  de confianza permite falsificar la IP y saltarse el rate limit y el bloqueo.
  Con `trust_proxy=True` el header se lee **de derecha a izquierda**
  (`ips[-trusted_proxies]`, la entrada que añadió tu proxy, no la que escribe el
  cliente) y, si la app es alcanzable saltándose el proxy, define
  `trusted_proxy_cidrs` para ignorar el XFF de peers que no son tuyos.
- **`rate_fail_open=True` por defecto**: si Redis cae, se sigue sirviendo
  tráfico. Cambia a `False` si tu prioridad es rechazar en vez de servir (503).
- **Los logs de auditoría nunca contienen el payload**: registran la regla que
  saltó, el campo (JSON pointer o parámetro), el patrón que lo disparó y el
  origen, no el contenido. Un log con payloads es un vector de
  inyección de log y expone datos de usuarios.
- **Regex con cuantificadores acotados**: todos los cuantificadores de las reglas
  integradas van con límite (`\s{0,16}`). En v0.3 se encontró, con la batería de
  rendimiento, un ReDoS cuadrático real (`or` + 80.000 espacios = 118 s de CPU);
  está corregido y cubierto por tests con entradas patológicas de 1M de
  caracteres y por tests de propiedades con hypothesis. Las reglas personalizadas
  **no** están acotadas: revisa las tuyas.
- **Validación al arrancar**: una clave con typo (`rate_limt`) o una regex
  inválida rompe el arranque, no la protección en producción. Los tests de
  propiedades verifican que solo salen `ValueError`/`TypeError`, nunca errores
  sorpresa.

## Requisito fundamental

Gatekeeper reduce superficie de ataque y te avisa. No convierte una aplicación
que concatena SQL en una aplicación segura.
