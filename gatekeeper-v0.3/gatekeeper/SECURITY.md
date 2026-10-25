# Política de seguridad

## Versiones soportadas

| Rama | Estado | Recibe correcciones |
|---|---|---|
| 0.4.x | **Activa** | Seguridad, errores y features |
| 0.3.x, 0.2.x, 0.1.x | Históricas | Solo seguridad crítica |

Una versión está soportada si no se rompe a propósito dentro de su major. La
tabla de versiones **medidas** (Python, Starlette, FastAPI, servidores ASGI y
Redis) está en
[Compatibilidad y soporte](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

!!! note "Publicado en PyPI"
    Gatekeeper se instala desde PyPI: `pip install gatekeeper-asgi`. La 0.4.0
    se publicó el 25 de octubre de 2026 y la 0.4.1 corrige un DoS de
    disponibilidad (ver más abajo). Ver
    [Instalación](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/instalacion.md).

## Vulnerabilidades corregidas

Publicamos aquí los fallos de seguridad corregidos, con su versión de
corrección. Cada entrada enlaza al aviso de GitHub correspondiente.

### GHSA — DoS cuadrático en la normalización de comentarios SQL

- **Versiones afectadas:** 0.4.0 (publicada en PyPI)
- **Versión corregida:** 0.4.1
- **Severidad:** alta · **Sin autenticación** · **Impacto:** disponibilidad

`normalize()` eliminaba los comentarios SQL con
`re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)`. Por cada `/*` **sin
cierre**, el motor recorría el resto del texto, de modo que el coste crecía
como O(n²) y `re` no suelta el GIL: el event loop completo quedaba bloqueado.

Medido sobre 0.4.0: **23,6 s con 128 KB** y **5,5 s con una sola petición de
64 KB** (que devolvía 200, sin bloquear el ataque). Con el
`max_body_size` de 1 MiB por defecto, **~25 minutos de CPU por petición**.

**Reproducción mínima:**

```bash
# 64 KB de "/*a" sin cerrar; la respuesta llega 200 tras ~5,5 s de CPU
curl -s -o /dev/null -w '%{time_total}\n' \
  --data-binary @<(python -c "print('/*a'*21845, end='')") \
  -H 'Content-Type: text/plain' https://tu-servidor/
```

**Mitigación para quien no puede actualizar todavía:** baja
`max_body_size` (por ejemplo a 64 KiB) y limita el número de peticiones por
segundo. Actualizar a **0.4.1** es la solución real.

La corrección sustituye los dos `re.sub` por un barrido lineal con
`str.find`, conservando la semántica (los comentarios versionados de MySQL
`/*!50000union*/` se siguen desenvolviendo). La regresión está cubierta por
`tests/test_redos_comentarios.py`, que exige que el coste crezca **linealmente**
y no solo que «no tarde mucho».

## Cómo reportar una vulnerabilidad

Usa [GitHub Security Advisories](../../security/advisories/new) para reportar de
forma privada. No abras un issue público con un fallo explotable.

Contesta dentro de 72 horas y coordino el fix y la publicación contigo. Si
prefieres, incluye un payload que reproduzca el fallo y el escenario en el que
salta (query, body, backend Redis, etc.).

Para errores que **no** son vulnerabilidades (una regla que bloquea tráfico
legítimo, un error de documentación), usa
[GitHub Issues](https://github.com/Eche-Dev/Gatekeeper/issues). Con el evento
de auditoría (`rule`, `field`, `pattern`) se puede arreglar rápido.

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

## Revisión de seguridad

La revisión de la versión actual está en
[SECURITY_REVIEW.md](SECURITY_REVIEW.md): un hallazgo alto (un DoS de memoria
con cuerpos JSON pequeños, ya corregido), cuatro aceptados con su
justificación y cinco límites conocidos.

!!! note "No es una revisión independiente"
    La hizo quien escribió el código, y el informe lo dice. Para una revisión
    de verdad independiente hace falta alguien ajeno al proyecto; el informe
    explica qué parte sí es independiente (las mediciones y las regresiones) y
    cómo reproducir los PoC.
