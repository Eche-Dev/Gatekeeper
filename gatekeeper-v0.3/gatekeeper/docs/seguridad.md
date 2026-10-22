# Seguridad

## Modelo de amenazas

**En alcance** — lo que Gatekeeper intenta mitigar:

- Fuerza bruta y abuso de API a nivel de IP (rate limiting).
- Inyección SQLi y XSS con firma reconocible en query y body.
- Path traversal y lectura de ficheros sensibles (`/etc/shadow`, `.env`, claves SSH).
- Content sniffing y secuestro de framing (cabeceras).

**Fuera de alcance** — para lo que NO sirve, dicho claro:

- Autenticación, autorización y lógica de negocio.
- Ataques al propio servidor ASGI, a la red o a la base de datos.
- Validación semántica de entradas (eso es de tu app).
- Firma de peticiones, CSRF tokens, gestión de secretos.

Gatekeeper es una capa más de defensa en profundidad. Tu app sigue necesitando
consultas parametrizadas y validación.

## Capas de defensa

| Capa | Mecanismo |
|---|---|
| Red/proxy | `trust_proxy` con lectura XFF de derecha a izquierda (`trusted_proxies` / `trusted_proxy_cidrs`) y `blocked_ips` (IP o CIDR) |
| Abuso | Rate limiting por IP, memoria o Redis atómico |
| Transporte | Límite de body (1 MiB → 413), también sin `Content-Length` |
| Contenido | Normalización (3 rondas, `%uXXXX`, NFKC) + reglas acotadas |

## Políticas de fallo

| Fallo | Política | Efecto |
|---|---|---|
| Redis no responde | `rate_fail_open=True` (defecto) | Se admite y se audita `rl_backend_unavailable` |
| Redis no responde | `rate_fail_open=False` | 503, disponibilidad sacrificada |
| Configuración inválida | Siempre | `ValueError` al arrancar, nunca protección silenciosamente ausente |
| Body sin `Content-Length` | Siempre | 413 (no se arriesga a leer sin límite) |

La decisión de *fail open* o *fail closed* es tuya y está en la configuración,
no escondida en el código.

## ReDoS: la historia honesta

v0.3 midió un **backtracking cuadrático real**: dos cuantificadores de blancos
adyacentes (`\s*[(']?\s*`) en las reglas de SQLi hacían que `or` + 80.000
espacios consumiera **118 s de CPU por petición** — un DoS con bodies de 1 MiB.
La respuesta fue:

- acotar **todos** los cuantificadores integrados (`\s{0,16}`) → lineal;
- test de regresión con entradas patológicas de 1M de caracteres;
- tests de propiedades con **hypothesis** (`tests/test_fuzz.py`) que fallan si
  alguien reintroduce `\s*` adyacente o mete una excepción nueva.

Las reglas personalizadas del usuario **no** están acotadas: revisa tus
patrones.

## Auditoría sin fugas

El logger `gatekeeper` registra eventos (regla, ruta, IP, tamaño del body)
pero **nunca el contenido de los payloads**. Un log de Gatekeeper no se puede
usar para robar tokens interceptados. En modo monitor puedes medir falsos
positivos sin bloquear y sin volcar credenciales.

## Versiones soportadas

| Versión | Estado |
|---|---|
| 0.3.x | Activa |
| 0.2.x, 0.1.x | Históricas, sin soporte |

## Reportar una vulnerabilidad

Escribe a **angel98dev26@gmail.com** con la descripción, versión/commit y pasos
para reproducir. No abras un issue público. Ver también
[SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md)
en el repo.

---

Siguiente: [Referencia (API) →](api.md)
