# Gatekeeper 0.4.0

**Primera versión publicada en PyPI.** `pip install gatekeeper-asgi`

## Qué es

Middleware ASGI de seguridad para FastAPI y Starlette: rate limiting, cabeceras
seguras, detección de patrones de ataque en query, cabeceras y body, reglas
propias por YAML y auditoría en JSON.

Una **capa adicional** delante de tu app. No sustituye a las consultas
parametrizadas, ni a la validación de entradas, ni a un WAF de borde.

## Novedades

### Medición que no se puede maquillar

Un **corpus retenido**: 109 ataques y 90 peticiones legítimas escritos **una vez
sin mirar las firmas de las reglas** y desde entonces solo medidos.

| | Corpus de desarrollo | **Retenido** |
|---|---|---|
| Ataques detectados | 159/159 (100%) | **103/109 (94,5%)** |
| Falsos positivos sin documentar | 0 | **0** |

El retenido da un número *más bajo* a propósito: si fuera 100%, significaría
que se ajustó para pasar. El corpus de desarrollo se puede usar para ajustar
las reglas, y eso mide memoria, no generalización.

También hay un corpus retenido para el modo combinado (`inspect_cross_carrier`):
20/20 ataques con la firma partida entre query y body, 0/20 falsos positivos,
frente a 10/20 en modo normal.

### Corregidos: nueve bugs reales

El más importante, por impacto:

**DoS de memoria con cuerpos pequeños.** El puntero JSON que identifica el
campo en la auditoría crecía de forma cuadrática con la profundidad. Medido a
través del middleware real: un body de **83 KiB** con 14.100 niveles
consumía **193,6 MiB** por petición, y 10 peticiones simultáneas llegaban a
**1,9 GiB** y 24 s de CPU, con respuesta 200 (el consumo era invisible).
`max_body_size` no lo acotaba: 83 KiB están muy por debajo de 1 MiB.

Ahora: **7,8 MiB** por petición y **58,3 MiB** con 10 simultáneas.

Los otros ocho:

| Bug | Qué pasaba |
|---|---|
| Redis < 6 no funcionaba | Con la política por defecto, **todas las peticiones pasaban sin rate limit**, en silencio |
| `Retry-After` con un segundo de más | Ventana de 60 s → `Retry-After: 61`. Y los dos backends no coincidían |
| Cabeceras de seguridad ausentes en los rechazos | Un 403 sin `X-Frame-Options` ni HSTS es **más débil** que la de 200 |
| Instalar rompía FastAPI 0.103.x | `pip` subía Starlette y FastAPI dejaba de funcionar |
| Falso positivo: blogs con fecha | `\/blog\/2026\/01\/15\/titulo` bloqueado. Cualquier blog |
| Firmas perdidas en textos largos | El pre filtro solo actúa ≥128 caracteres: funcionaban en cortos y **desaparecían en largos** |
| `...//` se escapaba | Variante clásica de path traversal |
| Body duplicado en memoria | Un body de 8 MiB ocupaba 16 MiB |

### Documentación nueva

- **Guía de inicio rápido**: instalar, añadir el middleware, y los dos `curl`
  que verifican que una petición normal da 200 y un ataque da 403.
- **Guía de despliegue por topología**: qué valor cambia en un proceso, varios
  workers, Docker o detrás de un proxy inverso.
- **Guía operativa**: qué observar, qué alertar, despliegue gradual y rollback.
- **Procedimiento de tráfico real**: cómo medir falsos positivos sobre tu
  tráfico antes de activar el bloqueo, con sus requisitos de autorización.
- **Matriz de compatibilidad medida**: Starlette 0.23→1.10, FastAPI
  0.103→0.162, Python 3.10→3.14, tres servidores ASGI y Redis 5.0/7.2. La
  tabla se genera con `tools/compat_matrix.py`, no se supone.

### Herramientas

- `gatekeeper report`: analiza un log de tráfico y sugiere ajustes.
- `tools/metrics.py`: exporta el log a métricas Prometheus (sin IPs, rutas ni
  payloads: solo conteos).
- `tools/compat_matrix.py`: regenera la matriz de compatibilidad.
- `tools/evaluate_heldout.py`: evalúa el corpus retenido.

### Revisión de seguridad

`SECURITY_REVIEW.md` documenta la revisión por zonas de confianza: un hallazgo
alto (el DoS de arriba, corregido), cuatro aceptados con su justificación y
cinco límites conocidos. **Declara que no es una revisión independiente** (la
hizo quien escribió el código) y qué parte sí lo es.

## Migración desde 0.3.x

No hay cambios obligatorios. Lo que cambia:

| Cambio | Qué hacer |
|---|---|
| El mínimo de Starlette baja a **0.23** | Ninguno. Es ampliar lo soportado: el mínimo anterior (0.37) rompía FastAPI 0.103.x |
| Las cabeceras de seguridad también van en los **rechazos** (403/413/429/503) | Ninguno. Solo se **añaden** cabeceras. Si tu app las ponía también, la suya gana (el middleware no pisa lo que ya venía) |
| El puntero JSON se **recorta** a 256 caracteres | Si parseas punteros completos, deja de poder contar con la ruta entera. `exclude_fields` sigue funcionando |
| `gatekeeper-asgi[servers]` (hypercorn, daphne) | Ninguno. Es un extra nuevo, opcional |

!!! warning "Sobre el recorte del puntero JSON"
    Un JSON con más de 64 niveles de anidamiento produce punteros recortados
    (`/bio/…/nivel`). El motivo es el DoS de arriba. `exclude_fields` compara
    por el primer y el último segmento, así que excluir un campo sigue
    funcionando.

## Compatibilidad

| | |
|---|---|
| Python | 3.10, 3.11, 3.12, 3.13, 3.14 |
| Starlette | 0.23 → 1.10 |
| FastAPI | 0.103 → 0.162 |
| Servidores ASGI | uvicorn, hypercorn, daphne |
| Redis (rate limit compartido) | 5.0, 7.2 |

La matriz completa, **medida**, está en
[docs/compatibilidad.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

## Instalación

```bash
pip install gatekeeper-asgi             # núcleo
pip install "gatekeeper-asgi[yaml]"     # + configuración por YAML
pip install "gatekeeper-asgi[redis]"    # + rate limit compartido entre workers
```

## Qué NO cubre

- Autenticación, autorización o gestión de sesiones.
- Consultas parametrizadas: **si concatenas SQL con entradas del usuario,
  ninguna capa de detección te salva**.
- Contenido `multipart/form-data` ni cuerpos binarios.
- Ataques a nivel de red o denegación de servicio distribuida.

La lista completa, con el porqué de cada punto, está en
[docs/amenazas.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/amenazas.md).

## Reportar un problema

- **Vulnerabilidades**: canal privado, ver
  [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md).
  **No abras un issue público con un fallo explotable.**
- **Errores y features**: [GitHub Issues](https://github.com/Eche-Dev/Gatekeeper/issues).
