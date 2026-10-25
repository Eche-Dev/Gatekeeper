# Gatekeeper

> **⚠️ Versión histórica: no instales esto.**
>
> Este directorio es la versión **0.1** de Gatekeeper, que ya **no recibe
> mantenimiento**. La versión actual está en
> [`gatekeeper-v0.3/gatekeeper/`](../gatekeeper-v0.3/gatekeeper/), y es la que
> se publica en PyPI como `gatekeeper-asgi`.
>
> Instalar este código te da una versión sin las correcciones de seguridad
> posteriores (incluido un fallo de DoS por memoria y la incompatibilidad con
> FastAPI antiguo que se corrigieron en 0.3). No hay soporte para esta rama.
>
> Para el estado de cada rama y la política de soporte, ver
> [Compatibilidad y soporte](../gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

Middleware ASGI de seguridad para FastAPI/Starlette. Una capa extra delante de tu app:
rate limiting, cabeceras seguras, detección de patrones de ataque y auditoría en JSON.

```bash
pip install gatekeeper-asgi
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
```

## Qué cubre en v0.1
| Protección | Detalle |
|---|---|
| Rate limiting | Ventana deslizante por IP, en memoria, respuesta 429 + `Retry-After` |
| Cabeceras | nosniff, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy |
| Patrones | SQLi, XSS, path traversal en ruta y query string (con decodificación doble) |
| Auditoría | Eventos JSON en el logger `gatekeeper` |
| Modo monitor | `monitor_only=True` registra sin bloquear, para medir falsos positivos |

## Qué NO cubre
- No inspecciona el body (planeado para v0.2).
- La detección por regex tiene falsos positivos/negativos: **no sustituye** a consultas parametrizadas ni a un WAF.
- El rate limiting es por proceso: con varios workers, cada uno cuenta aparte (Redis en v0.3).
- `trust_proxy=False` por defecto; actívalo solo detrás de un proxy de confianza.

## Desarrollo
```bash
pip install -e ".[dev]"
pytest --cov=gatekeeper
```

Licencia MIT.
