# Gatekeeper

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Docs](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/docs.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Middleware ASGI de seguridad para FastAPI/Starlette: rate limiting, cabeceras
seguras, detección de patrones de ataque en query y body, reglas propias por YAML
y auditoría en JSON. **Una capa adicional** delante de tu app, no un WAF ni una
sustitución de la validación de entradas.

> El proyecto activo es **v0.3**, que vive en
> [`gatekeeper-v0.3/gatekeeper/`](gatekeeper-v0.3/gatekeeper/).
> Las carpetas `v0.1` y `v0.2` se conservan como referencia histórica.

## Empezar

Gatekeeper todavía **no está publicado en PyPI**: se publicará cuando se decida
de forma explícita. Instálalo desde el repo:

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
pip install ./Gatekeeper/gatekeeper-v0.3/gatekeeper
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
```

Hay una **demo** con playground de payloads y GIF de una sesión real en
[`gatekeeper-v0.3/gatekeeper/demo/`](gatekeeper-v0.3/gatekeeper/demo/)
(despliegue en un comando con Vercel o Docker).

## Qué mide (no qué promete)

Dos corpus, uno propio y otro externo, ambos con guarda en CI:

| Métrica | Corpus propio (159 + 81) | OWASP CRS externo (1379 tests) |
|---|---|---|
| Ataques detectados | **100.0%** (159/159) | **34.7%** (394/1135, familias 930/941/942) |
| Falsos positivos sin documentar | **0** | — (3.9% sobre los negativos de CRS, línea base) |

El detalle y los payloads que escapan están en
[corpus/REPORT.md](gatekeeper-v0.3/gatekeeper/corpus/REPORT.md). Publicar el
número bajo del corpus ajeno es tan importante como el alto del propio.

## Documentación

- **Guía**: <https://eche-dev.github.io/Gatekeeper/> (se publica desde
  [`docs/`](gatekeeper-v0.3/gatekeeper/docs/) en cada push a `main`; `mkdocs serve` en local)
- [README completo](gatekeeper-v0.3/gatekeeper/README.md) ·
  [Contribuir](CONTRIBUTING.md) ·
  [Seguridad](gatekeeper-v0.3/gatekeeper/SECURITY.md) ·
  [Changelog](gatekeeper-v0.3/gatekeeper/CHANGELOG.md)

## Licencia

MIT © [Ángel David Echenique Villanueva (Eche-Dev)](https://github.com/Eche-Dev).
El corpus externo de OWASP CRS conserva su licencia Apache-2.0 con atribución
incluida.
