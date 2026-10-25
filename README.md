# Gatekeeper

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Docs](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/docs.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Middleware ASGI de seguridad para FastAPI/Starlette: rate limiting, cabeceras
seguras, detección de patrones de ataque en query y body, reglas propias por YAML
y auditoría en JSON. **Una capa adicional** delante de tu app, no un WAF ni una
sustitución de la validación de entradas.

> **El proyecto activo es v0.3**, y vive en
> [`gatekeeper-v0.3/gatekeeper/`](gatekeeper-v0.3/gatekeeper/). Es la única
> versión que se publica y que recibe mantenimiento.
>
> Las carpetas `v0.1` y `v0.2` se conservan **solo como referencia
> histórica**: no reciben correcciones (incluidas las de seguridad) y sus
> README avisan de que no se instalen. La política por rama está en
> [Compatibilidad y soporte](gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

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

Para comprobar en tu propia máquina que bloquea lo que debe, la
[guía de inicio rápido](gatekeeper-v0.3/gatekeeper/docs/inicio-rapido.md) te da
los dos `curl` que verifican que una petición normal da 200 y un ataque da 403.
Para decidir **dónde** desplegarlo, la
[guía de despliegue](gatekeeper-v0.3/gatekeeper/docs/despliegue.md) dice qué
valor cambia en cada topología (un proceso, varios workers, Docker, proxy
inverso).

## Qué mide (no qué promete)

Tres corpus, todos con guarda en CI:

| Métrica | Corpus propio (159 + 81) | **Retenido** (109 + 90) | OWASP CRS externo (1379 tests) |
|---|---|---|---|
| Ataques detectados | **100.0%** (159/159) | **94.5%** (103/109) | **41.0%** (465/1135, familias 930/941/942) |
| Falsos positivos sin documentar | **0** | **0** | 4.7% (11/232 negativos de CRS, línea base) |

El **retenido** se escribió una vez sin mirar las firmas de las reglas y desde
entonces solo se mide: por eso da un número más bajo que el propio (94,5% frente
a 100%). Esa diferencia es información, no un defecto — es lo que separa "las
reglas detectan esto" de "las reglas detectan lo que se escribieron para ellas".

El detalle y los payloads que escapan están en
[corpus/REPORT.md](gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) y
[corpus/HELDOUT.md](gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md). La evaluación
opt-in query/body se publica por separado en
[corpus/CROSS_REPORT.md](gatekeeper-v0.3/gatekeeper/corpus/CROSS_REPORT.md);
no se mezcla con estas cifras ni es una evaluación retenida. Publicar el número
bajo del corpus ajeno es tan importante como el alto del propio.

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
