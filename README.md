# Gatekeeper

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Docs](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/docs.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

**Gatekeeper es un middleware ASGI de seguridad para FastAPI y Starlette.** Se
coloca delante de tu aplicación y, en cada petición, hace tres cosas:

1. **Limita el tráfico** por IP (ventana deslizante, en memoria o compartida en Redis).
2. **Añade las cabeceras de seguridad** que tu app debería servir y que nadie
   se acuerda de poner (`nosniff`, `HSTS`, `X-Frame-Options`…).
3. **Busca patrones de ataque** en la ruta, la query string, las cabeceras y el
   body: SQLi, XSS, path traversal, NoSQL, comandos del sistema, SSRF, SSTI,
   CRLF, Log4Shell y proto-pollución.

Es **una capa más** de defensa en profundidad, no un WAF: no sustituye a las
consultas parametrizadas ni a la validación de entradas. Y no promete "no te
van a atacar": **publica cuánto detecta y cuánto se equivoca**.

> **La versión publicada es la 0.8.x**, y su código vive en
> [`gatekeeper-v0.3/gatekeeper/`](gatekeeper-v0.3/gatekeeper/) — el nombre de
> la carpeta es histórico y no coincide con la versión del paquete. Es la única
> versión que se publica y que recibe mantenimiento.
>
> Las carpetas `v0.1` y `v0.2` se conservan **solo como referencia
> histórica**: no reciben correcciones (incluidas las de seguridad) y sus
> README avisan de que no se instalen. La política por rama está en
> [Compatibilidad y soporte](gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).
>
> **In English: [README.en.md](gatekeeper-v0.3/gatekeeper/README.en.md)**

## Por qué existe

- **Una IP puede pedirlo todo.** Sin límite de peticiones, un bucle contra tu
  login es un ataque de fuerza bruta y un crawler es un DDoS.
- **Las cabeceras de seguridad no se ponen solas.** Basta un microservicio
  olvidado.
- **Un campo sin validar es una puerta.** Una búsqueda o un filtro que acaba
  en una consulta o en una plantilla se convierte en inyección si nadie lo
  revisa.

Gatekeeper los cubre **en un punto, delante de tu app**, sin tocar endpoint por
endpoint.

## Empezar

```bash
pip install gatekeeper-asgi             # núcleo
pip install "gatekeeper-asgi[yaml]"     # + configuración por YAML
pip install "gatekeeper-asgi[redis]"    # + rate limit compartido entre workers
```

O desde el repositorio:

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper
pip install ./gatekeeper-v0.3/gatekeeper
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
```

Para comprobar en tu propia máquina que bloquea lo que debe, la
[guía de inicio rápido](gatekeeper-v0.3/gatekeeper/docs/inicio-rapido.md) te da
los dos `curl` que verifican que una petición normal da 200 y un ataque da 403.
Para decidir **dónde** desplegarlo, la
[guía de despliegue](gatekeeper-v0.3/gatekeeper/docs/despliegue.md) dice qué
valor cambia en cada topología (un proceso, varios workers, Docker, proxy
inverso).

## Qué mide (no qué promete)

Tres corpus, todos con guarda en CI (si una regla nueva los empeora, el
workflow falla):

| Métrica | Corpus propio (159 + 131) | **Retenido** (109 + 140) | OWASP CRS externo (1379 tests) |
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

## El repositorio por dentro

| Qué | Dónde |
|---|---|
| El paquete que se publica en PyPI | [`gatekeeper-v0.3/gatekeeper/`](gatekeeper-v0.3/gatekeeper/) |
| La documentación (fuente de la web) | [`gatekeeper-v0.3/gatekeeper/docs/`](gatekeeper-v0.3/gatekeeper/docs/) |
| Los corpus y sus informes | [`gatekeeper-v0.3/gatekeeper/corpus/`](gatekeeper-v0.3/gatekeeper/corpus/) |
| La demo (playground de payloads) | [`gatekeeper-v0.3/gatekeeper/demo/`](gatekeeper-v0.3/gatekeeper/demo/) |
| Cómo se trabaja aquí | [`AGENTS.md`](AGENTS.md) · [el plan por fases](PLAN-VERIFICADO-100.md) |

## Documentación

- **Guía**: <https://eche-dev.github.io/Gatekeeper/> (se publica desde
  [`docs/`](gatekeeper-v0.3/gatekeeper/docs/) en cada push a `main`; `mkdocs serve` en local)
- [README completo](gatekeeper-v0.3/gatekeeper/README.md) ·
  [README in English](gatekeeper-v0.3/gatekeeper/README.en.md) ·
  [Contribuir](CONTRIBUTING.md) ·
  [AGENTS.md](AGENTS.md) (cómo se trabaja en el repo) ·
  [Seguridad](gatekeeper-v0.3/gatekeeper/SECURITY.md) ·
  [Changelog](gatekeeper-v0.3/gatekeeper/CHANGELOG.md)

## Licencia

MIT © [Ángel David Echenique Villanueva (Eche-Dev)](https://github.com/Eche-Dev).
El corpus externo de OWASP CRS conserva su licencia Apache-2.0 con atribución
incluida.
