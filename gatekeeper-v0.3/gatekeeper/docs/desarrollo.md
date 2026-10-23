# Desarrollo

## Entorno

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper/gatekeeper-v0.3/gatekeeper
pip install -e ".[dev]"
```

Python 3.10+ (el CI prueba 3.10–3.13). El proyecto vive en
`gatekeeper-v0.3/gatekeeper/`; `v0.1` y `v0.2` son históricas.

## Comandos

| Comando | Qué hace |
|---|---|
| `ruff check .` | Estilo |
| `mypy` | Tipos estrictos (`src/gatekeeper`, target 3.10) |
| `bandit -r src -q` | Análisis estático de seguridad |
| `pytest --cov=gatekeeper` | Tests + fuzzing, cobertura ≥ 90% |
| `python tools/evaluate.py --check` | Tasas de detección y FP (corpus propio + CRS) |
| `python tools/import_crs.py --check` | Procedencia del corpus externo |
| `python benchmarks/latency.py` | Latencia p50/p95/p99 por petición y escenario |
| `python benchmarks/latency.py --baseline <json>` | Compara con una Medición previa (misma máquina) |
| `python -m build && twine check dist/*` | Empaquetado |

## Estructura

| Carpeta | Contenido |
|---|---|
| `src/gatekeeper/` | El middleware: `middleware`, `config`, `rules`, `body`, `paths`, `ratelimit`, `cli` |
| `tests/` | Unitarios, `test_corpus.py`, `test_crs_corpus.py`, `test_fuzz.py` |
| `corpus/` | `attacks.json`, `benign.json`, `crs_payloads.json` (CRS, Apache-2.0) e informes |
| `tools/` | `evaluate.py` (medición) e `import_crs.py` (importador de CRS) |
| `benchmarks/` | `latency.py` |
| `docs/` | Esta documentación (MkDocs Material) |

## Tests: tres capas

1. **Unitarios** — comportamiento por componente, incluida la resistencia a
   ReDoS con entradas patológicas de 1M de caracteres.
2. **Corpus** — `evaluate.py` dentro de pytest: la detección no puede bajar del
   90% ni aparecen FP sin documentar; lo mismo con la línea base de CRS.
3. **Propiedades (hypothesis)** — `tests/test_fuzz.py`: entradas arbitrarias
   (unicode, percent-encoding, bytes) sobre `scan`, `normalize`,
   `extract_strings`, `Config` y `allow_paths`. Invariantes: nada revienta,
   `normalize` es idempotente, y una ruta con `..` **nunca** se exime.

## Latencia: medir, no construir un guard automático

`benchmarks/latency.py` mide **percentiles por petición real** (p50/p95/p99), no
medias por ronda: la media escondía la cola, que es lo que nota un usuario. El
mismo escenario que la media rondaba los ~90 µs tiene un p95 de 123 µs.

### C⁠omo comparar dos versiones

```bash
python benchmarks/latency.py --save base.json
# ... cambia el código ...
python benchmarks/latency.py --baseline base.json    # sale 1 si empeoró más del margen
```

El margen por defecto es 25 %. Compara el **overhead** (lo que añade el
middleware sobre la línea base de la misma corrida), no el absoluto.

### El pre filtro de familias

Antes de evaluar las 60 regex, Gatekeeper comprueba si el texto contiene algún
literal de cada familia (`script`, `union`, `/etc/`…) con una búsqueda de
subcadena. Si no, esa familia se salta entera. La normalización cuesta ~5 µs;
el resto eran regex de Python sobre texto inocuo.

Se midieron cuatro enfoques y solo uno gana, porque la diferencia entre ellos es
de 2× a 4×:

| Enfoque | Coste medido | Veredicto |
|---|---|---|
| 11 `search`, uno por familia | ~12 µs | se come el ahorro |
| `finditer` con alternancia gigante | 15 µs corto, 80 µs largo | crea un objeto por coincidencia |
| `search` con grupos por familia, en bucle | ~30 µs | el bucle se come todo |
| **`lit in texto` (el implementado)** | **~1 µs** | `in` sobre `str` es C puro |

Al añadirlo, el test que compara con y sin pre filtro sobre los dos corpus
encontró **12 discrepancias** (literales mal escritos que habrían perdido
detecciones). Esa es la razón de que exista `tests/test_prefilter.py`: la
optimización solo es aceptable si se puede demostrar que no cambia el
resultado.

### Por qué no corre en CI

Se implementó un guard automático con umbral en µs y **se eliminó al medir que
no podía ser fiable**. En un runner de CI con CPU compartida, el ruido de la
máquina supera a la señal:

| Situación | Overhead p50 medido |
|---|---|
| Portátil sin carga | 73 µs |
| Runner de CI saturado | 220–312 µs |
| Regresión real (200 firmas nuevas) | 175 µs |

Una máquina lenta da un overhead mayor que una regresión de código: ningún
umbral los separa. El guard solo podría dar falsos positivos en cada build o
ser ciego a regresiones moderadas. La decisión y sus datos están también en el
`ci.yml`, para que nadie lo reintroduzca sin conocer la razón.

El benchmark sigue siendo la herramienta: publicar la cola real y comparar
antes/después localmente. Automatizarlo exigiría un runner con CPU fijada.

## Documentación

```bash
mkdocs serve      # en local con recarga
mkdocs build --strict
```

La publicación es el job `deploy` del workflow **Docs**: corre en cada push a
`main`, al etiquetar un tag o manualmente desde la pestaña Actions. Requiere
**Settings → Pages → Source: GitHub Actions** en el repo.
`--strict` hace que un enlace roto rompa el build en CI.

## Añadir una regla

El proceso completo (firma genérica, medición, cuantificadores acotados,
documentar límites) está en
[CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md).
Resumen: cámbiala en `rules.py`, ejecuta `evaluate.py` y los tests, y añade los
casos benignos que no deben saltar.

## Release

1. `CHANGELOG.md` (Keep a Changelog) y versión en `pyproject.toml`.
2. Batería completa verde (el checklist del PR).
3. `git tag vX.Y.Z && git push --tags` → publica docs.
4. Crear la release en GitHub → dispara el workflow `publicar.yml`, que
   valida y publica en PyPI.

### Publicar en PyPI (Trusted Publishing)

**No hay ningún token de PyPI en los secretos del repo.** GitHub demuestra su
identidad a PyPI con OIDC y PyPI emite un token de publicación de un solo uso.
Lo único que puede publicar con tu nombre es quien pueda modificar el repo.

El workflow valida antes de publicar: que la versión del tag coincida con
`pyproject.toml`, que el paquete importe y que la CLI funcione. Para probarlo
sin publicar nada, desde la pestaña Actions: **Publicar en PyPI → Run workflow →
`dry_run` = true**.

Configuración inicial (una sola vez, a mano):

1. Crear el proyecto `gatekeeper-asgi` en PyPI.
2. Añadir un publisher **GitHub Actions** con repositorio `Eche-Dev/Gatekeeper`
   y workflow `publicar.yml`.
3. La primera versión hay que subirla a mano con un token de API (OIDC no crea
   el proyecto en PyPI, solo publica en uno que ya existe) y borrar el token
   después.

### Auditar dependencias

`pip-audit` corre en el job `audit` de CI sobre el runtime y el entorno de
desarrollo, en venvs limpios. En local, lo mismo:

```bash
python -m venv /tmp/audit && /tmp/audit/bin/pip install dist/*.whl
/tmp/audit/bin/pip install pip-audit
/tmp/audit/bin/pip freeze | grep -v '^-e ' | grep -vi gatekeeper-asgi > /tmp/req.txt
/tmp/audit/bin/pip-audit --strict -r /tmp/req.txt
```

Se filtra el paquete local porque hasta la primera publicación no está en PyPI
y `--strict` sale con error por eso, que no es una vulnerabilidad sino que el
paquete aún no existe.
