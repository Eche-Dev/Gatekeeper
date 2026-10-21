# Desarrollo

## Entorno

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper/gatekeeper-v0.3/gatekeeper
pip install -e ".[dev]"
```

Python 3.10+ (el CI prueba 3.10–3.12). El proyecto vive en
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
| `python benchmarks/latency.py` | Latencia por petición por escenario |
| `python -m build && twine check dist/*` | Empaquetado |

## Estructura

| Carpeta | Contenido |
|---|---|
| `src/gatekeeper/` | El middleware: `middleware`, `config`, `rules`, `body`, `paths`, `ratelimit` |
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

## Documentación

```bash
mkdocs serve      # en local con recarga
mkdocs build --strict
```

La publicación es el job `deploy` del workflow **Docs**: corre al etiquetar un
tag (`git tag v0.3.0 && git push --tags`) o manualmente desde la pestaña
Actions. Requiere **Settings → Pages → Source: GitHub Actions** en el repo.
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
4. PyPI es una decisión explícita del mantenedor, no un paso automático.
