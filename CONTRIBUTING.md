# Contribuir con Gatekeeper

Gracias por querer contribuir. Este proyecto se desarrolla **en español**:
issues, PRs y documentación en español; identificadores y nombres de fichero en inglés.

## Antes de empezar

- Si crees que has encontrado una **vulnerabilidad**, no abras un issue público:
  sigue el proceso de [SECURITY.md](gatekeeper-v0.3/gatekeeper/SECURITY.md).
- Revisa los **límites conocidos** antes de reportar un falso positivo o negativo:
  [corpus/REPORT.md](gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) documenta lo que ya
  se mide y se acepta.

## Entorno de desarrollo

Requisitos: Python 3.10 o superior (el CI prueba 3.10, 3.11 y 3.12).

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper/gatekeeper-v0.3/gatekeeper
pip install -e ".[dev]"
```

## Comandos de calidad

Todos se ejecutan desde `gatekeeper-v0.3/gatekeeper`. El mismo juego corre en CI
(Windows o Linux, da igual):

```bash
ruff check .                          # estilo
mypy                                  # tipos estrictos (src/gatekeeper)
bandit -r src -q                      # análisis estático de seguridad
pytest --cov=gatekeeper               # tests + fuzzing con hypothesis
python tools/evaluate.py --check      # tasas de detección y FP (corpus propio + CRS)
python tools/import_crs.py --check    # procedencia del corpus externo
python benchmarks/latency.py          # coste por petición
python -m build && twine check dist/*
```

## Estándares del código

- **`mypy --strict` limpio**, apuntando a Python 3.10 (usar `X | None`, no `Optional`).
- Comentarios y docstrings en español, con el *por qué*, no el *qué*.
- Sin dependencias nuevas sin discussión previa: el núcleo solo pide `starlette`.

## Reglas de detección: el criterio más importante del proyecto

Casi todo el valor de Gatekeeper está en no bloquear tráfico legítimo. Si propones
o modifies una regla:

1. **Firma genérica, no caso concreto.** `union\s{1,32}select` es genérica;
   `24 union all select from aa` es sobreajustar al examen.
2. **Mide antes y después.** `python tools/evaluate.py` tiene que seguir en verde:
   detección ≥ 90% en el corpus propio, **cero** FP sin documentar, y la guarda
   del corpus externo de CRS sin bajar.
3. **Cuantificadores acotados.** Nunca dos `\s*` adyacentes: en v0.3 eso produjo
   un ReDoS cuadrático real (118 s de CPU con 80.000 espacios). Usa `\s{0,16}`.
4. **Los límites se documentan, no se esconden.** Si la regla nueva bloquea algo
   legítimo de forma inevitable, añade el caso a `corpus/benign.json` con
   `known_fp` y explica el motivo; se contará aparte en el informe.
5. Si tocas `rules.py`, `body.py`, `paths.py` o `config.py`, añade propiedades en
   `tests/test_fuzz.py` para las invariantes nuevas.

## Proceso

1. Fork y rama: `feat/xxx` o `fix/xxx`.
2. Cambios con tests y CHANGELOG actualizado.
3. Pull request con la plantilla; CI tiene que estar verde (test, package y docs).
4. Revisión: se prioriza la honestidad de las métricas sobre el número alto.

## Estructura del repo

| Carpeta | Qué es |
|---|---|
| `gatekeeper-v0.3/gatekeeper/` | **Proyecto activo**: código, tests, corpus, docs |
| `gatekeeper-v0.2/`, `gatekeeper-v0.1/` | Versiones anteriores, conservadas como referencia |

Dentro del proyecto: `src/gatekeeper/` (código), `tests/` (unitarios, corpus, fuzzing),
`corpus/` (ataques, benignos y el corpus externo de CRS), `tools/` (evaluador e importador),
`benchmarks/` (latencia) y `docs/` (MkDocs).

## Lanzamientos (mantenedores)

1. Actualizar `CHANGELOG.md` y la versión en `pyproject.toml`.
2. Batería completa en verde (el checklist del PR).
3. `git tag v0.3.0 && git push origin v0.3.0` — el tag publica la documentación
   en GitHub Pages (job `deploy` del workflow Docs).
4. La publicación en PyPI es una decisión explícita, no un paso automático.

## Código de conducta

Al participar aceptas el [Código de conducta](CODE_OF_CONDUCT.md).
