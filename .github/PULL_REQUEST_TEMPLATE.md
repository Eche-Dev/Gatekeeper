## Qué cambia y por qué

<!-- Explica el problema que resuelve. Si hay issue, enlázalo: Fixes #NN -->

## Tipo

- [ ] Corrección de un error
- [ ] Funcionalidad nueva
- [ ] Regla de detección nueva o modificada
- [ ] Documentación o tooling

## Checklist

- [ ] `ruff check .`, `mypy` y `bandit -r src -q` limpios (desde `gatekeeper-v0.3/gatekeeper`)
- [ ] Tests nuevos para el cambio y `pytest --cov=gatekeeper` ≥ 90%
- [ ] `python tools/evaluate.py --check` en verde: la detección no baja y no aparecen
      falsos positivos sin documentar (corpus propio **y** externo de CRS)
- [ ] Si toca reglas: firma genérica (no un caso concreto), cuantificadores acotados
      (`\s{0,16}`, nunca `\s*` adyacentes) y probado contra tráfico benigno
- [ ] Límites aceptados documentados en el corpus (`known_fp` / `documented_miss`), no ocultados
- [ ] `CHANGELOG.md` actualizado
- [ ] `README.md` / `docs/` actualizados si cambia el comportamiento
