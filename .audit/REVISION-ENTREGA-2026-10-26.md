# Revisión de entrega — Gatekeeper 0.7.0 (Fases 3, 4 y 5)

Fecha: 2026-10-26 · Commit revisado: `acf3ec9c` (`main`) · Método: comprobar
contra GitHub, PyPI y la web publicadas; después contra el código del repo.

Esta revisión es de **entrega y coherencia** (¿está todo subido, publicado y
diciendo lo mismo?). **No es** la revisión de seguridad independiente de la
Fase 6: esa la tiene que hacer alguien que no haya escrito el código, y
`SECURITY_REVIEW.md` lo dice explícitamente.

---

## 1. Estado verificado: todo entregado

| Qué | Estado | Evidencia |
|---|---|---|
| `main` contiene todo el trabajo | ✅ | `acf3ec9c` = merge de PR #35; incluye `c2ca7bb` (plan actualizado con F3/F4/F5) |
| PR #34 (Fase 3) | ✅ mergeado | `82a4b55` |
| PR #35 (Fases 4+5) | ✅ mergeado | `acf3ec9c` |
| Tests 3.10 / 3.11 / 3.12 / 3.13 | ✅ | 4 check-runs `success` en `acf3ec9c` |
| Jobs `redis`, `package`, `audit`, `build`, `deploy` | ✅ | `success` |
| `Analyze` (CodeQL) × 2, `update-pip-graph` | ✅ | `success` |
| Job `compat` | ⏭ `skipped` | programado a propósito (`schedule` + `continue-on-error`) |
| Release GitHub v0.7.0 | ✅ publicada | `published_at` 2026-10-26T17:56:57Z |
| Tag `v0.7.0` | ✅ anotado | `a48dd91` (coincide con el commit de release) |
| PyPI `gatekeeper-asgi` 0.7.0 | ✅ publicada | wheel 67.821 B · sdist 493.534 B (17:57:49Z) |
| Web (GitHub Pages) | ✅ desplegada | `https://eche-dev.github.io/Gatekeeper/` con las cifras nuevas (159/159, 103/109, 465/1135) |

**Conclusión de esta parte: la entrega está completa y no queda nada a medias.**

---

## 2. Hallazgos

### H1 · ALTO — La portada de la web declara un mínimo de Starlette que el propio proyecto ya dio por roto

`gatekeeper-v0.3/gatekeeper/docs/index.md:84` (la sección «Requisitos» de la
portada, la primera página que ve quien llega a la web):

```
- [Starlette](https://www.starlette.io/) ≥ 0.37 — FastAPI lo trae ya
```

El resto del repo dice otra cosa:

| Sitio | Qué dice |
|---|---|
| `pyproject.toml` (línea de `dependencies`) | `starlette>=0.23` |
| `docs/compatibilidad.md:28` | «El mínimo es **0.23.0**. Antes era 0.37.0, y eso rompía a quien usara FastAPI 0.103.x» |
| `docs/instalacion.md` | «cualquier versión ≥ 0.23» / «**Starlette** 0.23 o superior» |
| `CHANGELOG.md:504-511` | «Instalar Gatekeeper rompía FastAPI 0.103.x… el mínimo de Starlette era `>=0.37`, pero FastAPI 0.103.x exige `starlette<0.28`» |

**Por qué importa y no es cosmético.** El 0.37 no es un mínimo arbitrario: es
el valor que **rompía la instalación** de quien usara FastAPI 0.103.x, porque
al instalar Gatekeeper pip subía Starlette por encima de 0.28 y FastAPI
dejaba de funcionar (arreglado en la 0.4.0, CHANGELOG y
`docs/compatibilidad.md`). La portada de la web sigue anunciando el valor
que causaba el problema. Quien la lea y fije `starlette>=0.37` en su proyecto
reproduce exactamente esa rotura.

**De dónde viene.** Es el hallazgo **B-10** de `AUDITORIA-2026-10-25.md:193`
(que además señalaba que `docs/instalacion.md` tenía 0.37 en la línea 43 y
0.23 en la 69) y aparece repetido en `.audit/Evaluacion-ia/chatgpt.md:206`.
`docs/instalacion.md` **sí** se corrigió; `docs/index.md` **no**. Es decir:
la Fase 4 (coherencia documental) corrigió la mitad del hallazgo y dejó la
portada —la página más visible— con la versión equivocada.

**Por qué el verificador no lo caza.** `tools/check_docs.py` compara la
**versión de Gatekeeper** entre sitios (`pyproject.toml` ↔ README ↔
`SECURITY.md` ↔ CHANGELOG). No compara las **dependencias de terceros**, así
que un mínimo de Starlette equivocado pasa el filtro.

**Arreglo (una línea, sin cambio de comportamiento):**

```diff
--- a/gatekeeper-v0.3/gatekeeper/docs/index.md
+++ b/gatekeeper-v0.3/gatekeeper/docs/index.md
@@ línea 84
-- [Starlette](https://www.starlette.io/) ≥ 0.37 — FastAPI lo trae ya
++ [Starlette](https://www.starlette.io/) ≥ 0.23 — FastAPI ya la trae
```

**Guarda recomendada (para que no vuelva a colarse).** Una comprobación más en
`tools/check_docs.py`: extraer el mínimo de `starlette` de `pyproject.toml`
(`dependencies`) y exigir que todo `≥ X` / `X o superior` que se mencione en
`docs/*.md` sea ≥ ese valor (y que no vuelva a aparecer un `0.37` como
mínimo). Es la misma idea que la que ya evita las erratas: un linter propio y
determinista, no una lista de valores sueltos.

---

### H2 · MEDIO — El recorte del sdist (Fase 5) no ha llegado a PyPI

El sdist **publicado** (`gatekeeper_asgi-0.7.0.tar.gz`, 493.534 B) lleva
todavía el contenido que la Fase 5 recortó:

```
contenido : 114 ficheros, 1.547.719 bytes descomprimidos
   tests            39   <-- recortado en F5
   corpus           15   <-- recortado en F5
   docs             14   <-- recortado en F5
   demo              6   <-- recortado en F5
   benchmarks        1   <-- recortado en F5
```

En `main` ese mismo sdist sale en **95,0 KiB** (con la guarda de 100 KiB en
CI). Es decir: el trabajo de la F5 está **mergeado y verde**, pero solo vive en
GitHub. Quien hace `pip install gatekeeper-asgi` hoy descarga 482 KiB con el
corpus, los tests, la web y las demos dentro.

**Consecuencia operativa:** la F5 no puede decirse "cerrada para el usuario"
hasta que exista una release que la incluya. Es el mismo motivo por el que el
clasificador `Programming Language :: Python :: 3.14` (ya en `main`) no aparece
en la ficha de PyPI.

---

### H3 · BAJO — SonarCloud queda `cancelled` en cada push

Check `SonarCloud Code Analysis` → `completed / cancelled`, con el resumen
«The last analysis has failed» en `sonarcloud.io`. Es la **app externa**
(fallo del análisis en SonarQube Cloud), no el repo: los otros **12** checks de
`main` están en verde. Si el repo tiene branch protection con checks
obligatorios, ese check no debería contar como bloqueante → marcarlo
*not required*.

---

### H4 · BAJO — Las fases 4 y 5 no tienen release

`pyproject.toml` sigue en `0.7.0` y el CHANGELOG tiene F4/F5 bajo
«[Sin publicar]». Todo está mergeado y medido, pero **nadie que instale desde
PyPI ve la Fase 4 ni la Fase 5**. Publicar una `0.8.0` (o `0.7.1`) cerraría
H2 y H4 de una vez.

---

## 3. Qué NO cubre esta revisión

- **La revisión de seguridad independiente** (la parte no automatizable de la
  Fase 6). La puede hacer alguien externo; `SECURITY_REVIEW.md` ya dice que
  no valida una revisión hecha por quien escribió el código.
- **`semgrep` + `zizmor` en CI** y los **tests diferenciales contra
  FastAPI/Starlette**: parte automatizable de la F6, pendiente.
- El **aplaneado del repo** (F5.1): se dejó sin hacer a propósito porque mueve
  `src/`, `tests/` y `docs/` a la raíz y rompe URLs públicas. Es decisión del
  propietario, no un defecto.

## 4. Reproducir esta revisión

```bash
git fetch origin --prune
git log origin/main --oneline -12
git ls-remote --tags origin

# CI de main, sin gh
curl -s https://api.github.com/repos/Eche-Dev/Gatekeeper/commits/main/check-runs

# Lo que hay publicado en PyPI
curl -s https://pypi.org/pypi/gatekeeper-asgi/json

# El sdist publicado, por dentro
python .audit/inspecciona_sdist.py .audit/pub_0.7.0.tar.gz

# La incoherencia de H1
git grep -n '0\.37' origin/main -- 'gatekeeper-v0.3/gatekeeper/docs/*.md'
git show origin/main:gatekeeper-v0.3/gatekeeper/pyproject.toml | Select-String 'starlette>='
```
