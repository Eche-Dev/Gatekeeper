# Compatibilidad y política de soporte

Qué versiones están probadas, qué significa "soportada", y qué pasa cuando
publicas una versión nueva.

## Matriz de compatibilidad

**Medida, no supuesta.** La tabla se genera con
`python tools/compat_matrix.py`, que crea un entorno virtual por cada
combinación, instala el paquete y comprueba que el middleware:

- se puede añadir a la app,
- bloquea un ataque (403),
- deja pasar una petición legítima (200),
- y pone las cabeceras de seguridad **también en el rechazo**.

### Starlette

| Versión | Resultado |
|---|---|
| 0.23.0 (mínimo) | ✅ |
| 0.27.0 | ✅ |
| 0.37.0 | ✅ |
| 0.41.3 | ✅ |
| 0.46.2 | ✅ |
| última (1.10.0) | ✅ |

El mínimo es **0.23.0**. Antes era 0.37.0, y eso rompía a quien usara
FastAPI 0.103.x: al instalar Gatekeeper, pip subía Starlette por encima de
0.28 y **FastAPI dejaba de funcionar**. El middleware solo usa
`MutableHeaders`, `JSONResponse` y los tipos ASGI, que son estables desde hace
años.

### FastAPI

| Versión | Starlette que trae | Resultado |
|---|---|---|
| 0.103.2 | 0.27.0 | ✅ |
| 0.110.3 | 0.37.2 | ✅ |
| 0.115.6 | 0.41.3 | ✅ |
| última (0.162.0) | 1.10.0 | ✅ |

### Python

| Versión | Probada en CI |
|---|---|
| 3.10 | ✅ (mínimo declarado) |
| 3.11 | ✅ |
| 3.12 | ✅ |
| 3.13 | ✅ |
| 3.14 | ✅ (local, no en CI) |

### Servidores ASGI

| Servidor | Probado en CI |
|---|---|
| uvicorn | ✅ |
| hypercorn | ✅ |
| daphne | ✅ |

Probados como **procesos reales** con peticiones HTTP por socket
(`tests/test_servidores_asgi.py`), no solo con `TestClient`.

### Redis (para el rate limit compartido)

| Versión | Probada |
|---|---|
| 5.0 | ✅ |
| 7.2 | ✅ |

### Dependencias opcionales

| Extra | Versión mínima | Para qué |
|---|---|---|
| `yaml` | PyYAML 6 | `Config.from_yaml()` |
| `redis` | redis 5.0 | Rate limit compartido entre workers |
| `servers` | — | hypercorn y daphne, para las pruebas |

!!! note "Por qué no hay cota superior de Starlette"
    Acotarla rompería instalaciones legítimas: el middleware no usa ninguna API
    que haya cambiado, así que subir la versión de Starlette no debería
    romper nada. Si algún día lo hace, se verá en los tests de la matriz.

## Qué significa "soportada"

Una versión está **soportada** si:

| | |
|---|---|
| Correcciones de seguridad | ✅ se aplican |
| Correcciones de errores | ✅ se aplican |
| Nuevas functionality | ✅ se aplica |
| Compatibilidad hacia atrás | ✅ se mantiene dentro de la major |
| Soporte de bugs sin corregir | ❌ no se promete |

"soportada" significa que **no se rompe a propósito**. No significa que
responda en un plazo concreto.

### Versiones mantenidas

| Rama | Estado | Recibe |
|---|---|---|
| 0.4.x | **Activa** | Todo: seguridad, errores, nuevas features |
| 0.3.x | Histórica (nunca publicada en PyPI) | Solo correcciones de seguridad críticas |
| 0.2.x | Histórica (nunca publicada en PyPI) | Solo correcciones de seguridad críticas |
| 0.1.x | Histórica (nunca publicada en PyPI) | Nada |

Al sacar la 0.5.0, la 0.4.x pasa a histórica y la 0.3.x deja de recibir
correcciones. Eso se anuncia en el CHANGELOG y en las release notes.

!!! note "Por qué la serie publicada empieza en 0.4.0"
    Las versiones 0.1.x a 0.3.x nunca se publicaron en PyPI: el paquete se
    instalaba desde el repositorio. Empezar la serie publicada en 0.4.0 evita
    la confusión de "instalo `gatekeeper-asgi==0.3.1` y no existe". Los
    números de versión antiguos siguen siendo válidos en el CHANGELOG, como
    historial.

!!! warning "Una major es un corte"
    Al cambiar de major (0.3 → 0.4), se puede cambiar la configuración por
    defecto, quitar opciones o cambiar el comportamiento. Por eso hay
    [notas de migración](#notas-de-migración) y por eso la versión menor (0.3.1
    → 0.3.2) **no** rompe nada: solo añade y corrige.

## Compatibilidad de la API

Gatekeeper sigue [SemVer](https://semver.org/lang/es/spec/v2.0.0.html):

- **PATCH** (0.3.1 → 0.3.2): correcciones y añadidos. No se rompe nada.
- **MINOR** (0.3.x → 0.4.0): features nuevas. Se puede **depreciar** algo
  (con aviso en el CHANGELOG y en la documentación), pero no se quita.
- **MAJOR** (0.x → 1.0): se puede quitar lo deprecado.

### Qué se considera "API pública"

Lo que se puede usar desde fuera del paquete:

| | |
|---|---|
| `gatekeeper.Config` | Sus campos y sus valores por defecto |
| `gatekeeper.GatekeeperMiddleware` | El middleware y su constructor |
| `gatekeeper.scan`, `scan_all`, `scan_detailed` | Las funciones de escaneo |
| `gatekeeper.RULES`, `PACK_NAMES` | Los nombres de las familias |
| La CLI: `gatekeeper report` | Su interfaz y el formato JSON |
| Los eventos de auditoría | Sus nombres y sus campos |
| El formato del YAML de configuración | Las claves y sus valores |

Lo que **no** es API pública (puede cambiar sin aviso en una minor):

- Los detalles de `src/gatekeeper/` que no estén en la lista de arriba.
- El texto exacto de los patrones de las reglas.
- El orden de las familias en `RULES`.
- Los mensajes de los logs (el formato JSON **sí** es API).
- Los detalles del informe de `gatekeeper report` (el JSON **sí**).

!!! note "Los patrones de las reglas son implementacion, no API"
    Una regla puede cambiar para detectar mejor una evasion. Eso cambia qué
    se bloquea. Si dependes de un patrón concreto, dependes de una
    implementación: no es una API estable.

### Depreciaciones

1. Se anuncian en el CHANGELOG bajo "Deprecated".
2. La documentación dice qué usar en su lugar.
3. Se quitan **una major después**, como mínimo.

## Notas de migración

Las cambios que rompen compatibilidad se documentan aquí, en el CHANGELOG y
en las release notes del tag.

### 0.4.x

| Cambio | Qué hacer |
|---|---|
| El mínimo de Starlette baja a **0.23** | Ninguno. Antes (0.37) rompía FastAPI 0.103.x: al instalar Gatekeeper, pip subía Starlette y FastAPI dejaba de funcionar |
| Las cabeceras de seguridad también van en los **rechazos** (403/413/429/503) | Ninguno. Solo se **añaden** cabeceras. Si tu app las ponía también, la suya gana (el middleware no pisa lo que ya venía) |
| El puntero JSON se **recorta** a 256 caracteres | Si parseas punteros completos, deja de poder contar con la ruta entera. `exclude_fields` sigue funcionando |
| Nuevo extra `servers` (hypercorn, daphne) | Ninguno. Es opcional |

!!! warning "Sobre el recorte del puntero JSON"
    Un JSON con más de 64 niveles de anidamiento produce punteros recortados
    (`/bio/…/nivel`). El motivo es un DoS medido: sin recorte, un body de 83
    KiB consumía 193,6 MiB. `exclude_fields` sigue funcionando (compara por
    el primer y el último segmento). Ver
    [SECURITY_REVIEW.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md).

### 0.3.x (nunca publicada en PyPI)

| Cambio | Qué hacer |
|---|---|
| `monitor_only` registra sin bloquear | Ninguno: es opt-in |
| `inspect_cross_carrier` combina query y body | Ninguno: es opt-in |
| `trust_proxy` desactivado por defecto | Si usas un proxy: `trust_proxy=True` **y** `trusted_proxy_cidrs` con tus redes |
| `exclude_fields` acepta globs | Los nombres exactos siguen funcionando |

!!! note "La política de deprecación se aplica desde 0.3"
    Antes de 0.3 no había releases en PyPI, así que no había a quién
    deprecar. Desde 0.3.0, cada cambio incompatible tiene que venir con su
    nota de migración.

## Proceso de release

1. **Preparar**: actualizar el CHANGELOG (mover "Sin publicar" a la versión
   nueva), actualizar el número de versión en `pyproject.toml`.
2. **Verificar**: el CI tiene que estar verde (tests, cobertura, corpus,
   auditoría de dependencias, paquete).
3. **Etiquetar**: `git tag -a v0.3.2 -m "Gatekeeper 0.3.2"`.
4. **Publicar**: el workflow `publicar.yml` construye el wheel y el sdist y
   los sube a PyPI con Trusted Publishing (OIDC). No hay ningún token en los
   secretos del repositorio.
5. **Anunciar**: release notes en GitHub con los puntos de la tabla de
   migración.

!!! info "El tag dispara la publicación"
    El workflow `publicar.yml` se activa con los tags `v*`. El tag es la
    señal: lo que no lleva tag, no se publica.

### Reproducir una publicación en local

```bash
python -m build
twine check dist/*
python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
```

Prueba primero en TestPyPI: es una instalación de verdad, sin consequences.

## Cómo reportar un problema

- **Errores y features**: [GitHub Issues](https://github.com/Eche-Dev/Gatekeeper/issues).
- **Vulnerabilidades**: canal privado, ver [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md).
  **No abras un issue público con un fallo explotable.**
- **Falsos positivos**: valen como issue. Di el campo, la regla que saltó y
  el patrón de la petición. Con eso se puede ajustar.

!!! tip "Un falso positivo con detalle se arregla rápido"
    El evento de auditoría lleva `rule`, `field` y `pattern`: con eso se sabe
    exactamente qué firió y dónde. `gatekeeper report` lo agrega.

## Limitaciones conocidas

- La detección por regex tiene falsos positivos y negativos: se miden y se
  publican, no se ocultan.
- `multipart/form-data` y los cuerpos binarios **no** se inspeccionan.
- Las reglas propias del usuario **no** están acotadas contra ReDoS.
- El rate limit en memoria se multiplica por el número de workers.
- No sustituye a consultas parametrizadas, autenticación ni autorización.

La lista completa, con el porqué de cada una, está en
[Modelo de amenazas](amenazas.md) y en
[SECURITY_REVIEW.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md).
