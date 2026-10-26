# Gatekeeper 0.8.0

## Qué es

Convierte en algo publicable lo que hasta ahora solo era un repo: la Fase 4
(coherencia documental) y la Fase 5 (repo y distribución) entran en un
paquete de **95 KiB** en vez de 482 KiB, la documentación deja de mentir en la
portada, y los README explican por fin **qué hace el proyecto**.

| | Antes (0.7.0) | Ahora (0.8.0) |
|---|---:|---:|
| Tamaño del sdist en PyPI | 482 KiB | **95 KiB** |
| Corpus, tests, web y demos dentro del paquete | Sí | **No** |
| Mínimo de Starlette en la portada de la web | 0.37 (el equivocado) | **0.23** (el real) |
| Los README explican qué hace el proyecto y por qué | No | **Sí** |

## Qué cambia

### 1 · El paquete que se instala pesa un 80 % menos

El sdist se llevaba el corpus (588 KiB sin comprimir), la web, las demos, los
benchmarks y los tests. Eso vive en **GitHub**, y el README lo enlaza; lo que
se baja de PyPI es el WAF.

- El CI lo **vigila**: el job `package` falla si el sdist pasa de 100 KiB.
- Además, el CI **instala el sdist** en un entorno limpio y ejecuta la suite
  contra él: es exactamente lo que se baja quien instala desde el código.

### 2 · La portada de la web ya no anuncia un mínimo de Starlette roto

`docs/index.md` decía «Starlette ≥ 0.37» mientras `pyproject.toml` declara
`starlette>=0.23`. El 0.37 no era un mínimo arbitrario: era el que **rompía la
instalación** de quien usara FastAPI 0.103.x (al instalar Gatekeeper, pip
subía Starlette por encima de 0.28 y FastAPI dejaba de funcionar). La
portada —la primera página que ve quien llega— seguía anunciando el valor
causante del problema.

Ahora dice 0.23, y **`tools/check_docs.py` lo vigila**: comprueba que el
mínimo que afirma la documentación sea el que declara `pyproject.toml`. La
comprobación exige que cada afirmación nombre a la dependencia en su propia
frase, para que un `redis >= 5.0` cerca de `starlette` no se confunda.

### 3 · Los README cuentan qué hace el proyecto

El README del paquete (que es la ficha de PyPI), el de la web y el inglés
explican ahora, **antes de entrar en detalle**:

- **qué problema resuelven** (una IP que pide de más, cabeceras de seguridad
  que nadie pone, un campo sin validar);
- **las tres cosas que hace el middleware**;
- **qué revisa**, por superficie y no por familia (el detalle por familia
  sigue en `docs/amenazas.md`);
- **qué pasa cuando detecta algo**, con la respuesta 403 y el evento de
  auditoría **reales**, generados ejecutando el middleware.

### 4 · La documentación no miente, y ahora se comprueba

`tools/check_docs.py` (en CI) verifica que la versión que dicen el README, la
guía de instalación, la tabla de `SECURITY.md` y el CHANGELOG sea la misma que
la de `pyproject.toml`; que los enlaces internos y sus anclas existan; que no
vuelvan a colarse las erratas que ya se colaron una vez; y que el **mínimo de
cada dependencia** sea el que se instala.

### 5 · El repositorio, limpio y con sus reglas escritas

- **`AGENTS.md`** en la raíz: el método con el que se trabaja el proyecto
  (verificar, no creer; medir antes de endurecer una firma; test antes del
  arreglo; los falsos positivos se documentan, no se esconden).
- **Limpieza de la raíz**: scripts sueltos sustituidos por `tools/`, el parche
  del fix de ReDoS y los planes antiguos movidos a `.audit/`, que es donde vive
  la evidencia.
- **El job `compat` del CI** (programado, no bloqueante) **mide** la matriz de
  compatibilidad: `tools/compat_matrix.py` ya estaba escrito y no se ejecutaba
  nunca.

## Migración desde 0.7.0

**Sin cambios en la API pública**: no hay deprecaciones, ni renombrados, ni
parámetros nuevos. `Config`, `GatekeeperMiddleware`, `custom_rules`,
`disabled_rules`, `rule_packs` y `exclude_fields` funcionan igual.

**Los cambios que sí pueden afectar:**

1. **El paquete instalado es más pequeño.** Deja de venir el corpus, la web,
   las demos, los benchmarks y los tests dentro del wheel y el sdist. Si
   tenías un script que leía `corpus/` desde el paquete instalado, deja de
   encontrarlo: ahora está en
   [el repositorio](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/corpus/).
2. **La versión de Python 3.14 sale en los metadatos** de PyPI (ya lo era en el
   repo). No cambia nada en la instalación: `requires-python` sigue siendo
   `>=3.10`.
3. **La detección no cambia.** Ni una regla, ni una firma, ni un corpus. Las
   cifras de abajo son las mismas que las de la 0.7.0, medidas con la misma
   batería.

## Detección

Sin cambios respecto a 0.7.0, verificado con los tres corpus:

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | 159/159 (100 %) | 0 no documentados (8 documentados) |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados (5 documentados) |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

## Qué NO cubre

- El **contenido** de los ficheros adjuntos (sí los nombres).
- Los **frames** de un WebSocket (sí el handshake).
- Binarios que no son JSON (imagen, PDF, zip…).
- El tráfico entre query y body si `inspect_cross_carrier=False`.
- Autenticación, autorización y consultas parametrizadas: eso va en tu app.
- El regex **dentro** de un mismo texto: lo que se controla es el **número de
  campos**, no el coste de una única evaluación.
- Los cuatro límites de la 0.7.0 (`{{config}}`, `${env:…}`/`${jndi}`, CRLF con
  cabecera citada, IP de metadata citada).

## Compatibilidad

Sin cambios: Python 3.10–3.14, Starlette 0.23.0–1.10.0, FastAPI
0.103.2–0.162.0, uvicorn/hypercorn/daphne y Redis 5.0/7.2. La matriz completa
y **medida** está en
[docs/compatibilidad.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md).

## Instalación

```bash
pip install --upgrade gatekeeper-asgi          # núcleo
pip install "gatekeeper-asgi[yaml]"             # + configuración por YAML
pip install "gatekeeper-asgi[redis]"            # + rate limit distribuido
```

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

El DoS de disponibilidad de la 0.4.0 (corregido en la 0.4.1) está en
[SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md),
en la sección «Vulnerabilidades corregidas».
