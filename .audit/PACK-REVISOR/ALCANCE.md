# Paquete para la revisión de seguridad independiente

> **Esto no es la revisión.** Es el material para que alguien la pueda hacer:
> el alcance, el punto de partida, los datos medidos y la plantilla del
> informe. La revisión la tiene que escribir **alguien que no haya ajustado
> las reglas** del proyecto.

**Fecha del material:** 2026-10-27 · **Código revisado:** `main` tras el PR #43
(`9724daf`, rama `fase7-cobertura`: la fase 7, la cobertura por módulo) ·
**Paquete:** `gatekeeper-asgi` 0.9.0 publicado en PyPI.

---

## 1. Por qué hace falta, y por qué no la puedo hacer yo

El proyecto lleva seis fases de auditoría, y las **mediciones** de todas ellas
son independientes: los PoC se ejecutan contra el código real y cada hallazgo
tiene una regresión que falla sin el arreglo. Eso es reproducible por
cualquiera.

Lo que **no** es independiente es el **juicio**. Quien ha ajustado las reglas
para tapar un bypass no es la persona adecuada para decir que ya no queda
ninguno: es un conflicto de interés real, y el propio `SECURITY_REVIEW.md`
del proyecto lo dice desde la 0.3.1:

> Esta revisión la hizo la misma persona que escribió el código. **No es una
> revisión independiente.**

Este paquete cierra ese hueco: le da a otra persona el contexto, los
puntos de partida y los datos, para que no tenga que reconstruir el proyecto
desde cero.

---

## 2. Qué se pide exactamente

Una revisión de seguridad del **middleware**, escrita por alguien que no haya
participado en el desarrollo, con esta forma:

| Campo | Contenido |
|---|---|
| Fecha y autor | nombre, fecha, commit revisado |
| Alcance | qué se ha revisado y qué **no** |
| Método | cómo se ha revisado (fronteras de confianza, PoC ejecutables) |
| Conflictos de intereses | qué relación tienes con el proyecto, y por qué no invalida la revisión |
| Hallazgos | cada uno con gravedad, PoC ejecutable y **qué se rompe** |
| Limitaciones conocidas | cuáles de las ya documentadas aceptas y cuáles no |
| Veredicto | si el middleware es apto para su uso declarado |

**Un hallazgo** es: algo que un atacante puede hacer con el middleware puesto
y que el middleware **dice** que frena (o que su documentación dice que frena),
y no frena. No es "a mí no me gusta esta regla" ni "esto sería más rápido".

**Un límite aceptado** es algo que ya está documentado como límite (los hay,
en `docs/amenazas.md` y en `SECURITY_REVIEW.md`). Si discrepas de un límite,
eso es una **observación**: hay que decir por qué el límite no es aceptable,
no presentarlo como un fallo nuevo.

---

## 3. El alcance, por orden de prioridad

El middleware es una capa **por delante** de la aplicación. Sus fronteras de
confianza son cuatro:

| Frontera | Entrada no confiable | Qué hace el código |
|---|---|---|
| **Body** | bytes del cliente | `read_body` → `extract_strings` → reglas |
| **Ruta y query** | del cliente | `normalize` → `scan` |
| **Cabeceras** | del cliente | `_header` → `scan` |
| **Configuración** | del operador | `Config.__post_init__` |

Por orden de dónde es más probable que quede un agujero:

1. **El body**, y en particular **la diferencia entre lo que el middleware
   inspecciona y lo que la aplicación usa**. Ese es el bypass que salió en la
   F6.4 (el `+` de un body): el middleware inspeccionaba `sleep(10 6)` y la
   aplicación ejecutaba `sleep(10+6)`. **La pregunta que hay que responder
   otra vez, con otros ejemplos: ¿hay algún otro texto que el middleware
   normalice de una forma y la aplicación use de otra?**

2. **La normalización** (`rules.normalize`): decodificación por rondas,
   NFKC, comentarios SQL, el tratamiento del `+`. Cada una de esas
   transformaciones es una oportunidad para que las dos visiones diverjan.

3. **El presupuesto de inspección**: `max_body_size`, `max_fields`,
   `max_inspection_ms`, `max_pointer_depth`. Un presupuesto que se agota
   tiene que **fallar cerrado** (413), nunca dejar el payload sin inspeccionar.

4. **El log de auditoría**: qué datos del atacante llegan al log, y si están
   saneados y acotados. El log nunca debe llevar el valor del payload.

5. **La configuración**: qué valores invalidos pasan en silencio, y qué pasa
   si el operador configura algo absurdo.

6. **El rate limiter**: la tabla de IPs, la normalización IPv4/IPv6, el XFF
   (que lo controla el atacante si no hay proxy delante), los procesos
   multiples, y el comportamiento con Redis caído.

7. **La CLI** (`gatekeeper report`): lee ficheros de log que puede haber
   escrito un atacante. Un ESC o un BEL en la salida es un escape de terminal.

8. **La superficie**: WebSocket, multipart, `application/octet-stream`, los
   métodos HTTP que no llevan body. Cada una tiene una política **explícita**
   (algunas son "no se inspecciona"), y lo que hay que revisar es que la
   política sea la que dice y no otra.

---

## 4. El punto de partida: PoC ejecutables

`.audit/PACK-REVISOR/ejecutar_pocs.py` (ver más abajo cómo se ejecuta) trae
**15 comprobaciones** sobre el código real. Cada una comprueba una propiedad
que el proyecto afirma, o que un hallazgo anterior dejó como regresión:

| comprobación | qué verifica |
|---|---|
| `punteros` | H-1: la amplificación de memoria del puntero JSON es lineal (no cuadrática) |
| `mas` | el `+` de un body es literal: `sleep(10+6)` se bloquea (regresión del bypass de la F6.4) |
| `log` | el log no lleva el valor del payload, y el nombre del campo viene acotado |
| `redos` | el escaneo es lineal con entradas patológicas (se mide la **relación** entre dos tamaños, no un umbral absoluto) |
| `redis` | con Redis caído, cada petición paga como mucho `redis_timeout` |
| `limite` | un body enorme se corta en `max_body_size` (413), no se lee entero |
| `diferencial` | el middleware y la aplicación interpretan el body igual (26 cuerpos borde, 7 marcadores, 12 ataques, contra Starlette y FastAPI) |
| `config` | un valor de configuración inválido rompe el arranque, no pasa en silencio |
| `nfkc` | la normalización NFKC no puede activar una regla por sí sola |

**Los PoC son un punto de partida, no un techo.** Están escritos para que se
añadan casos: cada uno es una función que devuelve un veredicto y un motivo.
Lo que se busca es que el revisor **extienda** la lista con sus propios casos,
especialmente en el punto 1 (divergencia entre las dos visiones del body).

Un `FALLA` en la salida **no es un veredicto sobre el código**: es un síntoma
que hay que confirmar, explicar y decidir si es un hallazgo. Y un `PASA` en
todos **tampoco** significa que no hay nada: el punto de partida cubre lo que
ya se conoce.

---

## 5. Los datos medidos (el estado que hay que comparar)

### Detección y falsos positivos

| corpus | resultado | guard en CI |
|---|---|---|
| propio (`corpus/attacks.json`) | **160/160 (100 %)** | ≥ 100 % |
| propio (`corpus/benign.json`) | 132 benignos, **0 FP sin documentar** (9 documentados) | ≤ 0 % sin documentar |
| retenido (`corpus/heldout_*`) | **103/109 (94,5 %)** | ≥ 85 % |
| retenido benigno | **0 FP sin documentar** | ≤ 0 % |
| CRS (externo, OWASP) | **465/1135 (41,0 %)** | ≥ 40 % |
| FP sobre los negativos de CRS | **11/232 (4,7 %)** | ≤ 5 % |
| modo cruzado | 7/7 ataques adicionales bloqueados | — |

El corpus retenido (`heldout_*`) existe **para no ajustarlo**: si un fallo del
retenido "se arregla" con una firma escrita para él, el corpus deja de servir
para nada. El corpus de desarrollo sí se puede usar para ajustar.

### Calidad del código

| comprobación | resultado |
|---|---|
| tests | **2938** verdes, 17 saltados |
| cobertura global | 98,65 % (umbral del CI: 90 %), y **todos** los módulos por encima del 95 % |
| `ruff` · `mypy` (estricto, contra 3.10) · `bandit` | sin avisos |
| `semgrep` propio (4 reglas) · `p/default` (290) · `zizmor` | 0 hallazgos bloqueantes |
| `pip-audit` (runtime y desarrollo) | 0 vulnerabilidades |
| CI | 9 jobs: test 3.10–3.13, `bench`, `package`, `sast`, `redis`, `audit` |
| matriz de compatibilidad | 10/10 combinaciones (6 Starlette + 4 FastAPI) con el diferencial en verde |

### Latencia (la que el usuario nota)

| escenario | p50 |
|---|---|
| solo cabeceras | 18 µs |
| inspección de body JSON | 232 µs |
| body de 100 KB | 8,3 ms (59× uno vacío) |

El body grande se paga **antes** de que la aplicación vea la petición. El
guard de CI compara el PR y `main` **en el mismo runner** (mediana de 3
repeticiones, margen del 50 %), porque en un runner compartido una máquina
lenta y una regresión real dan el mismo número.

---

## 6. Los límites conocidos, para que no se redescubran como «hallazgos»

Ya están documentados y aceptados. Si un revisor discrepa, es una
**observación**, y hay que razonarla:

| límite | por qué está |
|---|---|
| `multipart/form-data` **no** se inspecciona (el contenido de los ficheros) | requiere un parser propio; fuera de alcance |
| los cuerpos **binarios** no se inspeccionan | su contenido no son cadenas |
| las **claves JSON** no se unen al objetivo en el modo combinado | un puntero JSON es una clave, no un valor |
| el puntero JSON se **recorta** a 256 caracteres | consecuencia del arreglo de H-1; se marca con `…` |
| las **reglas propias** se validan al arrancar | riesgo exponencial: se rechaza; cuadrático: se avisa |
| NFKC **expande** hasta 4× | líneaal con el tamaño del body; no puede activar una regla por sí solo |
| el rate limiter en **memoria** se multiplica por workers | inherente a un contador en memoria; para varios workers está Redis |
| `monitor_only` no es un plan de rollback | es lo que hace útil el modo monitor; está avisado en `docs/operacion.md` |
| una app que parsea el body de una forma que el `Content-Type` no anuncia | el content-type es lo único que dice cómo inspeccionar |

La lista completa, con el motivo de cada uno, está en
`gatekeeper-v0.3/gatekeeper/docs/amenazas.md` y en el `SECURITY_REVIEW.md`.

---

## 7. Cómo reproducirlo todo

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper
cd gatekeeper-v0.3/gatekeeper
pip install -e ".[dev,servers]"

# La suite completa (2938 tests) y la cobertura
pytest -q --timeout=300
pytest --cov=gatekeeper --cov-fail-under=90 -q

# Los estilos, los tipos y el analisis de seguridad
ruff check .
mypy
bandit -r src -q

# La documentacion: que la doc no mienta
python tools/check_docs.py
python -m mkdocs build --strict

# La deteccion y los falsos positivos (propio, retenido y CRS)
python tools/evaluate.py --check
python tools/evaluate_heldout.py --check
python tools/evaluate_cross.py --check
python tools/import_crs.py --check

# La matriz de versiones (crea un venv por combinacion; tarda unos minutos)
python tools/compat_matrix.py --json

# Los PoC de este paquete
python .audit/PACK-REVISOR/ejecutar_pocs.py
python .audit/PACK-REVISOR/ejecutar_pocs.py --listar
```

**Cómo escribir un informe:** copia
`.audit/PACK-REVISOR/PLANTILLA-SECURITY-REVIEW.md` a
`gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md` (sustituyendo el informe
anterior, que es el registro de la revisión de la 0.3.1) y llénalo. Si el
informe va a vivir en otra rama o en otro repositorio, da igual: lo que
importa es que quede **publicado** y que el README diga quién revisó y
cuándo.

---

## 8. Dónde está cada cosa

| qué | dónde |
|---|---|
| el código del middleware | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/` (1.400 líneas, 10 módulos) |
| la configuración y sus valores por defecto | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/config.py` |
| las reglas y la normalización | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py` |
| la extracción del body | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/body.py` |
| el middleware (la orquestación) | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/middleware.py` |
| el análisis de ReDoS de las reglas propias | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/redos.py` |
| el log de auditoría (qué lleva y qué no) | `gatekeeper-v0.3/gatekeeper/src/gatekeeper/sanitize.py` y `middleware.py` |
| la revisión anterior (la de la 0.3.1) | `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md` |
| los límites conocidos | `gatekeeper-v0.3/gatekeeper/docs/amenazas.md` |
| el registro de todo lo corregido | `gatekeeper-v0.3/gatekeeper/CHANGELOG.md` |
| los corpus y su procedencia | `gatekeeper-v0.3/gatekeeper/corpus/README.md` |
| la evidencia de las fases anteriores | `.audit/` (y `.audit/REVISION-ENTREGA-2026-10-26.md`) |

---

## 9. Lo que este paquete **no** incluye

- **No es un encargo de buscar un fallo.** Si no hay ninguno, el informe lo dice y
  es igual de valioso. Un informe que busca el fallo a cualquier precio es
  peor que ninguno: entrena al mantenedor para desconfiar de todo.
- **No cubre el entorno**, solo el middleware: ni el sistema operativo, ni
  el servidor ASGI, ni la red, ni la configuración del despliegue. El
  alcance es el paquete `gatekeeper-asgi`.
- **No sustituye a las mediciones**: si un hallazgo es un DoS o un bypass,
  tiene que venir con un PoC ejecutable, como los de aquí.
