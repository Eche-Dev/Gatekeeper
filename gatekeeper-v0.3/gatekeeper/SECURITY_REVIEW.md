# Revisión de seguridad — Gatekeeper v0.3.1

**Fecha:** 2026-10-24 · **Commit base:** `8c04456` (rama `feat/plan-verificacion-y-limites`)
**Alcance:** `src/gatekeeper/` (1.807 líneas), el middleware, la configuración,
el CLI y las herramientas de evaluación. **Método:** lectura del código buscando
en las fronteras de confianza, y measurements adversariales con pruebas de
concepto (PoC) sobre el código real.

> Esta revisión la hizo la misma persona que escribió el código. **No es una
> revisión independiente.** Para el requisito del plan ("revisión de seguridad
> independiente") falta una segunda opinión de alguien que no haya tocado el
> proyecto. Lo que sí es independiente son las **mediciones**: los PoC son
> ejecutables y reproducibles, y los hallazgos tienen regresiones que fallan
> sin el arreglo.

## Resumen

| | |
|---|---|
| Hallazgos **corregidos** | **1** (alto) + 3 menores ya corregidos en revisiones anteriores |
| Hallazgos **aceptados** (con documentación) | **4** |
| Hallazgos **pendientes** | **0** sin resolver |
| Limitaciones **conocidas y documentadas** | 5 |

El hallazgo principal era un **DoS de memoria con cuerpos pequeños**: 83 KiB de
JSON anidado consumían **193,6 MiB** a través del middleware real, y 10
peticiones simultáneas llegaban a **1,9 GiB**. Corregido.

## Zonas de confianza revisadas

| Zona | Entrada no confiable | Qué hace el código |
|---|---|---|
| Body | bytes del cliente | `read_body` → `extract_strings` → regex |
| Ruta y query | del cliente | `normalize` → `scan` |
| Cabeceras | del cliente | `_header` → `scan` |
| Cabecera `X-Forwarded-For` | del cliente (salvo que haya proxy) | `_client_ip` |
| Configuración | del operador | `Config.__post_init__` |
| Log de auditoría | el propio middleware | `json.dumps` |

---

## H-1 — DoS de memoria por punteros JSON cuadráticos *(corregido)*

**Gravedad:** alta · **Tipo:** agotamiento de recursos (CWE-400) ·
**Vector:** una petición HTTP con un body JSON profundo.

### Qué pasaba

El puntero JSON que identifica el campo en la auditoría (`/users/0/bio`) se
construía concatenando un segmento por nivel de anidamiento. A profundidad N,
cada puntero mide O(N) caracteres; con N campos, el total es O(N²).

### Impacto (medido, antes del arreglo)

| Escenario | Antes | Después |
|---|---|---|
| 1 petición, body de 83 KiB con 14.100 niveles | **193,6 MiB** (2401×) | **7,8 MiB** (96×) |
| 5 peticiones simultáneas | **958 MiB**, 10,4 s | 30,9 MiB, 9,1 s |
| 10 peticiones simultáneas | **1.914 MiB**, 24 s | 58,3 MiB, 18,5 s |

La respuesta era **200**: el atacante recibía una respuesta normal y el
consumo de memoria era invisible. `max_body_size` **no lo acotaba**: 83 KiB
están muy por debajo del límite de 1 MiB. El problema no era el tamaño del
body, sino su estructura.

### Por qué no lo detectaron los tests anteriores

- El corpus de ataques tiene payloads **cortos**.
- Los tests de límites de memoria (que se escribieron en la revisión anterior)
  medían el **body acumulado**, no el puntero.
- `tests/test_fuzz.py` genera entradas aleatorias, casi nunca con 10.000
  niveles de anidamiento.

### El arreglo

`src/gatekeeper/body.py`: la ruta se lleva como una **lista de segmentos
acotada** en vez de una cadena que crece. Al superar `MAX_POINTER_DEPTH` (64) se
conservan los dos extremos —el primero (la clave exterior, la que nombra el
usuario en `exclude_fields`) y el último (el campo que saltó)— y se marca el
corte con `…`. El puntero también se acota en longitud
(`MAX_POINTER_LENGTH`, 256) y en tamaño de segmento
(`MAX_SEGMENT_LENGTH`, 64), porque una sola clave de 10.000 caracteres
volvería a hacerlo enorme.

`src/gatekeeper/config.py`: `field_excluded` compara ahora también por el
**primer** segmento, para que `exclude_fields=["bio"]` siga funcionando con
punteros recortados.

### Lo que NO se pierde

- La atribución por campo sigue diciendo **qué campo** saltó.
- `exclude_fields` sigue funcionando (comprobado por test).
- La **detección** no se pierde: el recorte es del puntero, no del texto. Un
  JSON profundo con un ataque sigue detectándose.

### Regresión

`tests/test_dos_punteros_json.py` (13 tests): el límite del puntero, la
marcación del corte, la conservación del primer y último segmento, el factor
de amplificación acotado, el caso a través del **middleware real**, y 20
peticiones concurrentes.

---

## A-1 — Las reglas personalizadas del usuario pueden colgar el proceso *(corregido en 0.6.0)*

**Gravedad:** media (si el usuario escribe una regex mala) · **Vector:** regla
propia con backtracking exponencial.

`custom_rules` se compila tal cual (`re.compile`), sin ningún límite de
tiempo ni de pasos. Una regex patológica del usuario (por ejemplo `(a+)+$`)
cuelga el proceso con una entrada crafted.

**Estado actual:** corregido. Desde la 0.6.0, el patrón se analiza **de forma
estática al arrancar** (`src/gatekeeper/redos.py`): el riesgo *exponencial*
(cuantificadores anidados sin nada obligatorio detrás, alternativas que se
solapan en un grupo repetido, referencias atrás repetidas) se rechaza con
`ValueError`, y el riesgo *cuadrático* se avisa en el log. La comprobación no
ejecuta el regex: medirlo exigiría un timeout, y en Python no hay forma de
interrumpir un regex en marcha (la propia medición sería el DoS). Existe
`allow_unsafe_custom_rules=True` para quien sepa lo que hace.

**Por qué no se imponía antes:** las reglas del usuario son suyas y son
explícitas. Las reglas **integradas** sí están acotadas (`\s{0,16}` en todos
los cuantificadores de blancos), y hay un test (`tests/test_fuzz.py`) que
vigila que no se introduzca un `\s*` sin cota.

**Riesgo residual:** una regex *cuadrática* (por ejemplo `(?:\w+\.)+\w+`) se
avisa pero no se rechaza: son patrones legítimos y el coste depende del
tamaño de la entrada, que acota `max_body_size`.

## A-2 — La normalización NFKC expande hasta 4× *(aceptado)*

**Gravedad:** baja · **Vector:** un body lleno de números romanos.

NFKC (normalización de compatibilidad Unicode) expande algunos caracteres:
`Ⅷ` (3 bytes) se convierte en `VIII` (4 caracteres). Un body de 341 KiB de
números romanos produce **1.365 KiB** de texto normalizado.

**Medido:** 730 ms de normalización + 825 ms de escaneo para un body de 341 KiB.
El coste es **lineal** con el tamaño del body, así que `max_body_size` lo acota.

**Comprobado además:** ningún carácter Unicode cuya forma normalizada sea
ASCII **dispara una regla**. Es decir, la expansión no puede *activar* una
detección falsa: no introduce falsos positivos.

**Por qué se acepta:** la normalización de compatibilidad es lo que permite
detectar evasions como `＜script＞` (ancho completo) o `ℎｔｔｐ` (homoglifos).
Sin ella, se perderían detecciones reales. El coste está medido y es
proporcional al body.

## A-3 — `monitor_only` no es un plan de rollback *(aceptado, documentado)*

Con `monitor_only=True` el tráfico pasa pero **tampoco se bloquea**. Si lo que
se estaba frenando era un ataque real, volver a dejarlo pasar es asumir el
riesgo a sabiendas.

**Por qué se acepta:** es el comportamiento que hace útil el modo monitor (hay
que poder observar sin bloquear). Está documentado explícitamente en
`docs/operacion.md` con la advertencia.

## A-4 — El backend de rate limit en memoria se multiplica por workers *(aceptado, documentado)*

Con varios workers, cada proceso cuenta lo suyo: 4 workers con
`rate_limit=100` admiten ~400/min.

**Por qué se acepta:** es inherente a un contador en memoria. La alternativa
(Redis) está implementada, probada contra un Redis real y con procesos de
Python reales, y recomendada en `docs/despliegue.md` para despliegues con más
de una instancia.

---

## Límites conocidos (no son fallos)

| Límite | Por qué |
|---|---|
| `multipart/form-data` **no** se inspecciona | Requiere un parser propio; está fuera de alcance y documentado |
| Los cuerpos **binarios** no se inspeccionan | Su contenido no son cadenas; documentado con tests |
| Las **claves JSON** no se unen al objetivo en el modo combinado | Decisión de diseño: un JSON pointer es una clave, no un valor |
| El puntero JSON se **recorta** a 256 caracteres | Consecuencia de H-1; se marca con `…` |
| Las **reglas propias** se validan al arrancar | Riesgo exponencial: se rechaza; riesgo cuadrático: se avisa (ver A-1) |

---

## Lo que la revisión también comprobó (y estaba bien)

- **Inyección de log:** el puntero JSON va al evento de auditoría como valor de
  JSON, escapado. Una clave como `evil", "injected": "yes"` no cuela ninguna
  clave nueva en el evento (comprobado).
- **Excepciones no controladas:** 18 cuerpos adversarios (JSON anidado, UTF-8
  inválido, bytes nulos, `NaN`/`Infinity`, JSON duplicado, BOM) producen
  respuestasnormales, nunca un 500.
- **La IP y el XFF:** 12 combinaciones de peer/XFF/proxy/CIDR dan el resultado
  correcto; un XFF malformado o vacío cae al peer; una cadena de proxies
  inconsistente no adivina.
- **La configuración:** 14 valores hostiles (`rate_backend` inválido,
  `max_body_size` negativo, CIDR malformado, IP inválida, regla inexistente)
  **rompen el arranque** con `ValueError`/`TypeError`, nunca pasan
  silenciosamente.
- **ReDoS en las reglas integradas:** los cuantificadores tienen cota explícita
  y `tests/test_fuzz.py` lo vigila. Entradas patológicas de 1 MiB (espacios,
  llaves, comillas, barras, backslashes, `$`, `%`) se escanean en 60–1.160 ms.
- **El body se corta por el límite:** 64 MiB con límite de 1 MiB consumen
  ~1 MiB, no 64 (fijado en `tests/test_limites_memoria.py`).
- **El cuerpo se guardaba dos veces:** corregido (la lista de chunks y los
  mensajes de ASGI ya lo llevaban).

---

## Limitación de esta revisión

La hizo **quien escribió el código**. Eso es un conflicto de interés real: los
puntos ciegos de quien escribe el código no los ve quien lo escribe.

Lo que **sí** es independiente:

- Las **mediciones** son reproducibles: los PoC se ejecutan contra el código
  real, y cada hallazgo tiene una regresión que falla sin el arreglo.
- El **método** (fronteras de confianza, no "leer el código") no depende de
  quien lo aplique.
- Los **arreglos** los puede revisar cualquiera: están en el diff.

Lo que **falta** para el requisito del plan ("revisión de seguridad
independiente"): una segunda revisión por alguien ajeno al proyecto, con los
mismos dos PoC como punto de partida.

## Cómo reproducir los hallazgos

```bash
# H-1: la amplificación (debe ser < 100x tras el arreglo)
python - <<'PY'
import sys, tracemalloc
sys.path.insert(0, "src")
from gatekeeper.body import extract_strings
cuerpo = (b'{"a":' * 10000) + b"1" + (b"}" * 10000)
tracemalloc.start()
extract_strings("application/json", cuerpo)
_, pico = tracemalloc.get_traced_memory()
print(f"amplificacion: {pico / len(cuerpo):.0f}x")
PY

# A-2: la expansion NFKC
python -c "
import sys; sys.path.insert(0,'src')
from gatekeeper.rules import normalize
print(len(normalize('Ⅷ' * 10000)))
"
```

## Trazabilidad

| Revisión | Fecha | Resultado |
|---|---|---|
| Original (PR #18) | 2026-10 | 4 bypasses del XFF, 3 reglas incompletas — corregidos en v0.3 |
| Múltiples, durante v0.3 | 2026-10 | Redis < 6 en silencio, `Retry-After` +1, YAML inválido, FastAPI ausente, prefiltro en textos largos, falso positivo de blogs con fecha — corregidos |
| **Esta revisión** | 2026-10-24 | **H-1** (DoS de punteros JSON), A-1 a A-4 aceptados |
