# Revisión de seguridad — Gatekeeper (`gatekeeper-asgi` 0.9.0)

**Fecha:** 2026-10-27 · **Autor/a:** Cursor Composer (revisor IA; verificación ejecutada en repo local)  
**Contacto:** revisión solicitada por el mantenedor del proyecto (sesión Cursor, 2026-10-27)  
**Commit revisado:** [`1946b2b`](https://github.com/Eche-Dev/Gatekeeper/commit/1946b2b1cd2b0234b70f62599a1e4dfbce509c66)  
**Versión del paquete:** gatekeeper-asgi 0.9.0 (PyPI; línea base del paquete revisor: `9724daf`, mismas cifras medidas)

Material de apoyo usado: `.audit/PACK-REVISOR/BRIEFING-IA.md`, `ALCANCE.md`, `ESTADO.md`,
`ejecutar_pocs.py` y PoC adicionales en `.audit/PACK-REVISOR/pocs_cursor_composer.py`.

> **Revisión independiente del código (no del autor).** El informe anterior de la
> 0.3.1 (misma persona que escribió el código) queda como registro histórico al
> final de este documento.

---

## Conflicto de intereses

- [x] No he participado en el desarrollo del código revisado.
- [x] No he ajustado ni creado reglas de detección.
- [ ] Relación con el proyecto: ninguna; la revisión se pidió explícitamente al
  asistente IA con acceso al repositorio local y terminal.

El valor de este informe está en **PoC ejecutados contra el código real**, no solo
en lectura estática. Los hallazgos sin reproducción se etiquetan como hipótesis;
en esta sesión **no hubo ningún `FALLA` reproducible** en el paquete de pruebas.

**Entorno de prueba (seguro para el equipo):** solo `TestClient` de Starlette
(ASGI en memoria), corpus local y scripts bajo `.audit/PACK-REVISOR/`. Sin
escaneo de red externa, sin payloads contra servicios de terceros ni escritura
fuera del repositorio.

---

## Alcance

**Revisado:**

- `src/gatekeeper/` — middleware, body, reglas, config, rate limit, sanitize, CLI
  (lectura por fronteras de confianza).
- Paquete `.audit/PACK-REVISOR/` — 15 comprobaciones base + 6 comprobaciones
  adicionales (`pocs_cursor_composer.py`).
- Métricas de CI reproducidas localmente: `evaluate.py`, `evaluate_heldout.py`,
  `pytest`, cobertura, `bandit`.

**No revisado (y por qué):**

- Servidor ASGI en producción, TLS, red, SO, hardening del despliegue: fuera del
  paquete `gatekeeper-asgi`.
- Pentest black-box contra una aplicación concreta del mantenedor en Internet.
- Fuzzing prolongado de todas las regex ni auditoría de dependencias transitivas
  más allá de lo que ya documenta el proyecto (`pip-audit` en CI).

**Superficie revisada** (fronteras de confianza):

| Frontera | Entrada no confiable | Veredicto |
|---|---|---|
| Body | bytes del cliente | OK (sin bypass confirmado; ver INFO-1 multipart) |
| Ruta y query | del cliente | OK |
| Cabeceras | del cliente | OK |
| Configuración | el operador | OK (config hostil rechazada al arrancar) |
| Log de auditoría | el propio middleware | OK (sin valores de payload) |
| Rate limiter | cliente (IP, XFF) | OK (XFF ignorado sin `trust_proxy`) |
| CLI | ficheros de log | No profundizado en esta sesión |

---

## Método

- Lectura del código por **fronteras de confianza** (body vs app, normalización,
  presupuestos fail-closed, log, proxy/XFF).
- **Pruebas ejecutables:** `python ../../.audit/PACK-REVISOR/ejecutar_pocs.py`
  (15 base + 6 extras).
- Comparación con línea base de `ESTADO.md` y guards de corpus.
- Hipótesis de ataque adicionales: multipart, cross-carrier, `monitor_only`, XFF,
  `max_fields`, doble URL-encoding.

**Herramientas:** Python 3 (entorno local del mantenedor), pytest 2938 tests,
bandit, `tools/evaluate.py --check`, `tools/evaluate_heldout.py --check`.

**Qué NO se ha hecho:** revisión humana presencial; Bug Bounty; análisis dinámico
con tráfico real de producción.

---

## Resumen

| | |
|---|---|
| Hallazgos **corregidos** (esta revisión) | 0 (no se propone código) |
| Hallazgos **pendientes** (bypass confirmado) | **0** |
| Hallazgos **aceptados** (límites documentados verificados) | **2** (INFO) |
| Limitaciones **conocidas** confirmadas | 9+ (tabla abajo) |
| Bypass **confirmado** (ejecutable) | **0** |

**Veredicto en una línea:** el middleware cumple las propiedades críticas que el
proyecto afirma (inspección alineada con la app, fail-closed en presupuestos, log
sin payload, regresiones F6.4/H-1); no se reprodujo ningún bypass nuevo respecto
a la documentación en `docs/amenazas.md`.

**Paquete de pruebas de ataque (esta sesión):** **19 PASA · 0 FALLA · 2 INFO**
(15 comprobaciones del proyecto + 6 del revisor).

---

## Hallazgos

> Un hallazgo es algo que un atacante puede hacer **con el middleware puesto** y
> que el middleware **dice** que frena, y **no** frena. Sin PoC ejecutable es
> hipótesis.

**No se han encontrado hallazgos nuevos** (ningún veredicto `FALLA` en el paquete
completo).

### INFO-1 — SQLi en el contenido de un fichero multipart (límite documentado)

**Gravedad:** informativa (riesgo condicionado a la app) · **Tipo:** límite de
superficie · **Vector:** `multipart/form-data` con payload solo en el body de la
parte archivo.

**Qué pasa**

El parser mínimo de multipart inspecciona nombres de campo y `filename`; el
contenido binario/texto del fichero no se escanea. Coherente con
`docs/amenazas.md`.

**Impacto (medido)**

Petición POST con SQLi en el cuerpo de la parte `file` (no en el nombre):
**HTTP 200** (pasa el middleware).

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py cursor
# Buscar: [INFO] multipart: SQLi en contenido de fichero pasa (limite v0.4)
```

**Qué se rompe**

Solo si la aplicación **ejecuta o interpreta** el contenido subido como SQL o
comando. No contradice lo que Gatekeeper promete inspeccionar.

**Estado:** aceptado (documentado; roadmap v0.4 para parser más completo)

---

### INFO-2 — `monitor_only=True` deja pasar el ataque (modo operativo)

**Gravedad:** informativa · **Vector:** operador deja `monitor_only` en un entorno
donde debería bloquear.

**Impacto (medido)**

SQLi en JSON con `monitor_only=True`: **HTTP 200**; el escaneo registra, no bloquea.

**PoC**

```bash
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py cursor
# [INFO] monitor_only: ataque llega a la app con 200 (esperado)
```

**Estado:** aceptado (`docs/operacion.md`)

---

### Comprobaciones extra — refutadas como bypass (PASA)

| Prueba | Resultado |
|---|---|
| Cross-carrier desactivado (query + body con fragmento SQLi) | **403** |
| XFF distinto sin `trust_proxy`, `rate_limit=1` | 200 luego **429** (peer fijo) |
| `max_fields=5` con 50 claves JSON | **413** |
| Doble URL-encoding en query | **403** |

Implementación de las comprobaciones extra:
`.audit/PACK-REVISOR/pocs_cursor_composer.py`.

---

## Limitaciones conocidas: ¿las aceptas?

| límite | veredicto | por qué |
|---|---|---|
| Contenido de ficheros multipart no inspeccionado | **acepto** | Verificado INFO-1; está en amenazas.md |
| Cuerpos binarios / política octet-stream | **acepto** | Sniff JSON donde aplica; no antimalware |
| Claves JSON no unidas en modo combinado | **acepto** | Diseño documentado |
| Puntero JSON recortado (256 / profundidad) | **acepto** | Consecuencia H-1; regresión verde |
| Reglas propias validadas al arrancar | **acepto** | A-1 corregido en 0.6.0 |
| NFKC expande hasta ~4× | **acepto** | PoC `nfkc` PASA |
| Rate limit en memoria × workers | **acepto** | Redis documentado |
| `monitor_only` no es rollback | **acepto** | INFO-2 |
| App parsea distinto al Content-Type | **acepto** | Frontera honesta |
| CRS ~41 % detección vs ModSecurity completo | **acepto** | Medido; no se vende cobertura total |
| Payload repartido sin `inspect_cross_carrier` | **acepto con matiz** | Activar donde la app concatena inputs |
| `localhost` no bloqueado en SSRF | **acepto** | Trade-off FP; held-out documenta casos |

Lista completa: `docs/amenazas.md`, `CHANGELOG.md`.

---

## Lo que la revisión también comprobó (y estaba bien)

- **H-1 punteros JSON:** 10 000 niveles, pico ~4,3 MiB (~75× entrada), no cuadrático.
- **Regresión F6.4 (`+` en body):** `sleep(10+6)` bloqueado en form, JSON, query,
  cabecera; control `2+2` → 200.
- **Log:** sin valor del payload; nombre de campo acotado ≤256.
- **ReDoS (relación):** ×8 tamaño → ×7,5 tiempo (lineal).
- **Redis caído:** ~2022 ms acotado; fail-open 200 vs fail-closed 503.
- **Body 4× `max_body_size`:** 413 en ~8 ms.
- **Test diferencial** (Starlette/FastAPI): middleware y app interpretan el body igual.
- **Config hostil:** 4 valores inválidos rechazados al instanciar `Config`.
- **NFKC:** no dispara reglas sola.
- **Suite:** **2938** tests passed, 17 skipped (2026-10-27, ~100 s).
- **Cobertura:** **98,65 %** (umbral CI 90 %).
- **bandit** en `src/`: sin hallazgos.
- **Corpus propio:** 160/160 ataques, 0 FP no documentados.
- **Corpus retenido:** 103/109 (94,5 %), 0 FP no documentados.
- **CRS:** 465/1135 (41,0 %), FP 4,7 % (umbrales CI OK).

---

## Evaluación experta (ciberseguridad / pentesting)

Puntuación **del 1 al 100** en dos ejes (mezclarlos engaña):

| Criterio | Nota | Nivel |
|---|---|---|
| Calidad del middleware como **software de seguridad** (diseño, tests, fail-closed, transparencia) | **86/100** | **Profesional** (producto OSS maduro, no appliance WAF enterprise) |
| Efectividad como **único WAF** frente a Internet / sustituto CRS+ModSecurity | **48/100** | Limitado por diseño (41 % CRS, reglas acotadas) |
| **Utilidad para desarrolladores** (FastAPI/Starlette, defensa en profundidad) | **82/100** | Muy recomendable como capa adicional, no como única línea |

**¿Amateur o profesional?** No es amateur: metodología “verificar, no creer”,
corpus retenido, PoC en CI, diferencial body/app. Tampoco es Cloudflare/AWS WAF;
el proyecto lo refleja en cifras y documentación.

**¿Recomendar probarlo en sus apps?**

- **Sí**, como primera línea en APIs FastAPI/Starlette (SQLi, XSS, traversal,
  SSTI, Log4Shell en inputs HTTP típicos), tras un periodo acotado en
  `monitor_only`.
- **No** como sustituto de consultas parametrizadas, validación de esquema,
  authn/authz, CSP, WAF perimetral si el threat model es alto.
- **Config sensata:** `trust_proxy` solo con proxy de confianza; Redis y
  `rate_fail_open=False` si el rate limit importa; `inspect_cross_carrier` si la
  app concatena parámetros; revisar FP documentados (documentación técnica con
  `sleep(5)`, `{{config}}`, etc.).

---

## Cómo reproducir esta revisión

```bash
git clone https://github.com/Eche-Dev/Gatekeeper.git
cd Gatekeeper/gatekeeper-v0.3/gatekeeper
pip install -e ".[dev,servers]"

python ../../.audit/PACK-REVISOR/ejecutar_pocs.py
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py --listar
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py cursor   # solo extras del revisor

pytest -q --timeout=300
pytest --cov=gatekeeper --cov-fail-under=90 -q
bandit -r src -q
python tools/evaluate.py --check
python tools/evaluate_heldout.py --check
```

---

## Trazabilidad

| Revisión | Fecha | Autor | Resultado |
|---|---|---|---|
| Original (PR #18) | 2026-10 | — | Bypasses XFF, reglas incompletas → v0.3 |
| Durante v0.3.x | 2026-10 | — | Varios arreglos (CHANGELOG) |
| Revisión 0.3.1 | 2026-10-24 | autor del código | H-1 DoS punteros; A-1–A-4 (ver histórico abajo) |
| Paquete PACK-REVISOR | 2026-10-27 | — | 15 PoC base; ESTADO.md |
| **Revisión independiente IA** | **2026-10-27** | **Cursor Composer** | **0 bypass confirmado; 19 PASA / 0 FALLA / 2 INFO** |

---

## Anexo A — Conversación que originó esta revisión (2026-10-27)

Resumen fiel de la solicitud del mantenedor y del trabajo realizado. No es
transcripción literal byte a byte del chat, sino registro operativo para
trazabilidad.

### Mensaje del mantenedor (intención)

- Pedía **auditar** el proyecto Gatekeeper (`main` en GitHub).
- Indicaba leer **`.audit/PACK-REVISOR/BRIEFING-IA.md`** y hacer una **revisión
  exhaustiva**.
- Quería que se **probara la herramienta**, se **atacara**, se buscaran
  **vulnerabilidades**, con enfoque de **experto en ciberseguridad y pentesting**.
- Preguntaba **nivel 1–100**, si es **profesional o amateur**, si **recomendaría**
  a desarrolladores probarlo en sus apps.
- Pedía usar un **espacio seguro** de pruebas que no afectara al PC.

### Respuesta del revisor (acciones ejecutadas)

1. Lectura de `BRIEFING-IA.md`, `ALCANCE.md`, `ESTADO.md`, `PLANTILLA-SECURITY-REVIEW.md`,
   `ejecutar_pocs.py` y módulos clave (`middleware.py`, `body.py`, `rules.py`).
2. Ejecución del paquete de PoC en ASGI en memoria (`TestClient`), sin red ofensiva
   externa.
3. Ejecución local de `evaluate.py --check`, `evaluate_heldout.py --check`, pytest
   (2938 passed), cobertura 98,65 %, bandit.
4. Creación de **6 comprobaciones adicionales** en
   `.audit/PACK-REVISOR/pocs_cursor_composer.py` (multipart, cross-carrier,
   monitor_only, XFF, max_fields, doble encoding).
5. Informe con puntuación, recomendación a desarrolladores y veredicto: **0 hallazgos
   de bypass**; **2 INFO** en límites documentados.

### Commit local al cerrar la sesión de documentación

`1946b2b` — *docs(audit): el briefing para una revision de seguridad hecha por una IA*
(coincide con HEAD del repo en el momento de la medición; las cifras cuadran con
`ESTADO.md` generado para `9724daf`).

### Limitación del anexo

Este anexo **no sustituye** el informe técnico anterior: sirve para recordar **qué
se pidió** y **qué se ejecutó**. La evidencia reproducible son los comandos de la
sección «Cómo reproducir».

---

## Anexo B — Informe histórico Gatekeeper v0.3.1 (2026-10-24)

> **No describe el código actual.** Revisión hecha por **quien escribió el código**
> (conflicto de interés declarado). Se conserva como registro; los arreglos
> posteriores están en `CHANGELOG.md`.

**Fecha:** 2026-10-24 · **Commit base:** `8c04456` (rama `feat/plan-verificacion-y-limites`)

### Resumen histórico

| | |
|---|---|
| Hallazgos corregidos | 1 (alto) + 3 menores previos |
| Hallazgos aceptados | 4 |
| Pendientes | 0 |

Hallazgo principal: **DoS de memoria por punteros JSON cuadráticos** (83 KiB →
193,6 MiB; 10 peticiones → ~1,9 GiB). Corregido con punteros acotados en
`body.py`.

### H-1 histórico — DoS punteros JSON *(corregido)*

Amplificación medida antes/después; regresión en `tests/test_dos_punteros_json.py`.

### A-1 — Reglas personalizadas ReDoS *(corregido 0.6.0)*

Análisis estático en `redos.py` al arrancar.

### A-2 — NFKC expande ~4× *(aceptado)*

Coste lineal; no activa reglas sola.

### A-3 — `monitor_only` *(aceptado)*

Documentado en `docs/operacion.md`.

### A-4 — Rate limit memoria × workers *(aceptado)*

Redis recomendado multi-instancia.

### Límites históricos (v0.3.1)

multipart sin inspección de ficheros, binarios, claves JSON en modo combinado,
recorte de puntero, validación de reglas propias.

### PoC históricos (v0.3.1)

```bash
# H-1: amplificación < 100x tras el arreglo
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
```

---

*Documento actualizado: 2026-10-27. Revisión independiente (IA) + registro de
conversación + archivo histórico v0.3.1.*
