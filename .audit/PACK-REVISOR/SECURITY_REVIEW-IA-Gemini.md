# Revisión de seguridad — Gatekeeper (`gatekeeper-asgi` 0.9.0)

**Fecha:** 2026-10-27 · **Autor/a:** Gemini (revisión de seguridad y pentesting independiente)
**Contacto:** Auditoría externa solicitada en repositorio local (`Eche-Dev/Gatekeeper`)
**Commit revisado:** [`1946b2b`](https://github.com/Eche-Dev/Gatekeeper/commit/1946b2b1cd2b0234b70f62599a1e4dfbce509c66)
**Versión del paquete:** gatekeeper-asgi 0.9.0 (rama `fase7-cobertura`)

Material de referencia: `.audit/PACK-REVISOR/BRIEFING-IA.md`, `ALCANCE.md`, `ESTADO.md`,
`ejecutar_pocs.py` y suite de pruebas del revisor en `.audit/PACK-REVISOR/pocs_gemini.py`.

---

## Conflicto de intereses

- [x] No he participado en el desarrollo del código revisado.
- [x] No he ajustado ni creado reglas de detección en el paquete base.
- [x] Declaro independencia respecto a las decisiones de diseño del mantenedor.

Esta revisión se fundamenta en **evidencia reproducible mediante código ejecutable**
contra el paquete real (`gatekeeper-asgi`), sin depender de suposiciones estáticas.
Cada hallazgo incluye un PoC ejecutable que reproduce el fallo en el código actual.

---

## Alcance

**Revisado:**

- `gatekeeper-v0.3/gatekeeper/src/gatekeeper/` (los 10 módulos: `middleware.py`, `rules.py`, `body.py`, `config.py`, `ratelimit.py`, `redos.py`, `sanitize.py`, `paths.py`, `cli.py`, `__init__.py`).
- Suite de regresión y corpus de ataque: `tests/`, `corpus/attacks.json`, `corpus/heldout_attacks.json`, `corpus/crs_payloads.json`.
- Paquete de pruebas de concepto `.audit/PACK-REVISOR/ejecutar_pocs.py` junto con `pocs_gemini.py`.

**No revisado (y por qué):**

- Entorno operativo de producción: configuración de servidor ASGI (Uvicorn / Granian), proxies reversos externos (Nginx / Envoy / Cloudflare), TLS y red.
- Dependencias upstream de terceros más allá de la interacción ASGI y Starlette/FastAPI.
- Fuzzing de mutación por horas en búsqueda de DoS en el motor regex de CPython.

**Superficie revisada (las fronteras de confianza):**

| Frontera | Entrada no confiable | Veredicto |
|---|---|---|
| Body (Multipart) | bytes del cliente | **CON HALLAZGO (H-1)**: diferencial de boundary permite evasión completa |
| Body (JSON / Form) | bytes del cliente | OK (UTF-16, JSON anidado y recortes de punteros funcionan según diseño) |
| Ruta y query | del cliente | **CON HALLAZGO (H-2)**: prefiltro descarta firmas al superar 128 chars |
| Cabeceras | del cliente | OK (saneadas, acotadas y evaluadas; XFF protegido) |
| Configuración | el operador | OK (validación en arranque `Config.__post_init__` rechaza valores hostiles) |
| Log de auditoría | el propio middleware | OK (no expone payloads, campos acotados y caracteres de control neutralizados) |
| Rate limiter | el cliente (IP, XFF) | OK (XFF verificado de derecha a izquierda; IPv6 agrupada en /64) |
| CLI | ficheros de log | OK (escapes ANSI/terminal neutralizados) |

---

## Método

- **Auditoría adversaria por fronteras de confianza**: análisis de discrepancia de parsing entre lo que inspecciona el middleware y lo que procesa el framework ASGI subyacente (Starlette / FastAPI / python-multipart).
- **Análisis de pipeline de normalización**: evaluación del flujo `unquote` → `NFKC` → `_strip_sql_comments` → `PREFILTER_LITERALS` → `scan_detailed`.
- **Pruebas de concepto reproducibles**: ejecución directa sobre ASGI en memoria con `TestClient` vía `.audit/PACK-REVISOR/ejecutar_pocs.py pocs_gemini`.
- **Verificación contra el corpus y CRS**: cotejo con `tools/evaluate.py`, `tools/evaluate_heldout.py` y `tools/evaluate_cross.py`.

---

## Resumen

| Métrica | Valor |
|---|---|
| Hallazgos **confirmados con PoC** | **2** (`H-1` Multipart Boundary Smuggling, `H-2` Prefilter Drop on Long Inputs) |
| Hallazgos **pendientes** | **2** |
| Limitaciones conocidas **confirmadas** | 9 |
| Limitaciones conocidas **discutidas** | 1 (exclusión por primer segmento de JSON pointer) |
| Bypasses **confirmados y medidos** | **2** |

**Veredicto en una línea:**
Gatekeeper demuestra un diseño defensivo maduro, exhaustivo y muy por encima del nivel amateur; sin embargo, se han confirmado **dos vulnerabilidades de evasión críticas** (diferencial de parsing en `multipart/form-data` y descarte silencioso de firmas en el prefiltro para peticiones de más de 128 bytes) que deben subsanarse para garantizar su robustez en producción.

---

## Hallazgos

### H-1 — Evasión total de inspección en multipart por discrepancia de parsing de `boundary` duplicado

**Gravedad:** ALTA · **Tipo:** CWE-436 / CWE-444 (Discrepancia en la interpretación de peticiones) · **Vector:** Inyección de parámetro `boundary` duplicado en cabecera `Content-Type`.

**Qué pasa**

En `gatekeeper/body.py` (función `_multipart_boundary`, líneas 189–195):
```python
def _multipart_boundary(content_type: str) -> str | None:
    for piece in content_type.split(";")[1:]:
        nombre, _, valor = piece.strip().partition("=")
        if nombre.strip().lower() == "boundary":
            return valor.strip().strip('"') or None
    return None
```
La función recorre los parámetros y retorna inmediatamente el **primer** `boundary` que encuentra.
Por el contrario, el parser multipart utilizado por Starlette y FastAPI (`python-multipart` / `parse_options_header`) almacena los parámetros en un diccionario clave-valor estándar (`params[key] = value`), de modo que si un parámetro se repite, el **último** sobreescribe a los anteriores.

Si un atacante envía:
`Content-Type: multipart/form-data; boundary=dummy; boundary=real`
y arma el cuerpo de la petición utilizando los separadores `--real`:
1. Gatekeeper toma `boundary=dummy`.
2. Busca `--dummy` en el cuerpo; como no existe, `extract_multipart` retorna una lista vacía `[]`.
3. Gatekeeper no inspecciona ningún campo ni valor y permite continuar la petición.
4. Starlette parsea la petición con `boundary=real`, extrayendo todos los campos y valores maliciosos (SQLi, XSS, Path Traversal) con estado HTTP 200.

**Impacto (medido)**

- Petición normal multipart con `1 UNION SELECT 1`: bloqueada con **403 Forbidden**.
- Petición idéntica con `boundary` duplicado: **200 OK**, la aplicación recibe `{'q': '1 UNION SELECT 1'}` intacto.
- Evasión del 100 % de las reglas de Gatekeeper en cualquier endpoint multipart.

**PoC ejecutable**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py pocs_gemini:multipart_duplicate_boundary
```
Salida medida:
```
[FALLA] H-1: multipart boundary duplicado esquiva la deteccion
         estado 200, la app recibio {'q': '1 UNION SELECT 1'}: Gatekeeper uso el primer boundary y Starlette el segundo
```

**Qué se rompe**

Cualquier endpoint que reciba formularios multipart (subida de archivos, formularios con campos de texto) queda totalmente desprotegido frente a inyecciones si el atacante duplica el atributo `boundary`.

**Corrección propuesta**

Alinear la extracción de parámetros con un diccionario donde la última ocurrencia mande (o rechazar con 400 si `boundary` aparece repetido):
```python
def _multipart_boundary(content_type: str) -> str | None:
    boundary = None
    for piece in content_type.split(";")[1:]:
        nombre, _, valor = piece.strip().partition("=")
        if nombre.strip().lower() == "boundary":
            boundary = valor.strip().strip('"') or None
    return boundary
```

**Estado:** Pendiente.

---

### H-2 — Falsos negativos masivos por omisión de literales en `PREFILTER_LITERALS` en peticiones >= 128 caracteres

**Gravedad:** ALTA · **Tipo:** CWE-693 (Mecanismo de protección insuficiente) / Falso Negativo · **Vector:** Petición con URL o query string >= 128 caracteres (padding o parámetros legítimos).

**Qué pasa**

En `gatekeeper/rules.py` (líneas 846–860):
```python
_PREFILTER_MIN_LEN = 128

def _vale_la_pena_prefiltrar(text: str) -> bool:
    return len(text) >= _PREFILTER_MIN_LEN
```
Para optimizar rendimiento, Gatekeeper evalúa `_posibles_familias(text)` solo cuando `len(text) >= 128`. Si ninguno de los literales de una familia en `PREFILTER_LITERALS` está presente, esa familia **se descarta por completo** sin ejecutar sus expresiones regulares.

Se descubrió que múltiples firmas incorporadas en `RULES` **no tienen sus literales correspondientes en `PREFILTER_LITERALS`**:
1. **`sensitive_files`**: Faltan `requirements.txt`, `composer.json`, `package-lock.json`, `pom.xml`, `.sql`, `.bak`, `backup.sql.zip`, directorios de herramientas IA (`.copilot/`, `.aider/`, etc.).
2. **`sqli`**: Faltan `::jsonb`, `sqlite_compileoption_used`, `CHR(`, negaciones `'not like`, `'not in`, `is not`.
3. **`xss`**: Faltan `<style` y `@import`.

En el corpus de pruebas (`attacks.json` y `heldout_attacks.json`), la inmensa mayoría de payloads son cortos (< 128 bytes), por lo que el prefiltro estaba apagado y las pruebas pasaban (403). Pero en tráfico real o si un atacante añade parámetros irrelevantes (`&dummy=aaaa...`), `len(text) >= 128`, el prefiltro se activa, descarta las familias correspondientes y la petición pasa desapercibida con **200 OK**.

**Impacto (medido)**

- Petición corta `/search?file=/requirements.txt` (< 128 chars): **403 Forbidden**.
- Petición `/search?file=/requirements.txt&pad=aaaa...` (>= 128 chars): **200 OK** (Bypass confirmado).
- Petición `/search?q='{"b":2}'::jsonb&pad=aaaa...`: **200 OK** (Bypass confirmado).
- Petición `/search?file=dump.sql&pad=aaaa...`: **200 OK** (Bypass confirmado).
- Petición con `<style>` en texto largo: **200 OK** (Bypass confirmado).

**PoC ejecutable**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py pocs_gemini:prefilter_sensitive_files pocs_gemini:prefilter_sqli pocs_gemini:prefilter_xss_style
```
Salida medida:
```
[FALLA] H-2A: prefiltro descarta sensitive_files en peticiones >= 128 caracteres
         4/4 firmas se escapan al anadir padding: requirements.txt, backup.sql.zip, dump.sql, config.bak
[FALLA] H-2B: prefiltro descarta firmas de SQLi en peticiones >= 128 caracteres
         4/4 firmas se escapan al anadir padding: PostgreSQL ::jsonb, SQLite compileoption, Oracle CHR concatenation, SQLi is not
[FALLA] H-2C: prefiltro descarta tag <style> de XSS en textos >= 128 caracteres
         corto: xss, largo: None (el literal <style no esta en PREFILTER_LITERALS['xss'])
```

**Qué se rompe**

Cualquier ataque de enumeración de archivos de credenciales/código fuente, SQLi mediante funciones avanzadas o inyecciones de hojas de estilo pasa desapercibido si la petición total tiene más de 128 caracteres.

**Corrección propuesta**

Sincronizar exhaustivamente `PREFILTER_LITERALS` con todas las expresiones regulares de `RULES` y ampliar `test_prefilter.py` para probar sistemáticamente todas las firmas de `RULES` con prefijo de 200 caracteres de relleno.

**Estado:** Pendiente.

---

## Limitaciones conocidas: ¿las aceptas?

| Límite | Veredicto | Justificación del revisor |
|---|---|---|
| `multipart/form-data` no inspecciona contenido binario | **Acepto** | Razonable: analizar binarios/imágenes en streaming en un middleware ASGI introduciría latencia inaceptable y consumo de memoria desproporcionado. |
| Los cuerpos binarios no se inspeccionan | **Acepto** | Coherente con el alcance de un WAF HTTP ligero; el escaneo de malware/antivirus pertenece a otra capa. |
| Claves JSON no se unen en modo cruzado | **Acepto** | Evita falsos positivos en payloads JSON legítimos donde las claves representan nombres de propiedades. |
| Puntero JSON recortado a 256 caracteres | **Acepto** | Medida anti-DoS indispensable frente a amplificación de memoria (H-1 de v0.3.1). |
| Reglas propias se validan al arrancar | **Acepto** | Previene que el propio operador introduzca ReDoS catastróficos en su aplicación. |
| NFKC expande hasta 4× | **Acepto** | Verificado: no genera falsos positivos ni activa reglas por sí sola de forma artificial. |
| Rate limiter en memoria se multiplica por workers | **Acepto** | Inherente a la arquitectura multi-proceso de Python sin IPC compartido; la documentación advierte claramente el uso de Redis en producción. |
| `monitor_only` no es un plan de rollback | **Acepto** | Diseñado como modo de observación para tunear firmas y registrar telemetría. |
| App que parsea body con Content-Type engañoso | **Acepto** | Si el cliente envía `application/pdf` pero la app ejecuta `request.json()`, el middleware no puede adivinar la semántica privada de la app. |
| Exclusión por primer segmento de JSON pointer | **Discuto** | En `Config.field_excluded()`, comparar `segmentos[0]` puede provocar que excluir un campo de primer nivel desactive la inspección de todo el subárbol JSON sin que el operador sea plenamente consciente. |

---

## Lo que la revisión también comprobó (y estaba bien)

- **Prevención de IP Spoofing**: Con `trust_proxy=False`, las cabeceras `X-Forwarded-For` no permiten falsear la IP de cliente ni evadir `blocked_ips` ni el rate limiter. Con `trust_proxy=True`, se respeta el conteo de saltos de derecha a izquierda.
- **Fail-closed en presupuestos de inspección**: Al superar `max_body_size` o `max_fields`, Gatekeeper responde con HTTP 413, imposibilitando que un atacante consuma el presupuesto para pasar inadvertido.
- **Auditoría limpia y segura**: El logger de eventos no filtra valores de payload y sanea secuencias de escape ANSI/terminal en nombres de campo y rutas.
- **Manejo de UTF-16 en JSON**: Cuerpos JSON codificados en UTF-16 con BOM son interpretados y escaneados correctamente por Gatekeeper.
- **Resistencia a ReDoS**: Escaneo lineal verificado con rachas patológicas de 800.000 caracteres.

---

## Trazabilidad

| Revisión | Fecha | Autor | Resultado |
|---|---|---|---|
| Original (PR #18) | 2026-10 | — | 4 bypasses de XFF, 3 reglas incompletas corregidos |
| Revisión 0.3.1 | 2026-10-24 | Autor original | H-1 (DoS punteros JSON corregido); límites A-1 a A-4 documentados |
| Revisión preliminar IA | 2026-10-27 | Cursor Composer | 0 fallas reproducidas en suite base |
| **Revisión de Seguridad y Pentesting** | **2026-10-27** | **Gemini** | **2 hallazgos confirmados con PoC ejecutables (`H-1` y `H-2`); límites auditados** |
