# Recopilación de Auditorías de Seguridad por Modelos de IA (`gatekeeper-asgi` 0.9.0)

Este documento reúne y estructura en formato Markdown limpio las 4 revisiones de seguridad realizadas sobre `gatekeeper-asgi` `0.9.0` (commit `1946b2b`, rama `fase7-cobertura`), junto con el índice de verificación cruzada e informes asociados en `.audit/PACK-REVISOR/`.

## Índice y tabla comparativa de revisiones

| # | Modelo / Revisor | Nota otorgada | Hallazgos reales reproducibles | Informe completo | Script de PoCs |
| :-: | :--- | :---: | :---: | :--- | :--- |
| 1 | **Gemini** | **86 / 100** | **2** (`H-1` boundary duplicado en multipart; `H-2A/B/C` literales faltantes en `PREFILTER_LITERALS` para $\ge 128$ chars) | `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md` | `.audit/PACK-REVISOR/pocs_gemini.py` |
| 2 | **Cursor Composer 2.5 Fast** | **86 / 100** | **0** (solo probó 6 controles de límites ya documentados) | `.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Cursor.md` | `.audit/PACK-REVISOR/pocs_cursor_composer.py` |
| 3 | **ChatGPT (Web)** | **76 / 100** | **0** (revisión teórica y documental sin ejecución de código) | `.audit/Evaluacion-ia/chatgpt.md` | *(Sin script PoC)* |
| 4 | **Claude** | **68 / 100** | **4** (`IA-1` crítico: `/*...*/` en `normalize()` evade 7 familias; `IA-2` body en `GET`/`HEAD`/`OPTIONS`; `IA-3` `Content-Encoding: gzip`; `IA-5` expansión NFKC 18x vs 4x; `IA-4` refutado) | `.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude.md` | `.audit/PACK-REVISOR/pocs_ia.py` |
| 5 | **Antigravity (Verificador + Pentest a fondo)** | **78 / 100** *(95/100 tras parche)* | **8 nuevos + 4 confirmados** (`AG-1` `name=` multipart sin escanear; `AG-2` `;` entrecomillado en boundary; `AG-3` multipart ignorado en `inspect_cross_carrier`; `AG-4` JSON UTF-16 en `octet-stream`; `AG-5` `exclude_fields` excluye subárboles enteros; `AG-6` cabeceras `Cookie`/`XFF` duplicadas en ASGI; `AG-7` bypass de `analizar_redos`; `AG-8` 7 ataques de `attacks.json` y 59 de CRS caen con $\ge 128$ chars) | `.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Antigravity.md` | `.audit/PACK-REVISOR/pocs_antigravity.py` |

---

## 1. Auditoría de Gemini

> **Nota del registro**: Ejecutó la suite completa de tests (`pytest -q --timeout=300`) y el paquete de pruebas `.audit/PACK-REVISOR/ejecutar_pocs.py` junto con `.audit/PACK-REVISOR/pocs_gemini.py`. Publicó su informe en `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md`.

### Informe de Auditoría de Seguridad y Pentesting Independiente: Gatekeeper ASGI

He completado la revisión de seguridad y las pruebas de penetración sobre **Gatekeeper** (`gatekeeper-asgi` `0.9.0`, commit `1946b2b`), siguiendo el procedimiento estricto de `BRIEFING-IA.md` y `ALCANCE.md`.

Las comprobaciones ejecutables han quedado añadidas al ejecutor en `.audit/PACK-REVISOR/pocs_gemini.py` y el informe formal ha sido publicado en `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md`.

#### 1.1. Hallazgos Confirmados con PoC Ejecutable

Al ejecutar `.audit/PACK-REVISOR/ejecutar_pocs.py`, el conjunto total arrojó: **`RESUMEN: 21 pasan · 4 fallan · 2 notas`**.

Los 4 fallos corresponden a dos vectores de evasión (*bypasses*) reproducibles:

```text
[FALLA] H-1: multipart boundary duplicado esquiva la deteccion
         estado 200, la app recibio {'q': '1 UNION SELECT 1'}: Gatekeeper uso el primer boundary y Starlette el segundo
[FALLA] H-2A: prefiltro descarta sensitive_files en peticiones >= 128 caracteres
         4/4 firmas se escapan al anadir padding: requirements.txt, backup.sql.zip, dump.sql, config.bak
[FALLA] H-2B: prefiltro descarta firmas de SQLi en peticiones >= 128 caracteres
         4/4 firmas se escapan al anadir padding: PostgreSQL ::jsonb, SQLite compileoption, Oracle CHR concatenation, SQLi is not
[FALLA] H-2C: prefiltro descarta tag <style> de XSS en textos >= 128 caracteres
         corto: xss, largo: None (el literal <style no esta en PREFILTER_LITERALS['xss'])
```

##### Hallazgo H-1: Evasión en `multipart/form-data` por `boundary` Duplicado (CWE-436 / CWE-444)

- **Mecanismo**: En `body.py`, `_multipart_boundary` extrae el primer `boundary` que aparece en el `Content-Type`. Por el contrario, `python-multipart` (utilizado por Starlette y FastAPI) almacena las opciones en un diccionario donde la última clave sobrescribe a las anteriores.
- **Explotación**: Si un atacante envía:
  ```http
  Content-Type: multipart/form-data; boundary=dummy; boundary=real
  ```
  y envía el cuerpo con `--real`, Gatekeeper busca `--dummy`, no encuentra ninguna parte, no inspecciona ningún campo y deja pasar la petición. La aplicación Starlette/FastAPI procesa el cuerpo con `boundary=real` y recibe el payload (`1 UNION SELECT 1`) con HTTP `200`.
- **Solución**: Iterar guardando el último `boundary` o rechazar con `400` si el parámetro está repetido.

##### Hallazgo H-2: Falsos Negativos Sistemáticos por Prefiltro en Peticiones $\ge 128$ caracteres (CWE-693)

- **Mecanismo**: Para optimizar rendimiento, `rules.py` activa el prefiltro (`_vale_la_pena_prefiltrar`) solo cuando el texto tiene `128` o más caracteres. Si ningún literal de la familia coincide, esa familia se descarta por completo sin evaluar sus expresiones regulares.
- **El problema**: Se añadieron patrones a `RULES` cuyos literales obligatorios no se incluyeron en `PREFILTER_LITERALS`:
  - `sensitive_files`: `requirements.txt`, `composer.json`, `package-lock.json`, `pom.xml`, `.sql`, `.bak`, `backup.sql.zip`, directorios de agentes IA (`.copilot/`, `.aider/`).
  - `sqli`: Inyecciones PostgreSQL JSON (`::jsonb`), SQLite (`sqlite_compileoption_used`), Oracle (`CHR()||CHR()`), negaciones (`'not like`, `'not in`, `is not`).
  - `xss`: Inyecciones con `<style>` y `@import`.
- **Explotación**: En peticiones cortas (como las del corpus de pruebas), el prefiltro está inactivo y devuelve `403`. En cualquier petición real con parámetros adicionales o relleno $\ge 128$ caracteres, el prefiltro descarta la familia y el ataque pasa con HTTP `200`.
- **Solución**: Sincronizar todos los literales en `PREFILTER_LITERALS` y parametrizar `test_prefilter.py` con payloads con padding.

#### 1.2. Lo que se probó y demostró solidez

- **Anti-Spoofing de IP / XFF**: Con `trust_proxy=False`, la cabecera `X-Forwarded-For` no permite eludir `blocked_ips` ni el rate limiter. Con `trust_proxy=True`, la cadena se lee estrictamente de derecha a izquierda.
- **Presupuestos Fail-Closed**: Agotar `max_body_size` o `max_fields` corta en seco con HTTP `413`. Un atacante no puede inundar de campos para evadir la inspección.
- **Auditoría limpia**: Los logs nunca imprimen los payloads del atacante y sanean secuencias de escape ANSI en nombres de campos y rutas.
- **Resistencia a ReDoS**: Verificado comportamiento estrictamente lineal frente a secuencias adversarias de 800.000 caracteres.
- **Decodificación UTF-16**: Los JSON en UTF-16 con BOM bajo `Content-Type: application/json` son interpretados y escaneados correctamente.

#### 1.3. Evaluación Experta (Gemini)

- **¿Qué nivel tiene la herramienta: Amateur o Profesional?**
  - **Nivel: Profesional.** El proyecto está a años luz de un script amateur o un *"wrapper ingenuo de regex"*:
    - Posee una suite de más de 2.900 tests con `98.6%` de cobertura real.
    - Incorpora corpus retenido (`heldout`), validación contra OWASP CRS, pruebas diferenciales ASGI y fuzzing contra ReDoS.
    - La arquitectura entiende los problemas reales de los WAFs de capa de aplicación (normalizaciones Unicode, presupuestos de memoria, serialización de punteros JSON).
    - Los fallos encontrados (`H-1` y `H-2`) son errores sutiles de sincronización entre optimizaciones (el prefiltro literal) y diferencias de especificación en parsers multipart; son el tipo de bugs que aparecen en proyectos de nivel profesional que buscan alto rendimiento.
- **Puntuación (1 al 100): ¿Qué tan útil es en general?**
  - **Puntuación: 86 / 100** (alcanzando **94 / 100** una vez parcheados `H-1` y `H-2`).
  - **Detección y Cobertura (9/10)**: Muy buena selección de firmas para APIs y aplicaciones web modernas, cubriendo SQLi, NoSQL, SSRF cloud, Log4Shell y comandos.
  - **Rendimiento y Huella (9.5/10)**: Coste por petición imperceptible (decenas de microsegundos en cabeceras; menos de un milisegundo en bodies medianos).
  - **Operabilidad y Seguridad Defensiva (9/10)**: Registro de auditoría sin filtración de datos sensibles, rate limiting flexible (memoria o Redis con Lua atómico) y cabeceras de seguridad integradas.
  - **Robustez frente a Bypasses (7/10 en el commit auditado)**: Mermada temporalmente por los dos hallazgos reproducidos (`H-1` y `H-2`).
- **¿Recomiendo que los desarrolladores la prueben en sus aplicaciones?**
  - **Sí, absolutamente recomendable**, teniendo en cuenta las siguientes consideraciones:
    1. **Como defensa en profundidad**: Debe usarse como una capa preventiva ("cinturón de seguridad"), nunca como sustituto de consultas parametrizadas o validación de esquemas (Pydantic).
    2. **Antes de producción**: Es crítico parchear `H-1` (boundary multipart) y sincronizar `PREFILTER_LITERALS` (`H-2`), ya que cualquier atacante que conozca la longitud mínima de prefiltro (`128` bytes) podría evadir firmas clave.
    3. **Modo `monitor_only` inicial**: Se recomienda desplegarla primero con `monitor_only=True` para auditar el tráfico legítimo y calibrar posibles falsos positivos en campos específicos (`exclude_fields`) antes de activar el bloqueo estricto.

---

## 2. Auditoría de Cursor Composer 2.5 Fast

- **Fecha**: `2026-10-27`
- **Autor**: Cursor Composer 2.5 Fast (revisor IA, verificación ejecutada en repo local)
- **Commit medido**: `1946b2b` (HEAD local; la línea base del paquete cita `9724daf` — las cifras coinciden con `ESTADO.md`)
- **Versión**: `gatekeeper-asgi 0.9.0` (según `ALCANCE.md`)

### 2.1. Conflicto de intereses y entorno

- No he participado en el desarrollo del código ni he ajustado reglas de detección.
- Soy un revisor automatizado: el valor de este informe está en PoC ejecutados, no solo en lectura estática.
- **Entorno de prueba (seguro para tu PC)**: solo `TestClient` de Starlette (ASGI en memoria), corpus local y scripts del paquete `.audit/PACK-REVISOR/`. Sin escaneo de red externa, sin payloads contra servicios reales ni escritura fuera del repo.

### 2.2. Método

| Actividad | Resultado |
| :--- | :--- |
| 15 PoC del proyecto + 6 PoC propios (`pocs_cursor_composer.py`) | `19 PASA · 0 FALLA · 2 INFO` |
| `pytest` (2938 tests) | `2938 passed, 17 skipped` |
| Cobertura | `98,65 %` (umbral `90 %`) |
| `bandit -r src` | Sin hallazgos |
| `python tools/evaluate.py --check` | `160/160` ataques, `0` FP no documentados; CRS `41,0 %` |
| `python tools/evaluate_heldout.py --check` | `103/109` (`94,5 %`), `0` FP no documentados |

Revisión por fronteras de confianza (`body`, `query`, cabeceras, presupuestos, `log`, `rate limit`, `config`) y lectura de `middleware.py`, `body.py`, `rules.py` (p. ej. `scan_plus_as_space` vs `scan_plus_literal`).

**No he hecho**: pentest black-box contra una app en producción, fuzzing a largo plazo de regex, ni auditoría del despliegue (nginx, TLS, IAM).

### 2.3. Resumen ejecutivo y hallazgos

| Métrica | Valor |
| :--- | :---: |
| Hallazgos confirmados (bypass / fail-open) | `0` |
| Hallazgos pendientes | `0` |
| Límites documentados confirmados en prueba | `2` (multipart contenido de fichero; `monitor_only`) |
| Bypass confirmado ejecutable | `0` |

El middleware cumple lo que promete en las propiedades que el propio proyecto fija como críticas: divergencia body/app (regresión F6.4), fail-closed en presupuestos, log sin payload, ReDoS acotado en la medición relativa, Redis con timeout.

- **INFO-1 — SQLi en el contenido de un fichero multipart (`200`)**:
  PoC en `pocs_cursor_composer.py`: payload solo en el body de la parte `file`, no en `filename`. Estado `200`. Coherente con `docs/amenazas.md`: se inspeccionan nombres de campo y de fichero, no el binario/texto del archivo.
- **INFO-2 — `monitor_only=True` deja pasar el ataque (`200`)**:
  Es modo operativo documentado, no fallo del motor de reglas.
- **Controles probados**:
  - Cross-carrier sin flag: probé query + body con fragmento SQLi; `403`.
  - XFF sin `trust_proxy`: segunda petición `429` — no rota IP con XFF.
  - `max_fields`: `413` con 50 claves y límite 5.
  - Doble URL-encoding en query: `403`.

### 2.4. Limitaciones conocidas — veredicto del revisor

| Límite | Veredicto | Comentario experto |
| :--- | :---: | :--- |
| Contenido de ficheros multipart no inspeccionado | Acepto | Estándar en muchos WAF ligeros; hay que documentarlo al equipo (ya está). |
| Cuerpos binarios / `octet-stream` | Acepto | Sniff JSON ayuda; no sustituye antivirus ni análisis de malware. |
| CRS ~41 % vs ModSecurity completo | Acepto | Honesto y medido; no vende "100 % OWASP". |
| Payload repartido sin `inspect_cross_carrier` | Acepto con matiz | Riesgo real en apps que concatenan inputs; activar la opción donde aplique. |
| `localhost` / `127.0.0.1` no bloqueados en SSRF | Acepto | Trade-off FP vs SSRF local; la app sigue siendo responsable. |
| `monitor_only` | Acepto | Peligroso si se olvida en prod; es decisión de operación, no de código. |
| Held-out SQLi más débil (variantes finas) | Acepto | 6 FN documentados; corpus retenido hace su trabajo. |

### 2.5. Puntuación (1–100) y nivel profesional

| Criterio | Nota | Nivel |
| :--- | :---: | :--- |
| Calidad del middleware como software de seguridad (diseño, tests, fail-closed, transparencia, mantenibilidad) | **86 / 100** | Profesional (tier "producto open-source maduro", no enterprise WAF appliance) |
| Efectividad como único WAF frente a Internet / sustituto de CRS+ModSecurity | **48 / 100** | Limitado por diseño (41 % CRS, familias acotadas, sin ML, sin correlación avanzada) |
| Utilidad general para desarrolladores (capa extra en FastAPI/Starlette, baja latencia, integración simple) | **82 / 100** | Muy recomendable como defensa en profundidad, no como única línea |

- **¿Recomiendo que desarrolladores lo prueben en sus apps?**
  - **Sí**, en APIs FastAPI/Starlette expuestas como primera línea barata tras un periodo `monitor_only` acotado.
  - **No** como sustituto de consultas parametrizadas, validación de esquema, authn/authz, CSP, subida de ficheros segura ni WAF perimetral.
- **Trazabilidad**:
  - Paquete completo: `python .audit/PACK-REVISOR/ejecutar_pocs.py`
  - Solo extras de Cursor: `python .audit/PACK-REVISOR/ejecutar_pocs.py cursor`

---

## 3. Auditoría de ChatGPT (desde la Web)

### 3.1. Planteamiento y qué se verificó

Separación en cuatro ejes:
1. **Funcionalidad**: si los mecanismos de protección hacen lo que prometen.
2. **Resistencia a ataques**: si se pueden eludir, provocar errores o consumir recursos de forma abusiva.
3. **Calidad de ingeniería**: arquitectura, tratamiento de errores, pruebas, dependencias, mantenibilidad y documentación.
4. **Madurez profesional**: si la herramienta está preparada para que terceros la prueben y utilicen en aplicaciones reales.

#### Métricas leídas de `ESTADO.md` (declaradas por el proyecto, no ejecutadas en la sesión web)

| Métrica | Valor declarado |
| :--- | :--- |
| Repositorio | `Eche-Dev/Gatekeeper` (`gatekeeper-asgi` `0.9.0`) |
| Tests en la línea base | `2.938` (`17` omitidos) |
| Cobertura declarada | `98,65 %` |
| Corpus propio | `160 / 160` (`100 %`) |
| Corpus retenido | `103 / 109` (`94,5 %`) |
| OWASP Core Rule Set (externo) | `465 / 1.135` (`41,0 %` detección, `11/232 = 4,7 %` FP) |

### 3.2. Puntuación provisional de Gatekeeper (ChatGPT)

| Eje evaluado | Puntuación | Observación |
| :--- | :---: | :--- |
| **Utilidad general** | **76 / 100** | Estimación provisional del valor práctico, el alcance y la madurez del proyecto. |
| **Ingeniería y mantenimiento** | **84 / 100** | Arquitectura, automatización, controles de calidad y trazabilidad documentados. |
| **Cobertura de detección generalizable** | **62 / 100** | El corpus retenido da buenos resultados, pero el corpus externo revela límites importantes. |
| **Preparación para uso profesional en producción** | **55 / 100** | Estimación conservadora mientras no se complete la verificación dinámica independiente. |

- **¿Es amateur o profesional?**
  - **Ingeniería**: proyecto serio, de nivel avanzado para un desarrollador independiente.
  - **Seguridad demostrada**: todavía no certificada de forma independiente sin ejecutar la batería dinámica.

### 3.3. Áreas prioritarias de ataque propuestas por ChatGPT

1. **Divergencias en el body HTTP (Prioridad crítica)**: JSON con claves duplicadas, anidamiento profundo, formularios con codificaciones mixtas, diferencias entre UTF-8/Unicode/escapes, cuerpos con distintos `Content-Type` y peticiones sin esa cabecera.
2. **ReDoS y agotamiento de recursos (Prioridad crítica)**: cadenas patológicas, estructuras de backtracking no reconocidas por el validador de `custom_rules`, y el hecho de que el presupuesto de tiempo de inspección (`max_inspection_time_ms`) es **cooperativo** (solo se comprueba entre pasos, no interrumpe una operación bloqueante en curso).
3. **Bypass de SQLi, XSS, SSRF y traversal**: codificación simple, doble y mixta; variaciones de comentarios y separadores; representaciones alternativas de IPs.
4. **Rate limiting y confianza en el proxy**: `X-Forwarded-For` falso, múltiple o malformado; IPv4-mapped IPv6; fallos de Redis.
5. **Logs, CLI y configuración**: escape de terminal, caracteres de control y configuraciones extremas.

### 3.4. Estado de verificación declarado por ChatGPT

| Actividad | Estado |
| :--- | :---: |
| Lectura del briefing, alcance, línea base y plantilla | Revisado |
| Lectura parcial de middleware, reglas, body, config, rate limiter y saneado | Revisado |
| Ejecución de los 15 PoC del proyecto y suite de tests | **No ejecutados** (entorno web sin acceso a la máquina local) |

---

## 4. Auditoría de Claude

> **Informe completo en**: `.audit/PACK-REVISOR/SECURITY_REVIEW-IA-Claude.md`
> **PoCs ejecutables en**: `.audit/PACK-REVISOR/pocs_ia.py`

### 4.1. Veredicto principal: `68 / 100`

> *"Nivel profesional en ingeniería, pero con un bypass crítico activo ahora mismo. No, hoy no lo recomendaría a otros desarrolladores en producción. Con lo que encontré arreglado, sí."*

#### El hallazgo crítico (`IA-1`)

Envolver cualquier payload en `/*...*/` lo esconde de **7 de las 11 familias** (`xss`, `ssti`, `log4shell`, `cmdi`, `crlf`, `path_traversal`, `ssrf`).
- **Causa**: `rules.normalize()` (`src/gatekeeper/rules.py:683`) borra los comentarios SQL (`_strip_sql_comments`) antes de que ninguna familia evalúe el texto, no solo antes de `sqli`.
- **Demostración con ejecución real en aplicación de prueba**:
  1. **SSTI (RCE)**: `/*{{ cycler.__init__.__globals__.os.popen('id').read() }}*/` contra una app Jinja2 real $\rightarrow$ el middleware deja pasar (`200`), la plantilla se ejecuta y devuelve `uid=0(root)`.
  2. **CMDi (RCE)**: `/*$(touch /tmp/pwned)*/` contra una app con `subprocess.run(shell=True)` $\rightarrow$ el comando se ejecuta con el middleware activo en modo bloqueo.
  3. **XSS reflejado**: `/*<script>alert(1)</script>*/` llega intacto al HTML.
- **Solución**: aplicar el mismo patrón de doble lectura que se usó para el `+` en la Fase 6.4 (`_strip_sql_comments` como variante adicional o restringido a `sqli`), sin perder la variante con el texto sin recortar.

#### Otros hallazgos de menor impacto (`IA-2`, `IA-3`, `IA-5`) y controles verificados (`IA-4`)

- **IA-2 (Media)**: Un body en `GET`, `HEAD` u `OPTIONS` no se inspecciona (`BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}` es una lista cerrada en `middleware.py:41`). Afecta a endpoints que leen `await request.json()` en peticiones `GET`.
- **IA-3 (Baja)**: `Content-Encoding: gzip` no se descomprime antes de inspeccionar. Solo explotable si otro componente (proxy o middleware interior) descomprime el body después de Gatekeeper, pero no está mencionado en `docs/amenazas.md`.
- **IA-5 (Documentación)**: `ALCANCE.md` dice que NFKC *"expande hasta 4x"*. Con `\ufdfa` (Sallallahu Alayhi Wasallam) expande **18x en caracteres** y se midió un pico de **97x en memoria (`tracemalloc`)** (25,4 MB de pico con un body de 256 KiB).
- **IA-4 (Control superado — `[PASA]`)**: La IPv4-mapeada-en-IPv6 (`::ffff:203.0.113.7`) ya se normaliza correctamente tanto en `blocked_ips` (`config.py`) como en el rate limiter (`ratelimit.py`).

### 4.2. Desglose de puntuación de Claude (`68 / 100`)

| Área | Nota |
| :--- | :---: |
| Ingeniería, tests, CI | `18 / 20` |
| Honestidad y medición (corpus, CRS, briefing de auditoría) | `18 / 20` |
| Seguridad real (el bypass crítico `IA-1` pesa aquí) | `8 / 20` |
| Documentación | `13 / 15` |
| Cobertura de familias | `11 / 15` |
| Publicación y supply chain | `10 / 10` |
| **Total** | **68 / 100** |

### 4.3. Explicación de Claude sobre por qué calificó con `74/100` la versión `0.4.0` y con `68/100` la `0.9.0`

Ante la pregunta del autor (*"¿Anteriormente la calificaste con 74/100 y ahora 68/100, por qué? ¿He empeorado?"*), Claude aclaró:

1. **No hay regresión del proyecto**: Entre `0.4.0` y `0.9.0` el proyecto mejoró enormemente (WebSocket protegido, `octet-stream` con sniff, `multipart`, rate limiter con tope de claves LRU, IPv4-mapeada-en-IPv6 resuelta, 2.938 tests).
2. **Cambio de rúbrica a petición del autor**: En la revisión de `0.4.0` ("74/100"), el peso de la seguridad del código era el 20 % y el hallazgo principal era un DoS (ReDoS de 21 s con un body de 128 KB). En la revisión de `0.9.0` se aplicó la rúbrica estricta de `BRIEFING-IA.md` y `ALCANCE.md`, donde un bypass que permite **ejecución remota de comandos (RCE)** en 7 de las 11 familias (`IA-1`) penaliza directamente el bloque de "Seguridad real" (`8/20`).
3. **Mayor profundidad de inspección**: Gracias al paquete `.audit/PACK-REVISOR/`, la revisión de `0.9.0` pudo auditar a fondo el pipeline compartido de normalización (`rules.normalize()`), encontrando el defecto de `_strip_sql_comments`. Una vez corregido `IA-1`, la nota de Claude sube por encima de **85 / 100**.
