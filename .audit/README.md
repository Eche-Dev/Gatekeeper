# `.audit/` — evidencia reproducible de la auditoría

Esta carpeta contiene los bancos de prueba usados en la auditoría de
**Gatekeeper 0.4.0** (`AUDITORIA-2026-10-25.md`) y en el plan verificado
(`PLAN-VERIFICADO-100.md`). Son scripts de solo lectura sobre el código:
**no forman parte del paquete publicado** (`pyproject.toml` solo distribuye
`src/gatekeeper`) y no importan nada del paquete instalado.

## Cómo ejecutarlos

```bash
cd gatekeeper-v0.3/gatekeeper     # el paquete activo
python ../../.audit/<script>.py
```

Todos insertan el `src/` del paquete activo en `sys.path`, así que funcionan
contra tu código local.

| Script | Qué mide o demuestra |
|---|---|
| `redos_bench.py` | Curva de coste de `normalize()`/`scan()` con entradas hostiles crecientes. Cada medición va en un **proceso separado con timeout duro**, para que un ReDoS real no cuelgue la auditoría. `GK_SRC` permite apuntarlo a otra copia del código (por ejemplo, una con el parche aplicado) para comparar. |
| `e2e_dos.py` | Demuestra el DoS de extremo a extremo: una sola petición HTTP con `/*a` repetido. |
| `security_probe.py` | 16 pruebas de ataque: WebSocket, `application/octet-stream`, multipart, punteros JSON >64 niveles, memoria del rate limiter, fuga al log, escape de terminal en la CLI, falsos negativos y falsos positivos. |
| `config_probe.py` | 18 controles de configuración: cadena de proxies, `X-Forwarded-For` falsificado, `blocked_ips` con CIDR, `allow_paths` como trampolín, cabeceras de seguridad del 403, matriz de content-types. |
| `log_leak_probe.py` | Demuestra **en qué casos el payload completo llega al log de auditoría** (nombre de parámetro form-urlencoded y clave JSON). |
| `family_check.py` | Comprueba la atribución de familias: qué reglas SQLi viven en `sensitive_files` y qué pasa con `disabled_rules`. |
| `cross_ai_probe.py` / `cross_ai_probe2.py` | Verificación de las afirmaciones concretas de las auditorías de ChatGPT y Gemini (ReDoS en `custom_rules`, presupuestos de recursos, cadena de confianza del proxy, `exclude_fields`, query reconstruida). |
| `fields_dos.py` / `fields_e2e.py` | Coste por petición según el **número de campos** del body (~67 µs/campo, lineal) y perfil del camino caliente. |

## Fase 3 — detección (FN, FP y corpus)

| Script | Qué mide o demuestra |
|---|---|
| `f3_probe.py` | Los 15 casos de la Fase 3 (4 FN, 2 FP de prosa y 9 referencias): qué detecta cada uno y con qué regla. Es el "antes" reproducible. |
| `f3_ajustes.py` | Para cada firma candidata a endurecer: **cuántos ataques dependen SOLO de ella** (propio, retenido y CRS). Sin ese dato no se puede afirmar que endurecer una firma no pierde detecciones. |
| `f3_payloads.py` | Vuelca los payloads concretos que dependen de las firmas candidatas, para calibrar la regex nueva contra los ataques de verdad y no contra la idea que uno tiene de ellos. |
| `f3_corpus.py` | Los 100 casos nuevos del corpus de falsos positivos (50 de desarrollo + 50 retenidos). `--write` los deja en `corpus/`; sin `--write` solo los mide. |
| `diff_deteccion.py` | Vuelca la detección del corpus de OWASP CRS **payload a payload** (id, familia, esperado, regla que saltó). |
| `compara.py` | Compara dos volcados de `diff_deteccion.py` y lista lo que cambió: cuántos se perdieron, cuántos se ganaron y en qué familia. |
| `rules_f3.py` | Copia de `rules.py` en un **estado intermedio** de la Fase 3. Sirve para reproducir `crs_after2.txt`; el estado final está en el historial de git. |
| `crs_before.txt` / `crs_after.txt` / `crs_after2.txt` / `crs_f3_5.txt` | Los volcados del CRS en cada paso: publicado (0.6.0), tras la primera tanda de la Fase 3, tras la segunda y al final. |
| `REPORT_baseline.md` | El informe del corpus antes de la Fase 3, para ver el diff de cifras sin recalcular nada. |

### Cifras de la Fase 3 (medidas, no estimadas)

| Medida | Antes | Después |
|---|---:|---:|
| Vectores de la lista del plan sin detectar | 4 | **0** |
| Falsos positivos de prosa | 6 | **2** (los otros 4, documentados) |
| Peticiones legítimas en el corpus propio | 81 | **131** |
| Peticiones legítimas en el corpus retenido | 90 | **140** |
| CRS payload a payload | — | **0 perdidos, 0 ganados** |
| Retenido (detección) | 103/109 (94,5 %) | **103/109 (94,5 %)** |

## Cifras de referencia (este equipo, Python 3.14.8)

| Medida | Valor |
|---|---|
| `normalize()` con 128 KB de `/*a` sin cerrar | **23,587 s** (con el parche: **0,009 s**) |
| Una POST de 64 KB, de extremo a extremo | **5,5 s** y responde **200** |
| `normalize()` con 1 MiB de texto legítimo | 0,81 s |
| Coste por campo del body | ~67 µs (20.000 campos → 1,34 s) |
| Rate limiter con 300.000 IPs distintas | **245,8 MB** (859 bytes/IP) |
| Petición con 128 KB tras aplicar el parche | lineal (×2 por duplicación, antes ×4) |

Los números variar entre equipos; las **relaciones** (×4 por duplicación en el
DoS, ×2 por número de campos) se mantienen.
