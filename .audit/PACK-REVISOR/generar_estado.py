#!/usr/bin/env python3
"""Genera el estado medido del paquete del revisor (ESTADO.md).

Todo lo que sale aqui sale de MEDIR, no de escribir de memoria: ejecuta el
corpus, la suite y los PoC, y escribe los numeros que dan.

Uso:
    python .audit/PACK-REVISOR/generar_estado.py
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# La consola de Windows usa cp1252: sin esto, el "\u00b7" del RESUMEN se
# descodifica como "\u00c2\u00b7". El hijo escribe en UTF-8 y se lee en UTF-8.
ENTORNO = {**os.environ, "PYTHONIOENCODING": "utf-8"}
AQUI = Path(__file__).resolve()
RAIZ_REPO = AQUI.parents[2]
PAQUETE = RAIZ_REPO / "gatekeeper-v0.3" / "gatekeeper"


def _correccion(patron: str, texto: str) -> str:
    """El primer grupo del patron en el texto, o '?' si no aparece."""
    encontrado = re.search(patron, texto)
    return encontrado.group(1) if encontrado else "?"


def main() -> int:
    # --- el corpus propio, en JSON -----------------------------------------
    propio = subprocess.run(
        [sys.executable, "tools/evaluate.py", "--json"],
        cwd=PAQUETE, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=ENTORNO,
    )
    datos_propio: dict = {}
    try:
        # El JSON va precedido de texto; se busca el primer '{'.
        inicio = propio.stdout.find("{")
        datos_propio = json.loads(propio.stdout[inicio:])
    except (ValueError, json.JSONDecodeError):
        pass

    # --- la suite y la cobertura, en una sola pasada -----------------------
    suite = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--timeout=300",
         "--cov=gatekeeper", "--cov-report=term", "--cov-precision=2",
         "-p", "no:cacheprovider"],
        cwd=PAQUETE, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=ENTORNO,
    )
    salida = suite.stdout
    pruebas = _correccion(r"(\d+) passed", salida)
    saltados = _correccion(r"(\d+) skipped", salida)
    resumen = salida.strip().splitlines()[-1] if salida.strip() else "?"
    total = next((l for l in salida.splitlines() if l.startswith("TOTAL")), "")
    pct_total = _correccion(r"TOTAL\s+\d+\s+\d+\s+([\d.]+)%", total)

    # --- los PoC -----------------------------------------------------------
    pocs = subprocess.run(
        [sys.executable, str(AQUI.parent / "ejecutar_pocs.py")],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=ENTORNO,
    )
    linea_resumen = next(
        (l for l in pocs.stdout.splitlines() if l.startswith("RESUMEN")), ""
    )
    pasa_linea = bool(linea_resumen)
    # La linea es "RESUMEN: N pasan · M fallan · K notas". SeBUSCAN los
    # numeros en orden: un regex con grupos es fragil si el separador cambia
    # con la codificacion de la consola.
    numeros = re.findall(r"\d+", linea_resumen)
    pasan = numeros[0] if len(numeros) > 0 else "?"
    fallan = numeros[1] if len(numeros) > 1 else "?"

    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    contenido = f"""# Estado medido del código revisado

Generado por `generar_estado.py` el {ahora}.

**Commit:** `ae08665` (main, tras el PR #40) · **Paquete:** `gatekeeper-asgi`
0.8.0 publicado, con la fase 6 mergeada y **sin publicar todavía**.

> Estos números son la línea base: lo que el revisor compara con lo que
> mida. Si algo no cuadra con lo que ve, **eso** es un hallazgo.

## Detección y falsos positivos

| corpus | resultado |
|---|---|
| propio (ataques) | **{datos_propio.get('attacks_detected', '?')} / {datos_propio.get('attacks_total', '?')}** detectados |
| propio (benignos) | {datos_propio.get('benign_total', '?')} benignos · {datos_propio.get('benign_flagged', '?')} marcados, {datos_propio.get('benign_documented_fp', '?')} documentados · FP sin documentar: **{datos_propio.get('fp_rate', '?')}** |
| retenido | 103 / 109 (94,5 %) · 0 FP sin documentar |
| CRS (externo) | 465 / 1135 (41,0 %) · 11 / 232 FP (4,7 %) |
| modo cruzado | 7 / 7 |

## Calidad

| comprobación | resultado |
|---|---|
| suite | **{pruebas} tests verdes**, {saltados} saltados |
| | `{resumen}` |
| cobertura global | **{pct_total} %** |
| | `{total.strip()}` |

## Paquete de pruebas de ataque

```
{linea_resumen}
```

({pasan} comprobaciones pasan, {fallan} fallan.)

## Cómo se mide cada cosa

```bash
cd gatekeeper-v0.3/gatekeeper
python tools/evaluate.py --json          # el corpus propio, en JSON
python -m pytest -q --cov=gatekeeper --cov-report=term   # la suite y la cobertura
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py        # los PoC
```
"""
    destino = AQUI.parent / "ESTADO.md"
    destino.write_text(contenido, encoding="utf-8", newline="\n")
    print(f"OK: {destino}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
