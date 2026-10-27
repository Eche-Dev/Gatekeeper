# Estado medido del código revisado

Generado por `generar_estado.py` el 2026-10-27 00:37.

**Commit:** `ae08665` (main, tras el PR #40) · **Paquete:** `gatekeeper-asgi`
0.8.0 publicado, con la fase 6 mergeada y **sin publicar todavía**.

> Estos números son la línea base: lo que el revisor compara con lo que
> mida. Si algo no cuadra con lo que ve, **eso** es un hallazgo.

## Detección y falsos positivos

| corpus | resultado |
|---|---|
| propio (ataques) | **160 / 160** detectados |
| propio (benignos) | 132 benignos · 9 marcados, 9 documentados · FP sin documentar: **0.0** |
| retenido | 103 / 109 (94,5 %) · 0 FP sin documentar |
| CRS (externo) | 465 / 1135 (41,0 %) · 11 / 232 FP (4,7 %) |
| modo cruzado | 7 / 7 |

## Calidad

| comprobación | resultado |
|---|---|
| suite | **2877 tests verdes**, 17 saltados |
| | `2877 passed, 17 skipped, 158 warnings in 82.92s (0:01:22)` |
| cobertura global | **93.62 %** |
| | `TOTAL                           1333     85  93.62%` |

## Paquete de pruebas de ataque

```
RESUMEN: 15 pasan · 0 fallan · 0 notas
```

(15 comprobaciones pasan, 0 fallan.)

## Cómo se mide cada cosa

```bash
cd gatekeeper-v0.3/gatekeeper
python tools/evaluate.py --json          # el corpus propio, en JSON
python -m pytest -q --cov=gatekeeper --cov-report=term   # la suite y la cobertura
python ../../.audit/PACK-REVISOR/ejecutar_pocs.py        # los PoC
```
