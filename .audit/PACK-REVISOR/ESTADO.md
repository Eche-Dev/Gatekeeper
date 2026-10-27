# Estado medido del código revisado

Generado por `generar_estado.py` el 2026-10-27 01:38.

**Commit:** `9724daf` (rama `fase7-cobertura`) · **Paquete:** `gatekeeper-asgi`
0.9.0 publicado en PyPI.

> Estos números son la línea base: lo que el revisor compara con lo que
> mida. Si algo no cuadra con lo que ve, **eso** es un hallazgo.
>
> El hash puede no coincidir con el que tengas delante (un merge crea otro):
> lo que hay que comparar son las **cifras**, que se miden sobre el código.

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
| suite | **2938 tests verdes**, 17 saltados |
| | `2938 passed, 17 skipped, 158 warnings in 82.97s (0:01:22)` |
| cobertura global | **98.65 %** |
| | `TOTAL                           1333     18  98.65%` |

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
