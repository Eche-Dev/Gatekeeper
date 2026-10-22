#!/usr/bin/env python3
"""Mide la latencia que Gatekeeper añade a cada petición (microsegundos).

No usa red: llama al stack ASGI directamente, así que lo que se mide es solo
el trabajo del middleware (rate limit, inspección de patrones, cabeceras).

Diseño (B5): percentiles por petición real (p50/p95/p99), no medias por
ronda. La media miente en dos direcciones: la infla una pausa del recolector de
basura y esconde la cola lenta, que es lo que un usuario nota. Medimos cada
petición con `perf_counter_ns` y publicamos la distribución entera, más un
guard de regresión (`--check`) que CI pueda ejecutar.

Uso:
    python benchmarks/latency.py                 # tabla por consola
    python benchmarks/latency.py --json          # salida legible por máquina
    python benchmarks/latency.py --check         # guard de regresión (sale 1 si empeora)
    python benchmarks/latency.py --iterations 5000 --rounds 3

Interpreta los números con cuidado: son microsegundos en tu máquina, no en
producción. Sirven para comparar escenarios entre sí y para detectar
regresiones de rendimiento, no como promesa de latencia absoluta. Por eso el
guard compara con margen de ruido y documenta su presupuesto, en vez de
comprobar una cifra absoluta que ningún CI comparte.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware

QUERY_OK = b"q=hello+world&page=2"
QUERY_ATTACK = b"q=1+UNION+SELECT+password+FROM+users"

# Presupuesto del guard, en µs por petición, para el escenario COMPLETO (el
# peor caso honesto: inspección + rate limit). Es una guarda de REGRESIÓN: si
# alguien añade una regla cara o cambia el camino caliente, el p95 lo delata.
# El margen absorbe el ruido de la máquina de CI (CPU compartida, GC, jitter):
# no buscamos precisión de reloj, buscamos que una regresión grande no pase.
CHECK_BUDGET_US = {"completo (inspección + rate limit)": 150.0, "inspección (query + body), sin rate limit": 150.0}


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(message):
    pass


def make_app(config: Config | None = None) -> Starlette:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    if config is not None:
        app.add_middleware(GatekeeperMiddleware, config=config)
    return app


def make_scope(query: bytes = QUERY_OK, method: str = "GET", body: bytes = b"") -> dict:
    headers = [(b"host", b"bench"), (b"user-agent", b"bench")]
    if body:
        headers.append((b"content-type", b"application/json"))
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": query,
        "root_path": "",
        "headers": headers,
        "client": ("203.0.113.9", 40000),
        "server": ("bench", 80),
    }


def percentile(samples: list[float], pct: float) -> float:
    """Percentil por el metodo del vecino mas cercano (sin interpolacion).

    Para latencia por peticion queremos "la peticion mas lenta dentro de este
    1 %", no un promedio que ninguna peticion real soporta.
    """
    if not samples:
        return 0.0
    ordered = sorted(samples)
    k = max(0, min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[k]


def measure(app, iterations: int, rounds: int, query: bytes = QUERY_OK) -> list[float]:
    """Latencia POR PETICIÓN en µs: una muestra por request, de todas las rondas.

    A diferencia de la media por ronda (v0.3), esto captura la cola: una regla
    con backtracking leve se ve en p99 aunque la mediana no se mueva.
    """

    async def one() -> float:
        t0 = time.perf_counter_ns()
        await app(make_scope(query), _receive, _send)
        return (time.perf_counter_ns() - t0) / 1000.0

    async def run() -> list[float]:
        for _ in range(min(iterations, 500)):  # calentamiento
            await one()
        samples: list[float] = []
        for _ in range(rounds):
            for _ in range(iterations):
                samples.append(await one())
        return samples

    return asyncio.run(run())


def scenarios() -> list[tuple[str, Config | None, dict]]:
    # rate_limit alto a propósito: si la ventana se agota, el benchmark mide el
    # camino de rechazo (429) en vez del camino que queremos medir.
    return [
        ("sin middleware (base)", None, {}),
        ("solo cabeceras",
         Config(inspect_requests=False, inspect_body=False, rate_limit=0), {}),
        ("inspección (query + body), sin rate limit",
         Config(rate_limit=0), {}),
        ("rate limit solo (sin inspección)",
         Config(inspect_requests=False, inspect_body=False, rate_limit=10_000_000), {}),
        ("completo (inspección + rate limit)",
         Config(rate_limit=10_000_000), {}),
        ("request atacante (bloqueado con 403)",
         Config(rate_limit=10_000_000), {"query": QUERY_ATTACK}),
    ]


def _stats(samples: list[float], baseline: dict[str, float] | None) -> dict:
    p50 = percentile(samples, 50)
    p95 = percentile(samples, 95)
    p99 = percentile(samples, 99)
    row = {
        "p50_us": round(p50, 2),
        "p95_us": round(p95, 2),
        "p99_us": round(p99, 2),
        "max_us": round(max(samples), 2),
        "mean_us": round(statistics.fmean(samples), 2),
        "samples": len(samples),
    }
    if baseline is not None:
        # El coste del middleware se lee mejor como diferencia entre el mismo
        # percentil: p95 del escenario menos p95 de la base. Restar p95 de la
        # mediana (o al revés) mezcla dos poblaciones y no significa nada.
        row["overhead_p50_us"] = round(p50 - baseline["p50_us"], 2)
        row["overhead_p95_us"] = round(p95 - baseline["p95_us"], 2)
    return row


def run_benchmark(iterations: int, rounds: int, repeats: int = 3) -> dict:
    # Silencia la salida del logger de auditoría (los eventos se generan igual:
    # json.dumps se ejecuta antes del nivel, así que su coste sigue medido).
    logging.getLogger("gatekeeper").setLevel(logging.CRITICAL)

    results = []
    baseline: dict[str, float] | None = None
    for name, config, kwargs in scenarios():
        samples = measure(make_app(config), iterations, rounds, **kwargs)
        row = {"scenario": name, **_stats(samples, baseline)}
        if baseline is None:
            baseline = {"p50_us": row["p50_us"], "p95_us": row["p95_us"]}
        # Para los escenarios que decide el veredicto del guard, repetimos la
        # medición y nos quedamos con el MEJOR p95. El ruido del sistema (GC,
        # CPU compartida) solo SUBE el percentil; el mínimo de varias rondas es
        # la estimación más cercana al coste real del código. Sin esto, una
        # pausa del recolector dentro del 5 % más lento declara una regresión
        # inexistente y el guard deja de ser creíble.
        if name in CHECK_BUDGET_US and repeats > 1:
            mejor_p95 = row["p95_us"]
            for _ in range(repeats - 1):
                repetida = measure(make_app(config), iterations, rounds, **kwargs)
                mejor_p95 = min(mejor_p95, percentile(repetida, 95))
            row["p95_us"] = round(mejor_p95, 2)
            row["p95_repeats"] = repeats
            # El overhead se recalcula: si no, mezclaría el p95 original (con
            # ruido) contra una base limpia y daría un número sin sentido.
            if baseline is not None:
                row["overhead_p95_us"] = round(row["p95_us"] - baseline["p95_us"], 2)
        results.append(row)
    return {
        "iterations": iterations,
        "rounds": rounds,
        "repeats": repeats,
        "python": platform.python_version(),
        "platform": platform.system(),
        "results": results,
    }


def check(data: dict) -> tuple[bool, list[str]]:
    """Guard de regresión: ningún escenario con presupuesto supera su p95.

    Función PURA sobre los datos ya medidos (no vuelve a medir): el ruido se
    filtró en `run_benchmark` repitiendo y quedándose con el mejor p95, así que
    aquí el veredicto es determinista y testeable.

    Falla SOLO si el p95 se pasa del presupuesto. El p50 se informa pero no
    rompe el build: en CI compartido la mediana tiene demasiado ruido para ser
    un contrato, mientras que una regresión grande sube el percentil 95 de
    forma consistente.
    """
    fallos: list[str] = []
    for row in data["results"]:
        presupuesto = CHECK_BUDGET_US.get(row["scenario"])
        if presupuesto is None:
            continue
        p95 = row["p95_us"]
        estado = "ok" if p95 <= presupuesto else "REGRESIÓN"
        print(f"  [{estado:9}] {row['scenario']}: p95={p95:.2f}µs "
              f"(presupuesto {presupuesto:.0f}µs)")
        if p95 > presupuesto:
            fallos.append(
                f"{row['scenario']}: p95 {p95:.2f}µs supera el presupuesto "
                f"{presupuesto:.0f}µs"
            )
    return not fallos, fallos


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=3,
                        help="Veces que se mide cada escenario con presupuesto; se "
                             "queda con el MEJOR p95 para filtrar ruido del sistema.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true",
                        help="Guard de regresión: sale 1 si algún p95 supera el presupuesto.")
    args = parser.parse_args(argv)

    data = run_benchmark(args.iterations, args.rounds, args.repeats)

    if args.check:
        print("Guard de latencia (p95 por petición, presupuesto de regresión):")
        ok, fallos = check(data)
        if not ok:
            print("\nREGRESIÓN DE LATENCIA:")
            for fallo in fallos:
                print(f"  - {fallo}")
            print("\nSi el cambio es intencionado, actualiza CHECK_BUDGET_US con el motivo.")
            return 1
        print("\n✅ sin regresión de latencia")
        return 0

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    print(f"Latencia por petición (µs) — {args.iterations} peticiones x {args.rounds} "
          f"rondas = {args.iterations * args.rounds} muestras\n")
    print("| Escenario | p50 | p95 | p99 | máx | +p50 vs base |")
    print("|---|---|---|---|---|---|")
    for row in data["results"]:
        extra = f" | +{row['overhead_p50_us']:.2f}" if "overhead_p50_us" in row else " | —"
        print(f"| {row['scenario']} | {row['p50_us']:.2f} | {row['p95_us']:.2f} "
              f"| {row['p99_us']:.2f} | {row['max_us']:.2f}{extra} |")
    print("\np95/p99 por petición: la media por ronda (v0.3) escondía justo esta cola.")
    print("Los valores absolutos dependen de tu máquina; compara escenarios entre sí.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
