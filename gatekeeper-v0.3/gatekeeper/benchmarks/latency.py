#!/usr/bin/env python3
"""Mide la latencia que Gatekeeper añade a cada petición (microsegundos).

No usa red: llama al stack ASGI directamente, así que lo que se mide es solo
el trabajo del middleware (rate limit, inspección de patrones, cabeceras).

Uso:
    python benchmarks/latency.py                 # tabla por consola
    python benchmarks/latency.py --json          # salida legible por máquina
    python benchmarks/latency.py --iterations 3000

Interpreta los números con cuidado: son microsegundos en tu máquina, no en
producción. Sirven para comparar escenarios entre sí y para detectar
regresiones de rendimiento, no como promesa de latencia absoluta.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
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


def make_scope(query: bytes = QUERY_OK) -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": query,
        "root_path": "",
        "headers": [(b"host", b"bench"), (b"user-agent", b"bench")],
        "client": ("203.0.113.9", 40000),
        "server": ("bench", 80),
    }


def measure(app, iterations: int, rounds: int, query: bytes = QUERY_OK) -> list[float]:
    """Devuelve la latencia media por petición (µs) de cada ronda."""

    async def one() -> None:
        await app(make_scope(query), _receive, _send)

    async def run() -> list[float]:
        for _ in range(min(iterations, 500)):  # calentamiento
            await one()
        samples = []
        for _ in range(rounds):
            start = time.perf_counter()
            for _ in range(iterations):
                await one()
            samples.append((time.perf_counter() - start) / iterations * 1e6)
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


def run_benchmark(iterations: int, rounds: int) -> dict:
    # Silencia la salida del logger de auditoría (los eventos se generan igual:
    # json.dumps se ejecuta antes del nivel, así que su coste sigue medido).
    logging.getLogger("gatekeeper").setLevel(logging.CRITICAL)

    results = []
    baseline = None
    for name, config, kwargs in scenarios():
        samples = measure(make_app(config), iterations, rounds, **kwargs)
        median = statistics.median(samples)
        if baseline is None:
            baseline = median
        results.append({
            "scenario": name,
            "median_us": round(median, 2),
            "min_us": round(min(samples), 2),
            "overhead_us": round(median - baseline, 2),
            "overhead_pct": round((median / baseline - 1) * 100, 1),
        })
    return {"iterations": iterations, "rounds": rounds, "results": results}


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    data = run_benchmark(args.iterations, args.rounds)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    print(f"Latencia por petición (µs) — {args.iterations} peticiones x {args.rounds} rondas\n")
    print("| Escenario | µs/petición | µs añadidos | sobre la base |")
    print("|---|---|---|---|")
    for row in data["results"]:
        print(f"| {row['scenario']} | {row['median_us']:.2f} | +{row['overhead_us']:.2f} "
              f"| {row['overhead_pct']:+.0f}% |")
    print("\nLos valores absolutos dependen de tu máquina; compara escenarios entre sí.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
