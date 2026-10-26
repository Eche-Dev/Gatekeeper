#!/usr/bin/env python3
"""Mide la latencia que Gatekeeper añade a cada petición (microsegundos).

No usa red: llama al stack ASGI directamente, así que lo que se mide es solo
el trabajo del middleware (rate limit, inspección de patrones, cabeceras).

Diseño (B5): percentiles por petición real (p50/p95/p99), no medias por
ronda. La media miente en dos direcciones: la infla una pausa del recolector de
basura y esconde la cola lenta, que es lo que un usuario nota. Medimos cada
petición con `perf_counter_ns` y publicamos la distribución completa.

Cómo comparar dos versiones (lo único fiable):

    python benchmarks/latency.py --save base.json
    # ... cambia el código ...
    python benchmarks/latency.py --baseline base.json

El veredicto es de quien lo ejecuta, no del pipeline. Se intentó un guard
automático en CI y se descartó porque en un runner de CPU compartida el
ruido de la máquina supera a la señal (ver `comparar`).

Uso:
    python benchmarks/latency.py                 # tabla por consola
    python benchmarks/latency.py --json          # salida legible por máquina
    python benchmarks/latency.py --iterations 3000 --rounds 5

Interpreta los números con cuidado: son microsegundos en tu máquina, no en
producción. Sirven para comparar escenarios entre sí y para detectar
regresiones de rendimiento, no como promesa de latencia absoluta.
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
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware

QUERY_OK = b"q=hello+world&page=2"
QUERY_ATTACK = b"q=1+UNION+SELECT+password+FROM+users"
BODY_OK = b'{"comment":"A normal request body"}'
BODY_CROSS_ATTACK = b'{"statement":"select password from users"}'
# Carga grande: 100 KB de body, por debajo del presupuesto de 256 KiB.
BODY_GRANDE = b'{"comment":"' + (b"x" * 100_000) + b'"}'

# NO hay un presupuesto absoluto, y es una decisión con datos.
#
# Se intentó un guard de regresión en CI con un umbral en µs y se descartó
# tras medirlo: en un runner de CPU compartida el RUIDO DE LA MÁQUINA es mayor
# que la señal. Overhead p50 medido con el mismo código: 73µs en un
# portátil sin carga, 220-312µs en un runner saturado (o un portátil al 30%
# de CPU), y 175µs con 200 firmas nuevas añadidas al código. Una máquina
# lenta da un overhead mayor que una regresión real: ningún umbral los
# separa, así que el guard solo podía dar falsos positivos en CI o ser ciego.
#
# Lo que SÍ es fiable es comparar DOS ejecuciones en la MISMA máquina, que es
# lo que hace `--baseline`: guarda el JSON de una corrida y compára otra
# contra él. Ahí sí la diferencia es señal, porque el ruido de fondo es el
# mismo en las dos.


def make_receive(body: bytes = b""):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def _send(message):
    pass


def make_app(config: Config | None = None) -> Starlette:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok, methods=["GET", "POST"])])
    if config is not None:
        app.add_middleware(GatekeeperMiddleware, config=config)
    return app


def make_scope(
    query: bytes = QUERY_OK, method: str = "GET", body: bytes = b""
) -> dict:
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


def measure(
    app,
    iterations: int,
    rounds: int,
    query: bytes = QUERY_OK,
    method: str = "GET",
    body: bytes = b"",
) -> list[float]:
    """Latencia POR PETICIÓN en µs: una muestra por request, de todas las rondas.

    A diferencia de la media por ronda (v0.3), esto captura la cola: una regla
    con backtracking leve se ve en p99 aunque la mediana no se mueva.
    """

    async def one() -> float:
        t0 = time.perf_counter_ns()
        await app(make_scope(query, method, body), make_receive(body), _send)
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
        ("inspección de query (sin body), sin rate limit",
         Config(rate_limit=0), {}),
        ("inspección de body JSON, sin rate limit",
         Config(rate_limit=0), {"method": "POST", "body": BODY_OK}),
        ("cruce query/body opt-in (benigno)",
         Config(rate_limit=0, inspect_cross_carrier=True),
         {"query": b"q=hello", "method": "POST", "body": BODY_OK}),
        ("cruce query/body atacante (403)",
         Config(rate_limit=0, inspect_cross_carrier=True),
         {"query": b"q=union", "method": "POST", "body": BODY_CROSS_ATTACK}),
        ("rate limit solo (sin inspección)",
         Config(inspect_requests=False, inspect_body=False, rate_limit=10_000_000), {}),
        ("completo (inspección + rate limit)",
         Config(rate_limit=10_000_000), {}),
        ("request atacante (bloqueado con 403)",
         Config(rate_limit=10_000_000), {"query": QUERY_ATTACK}),
        ("carga grande (body 100 KB), sin rate limit",
         Config(rate_limit=0), {"method": "POST", "body": BODY_GRANDE}),
    ]


def medir_recursos(
    app,
    iterations: int = 200,
    query: bytes = QUERY_OK,
    method: str = "GET",
    body: bytes = b"",
) -> dict:
    """CPU (µs por peticion) y memoria pico (KiB) de un escenario.

    La CPU se mide con `time.process_time_ns` (tiempo de CPU del proceso, no
    del reloj: si el portatil esta compartido, el reloj incluye la espera de
    otros y la CPU no). La memoria, con `tracemalloc`, que va aparte porque
    multiplica el coste de la medicion: por eso no se mezcla con la latencia.
    """

    async def run() -> tuple[float, float]:
        for _ in range(50):  # calentamiento
            await app(make_scope(query, method, body), make_receive(body), _send)
        tracemalloc.start()
        cpu0 = time.process_time_ns()
        for _ in range(iterations):
            await app(make_scope(query, method, body), make_receive(body), _send)
        cpu1 = time.process_time_ns()
        _actual, pico = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return (cpu1 - cpu0) / 1000.0 / iterations, pico / 1024.0

    cpu_us, pico_kib = asyncio.run(run())
    return {
        "cpu_us": round(cpu_us, 2),
        "pico_memoria_kib": round(pico_kib, 1),
        "iteraciones": iterations,
    }


def medir_redis_caido(iterations: int = 3) -> dict:
    """Cuánto cuesta una peticion cuando Redis no responde.

    El backend de Redis se crea con `socket_connect_timeout=2.0` fijo, asi que
    con Redis caido cada peticion espera ese timeout antes de decidir (y con
    `rate_fail_open=True` la admite igualmente). Se mide aparte, con pocas
    peticiones: con 300 seria esperar 10 minutos.

    Si el extra [redis] no esta instalado, se dice y no se mide.
    """
    try:
        from redis.asyncio import Redis  # noqa: F401
    except ImportError:
        return {"disponible": False}

    config = Config(
        rate_backend="redis",
        redis_url="redis://127.0.0.1:6399/0",  # puerto cerrado
        rate_fail_open=True,
    )
    app = make_app(config)
    muestras: list[float] = []

    async def run() -> None:
        for _ in range(iterations):
            t0 = time.perf_counter()
            await app(make_scope(), make_receive(), _send)
            muestras.append((time.perf_counter() - t0) * 1000.0)

    asyncio.run(run())
    return {
        "disponible": True,
        "peticiones": iterations,
        "ms_por_peticion": round(statistics.fmean(muestras), 1),
        "ms_min": round(min(muestras), 1),
        "ms_max": round(max(muestras), 1),
    }


def medir_ruido(iterations: int, rounds: int, reps: int = 5) -> dict:
    """Ruido entre dos mediciones del MISMO codigo, en la MISMA maquina.

    Es el numero que decide si un umbral en CI puede existir: si el ruido
    entre corridas es mayor que la senal de una regresion real, cualquier
    umbral dara falsos positivos. Comparando dos EJECUCIONES en la misma
    maquina, el ruido de fondo se cancela y la diferencia si es senal.
    """
    valores = []
    for _ in range(reps):
        muestras = measure(make_app(Config(rate_limit=0)), iterations, rounds)
        valores.append(percentile(muestras, 50))
    # La referencia es la MEDIANA, no la primera corrida: la primera medición
    # de un proceso recién arrancado (CPU en reposo, caches frías) no es
    # comparable con las siguientes, y usarlo de referencia inflaba el ruido
    # hasta un 48% que no es real.
    referencia = statistics.median(valores)
    desvios = [abs(v - referencia) / referencia for v in valores] if referencia else [0.0]
    return {
        "repeticiones": reps,
        "p50_us": [round(v, 2) for v in valores],
        "referencia_us": round(referencia, 2),
        "ruido_max_relativo": round(max(desvios), 4),
        "ruido_medio_relativo": round(statistics.fmean(desvios), 4),
    }


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

    specs = scenarios()
    base_nombre, base_config, base_kwargs = specs[0]
    # La línea base se mide UNA vez por repetición, junto al escenario que se
    # evalúa: comparar el p95 de un escenario con una base medida en otro
    # momento mezcla las condiciones de la máquina y ensucia el overhead.
    base_samples = measure(make_app(base_config), iterations, rounds, **base_kwargs)
    baseline = {
        "p50_us": round(percentile(base_samples, 50), 2),
        "p95_us": round(percentile(base_samples, 95), 2),
    }

    results = [{"scenario": base_nombre, **_stats(base_samples, None)}]
    for name, config, kwargs in specs[1:]:
        samples = measure(make_app(config), iterations, rounds, **kwargs)
        row = {"scenario": name, **_stats(samples, baseline)}
        # Para los escenarios que deciden el veredicto del guard, repetimos la
        # medición y nos quedamos con la MEDIANA del overhead p50.
        #
        # Mediana y no mínimo: una pausa del recolector afecta UNA ronda de
        # tres y la mediana la ignora; una regresión real afecta a TODAS y la
        # mediana la conserva. Con el mínimo se filtraba de más (medido: 200
        # firmas nuevas NO disparaban el guard). Un guard que no ve una
        # regresión real no sirve.
        if repeats > 1:
            candidatas = [row["overhead_p50_us"]]
            for _ in range(repeats - 1):
                base_ronda = measure(make_app(base_config), iterations, rounds, **base_kwargs)
                repetida = measure(make_app(config), iterations, rounds, **kwargs)
                candidatas.append(
                    percentile(repetida, 50) - percentile(base_ronda, 50)
                )
            row["overhead_p50_us"] = round(statistics.median(candidatas), 2)
            row["overhead_repeats"] = repeats
        results.append(row)
    return {
        "iterations": iterations,
        "rounds": rounds,
        "repeats": repeats,
        "python": platform.python_version(),
        "platform": platform.system(),
        "results": results,
    }


def comparar(antes: dict, ahora: dict, margen: float = 0.25) -> tuple[bool, list[str]]:
    """Compara DOS mediciones (misma máquina) y dice si el middleware empeoró.

    `margen` es la tolerancia relativa: un escenario se considera regresión si su
    overhead p50 subió más de ese porcentaje respecto a la Medición anterior.
    0.25 = 25% de margen.

    Funciona comparando el OVERHEAD sobre la línea base (no el absoluto), para
    que un cambio en el escenario base no contamine el veredicto. Es la única
    comparación fiable: misma máquina, mismo módulo, misma sesión.
    """
    previos = {r["scenario"]: r for r in antes["results"]}
    regresiones: list[str] = []
    for row in ahora["results"]:
        previo = previos.get(row["scenario"])
        if previo is None or "overhead_p50_us" not in row or "overhead_p50_us" not in previo:
            continue
        antes_us, ahora_us = previo["overhead_p50_us"], row["overhead_p50_us"]
        if antes_us <= 0:
            continue
        cambio = (ahora_us - antes_us) / antes_us
        empeora = ahora_us > antes_us and cambio > margen
        print(f"  [{'REGRESIÓN' if empeora else 'ok':9}] {row['scenario']}: "
              f"{antes_us:.1f}µs → {ahora_us:.1f}µs ({cambio:+.0%})")
        if empeora:
            regresiones.append(
                f"{row['scenario']}: el overhead subió de {antes_us:.1f}µs a "
                f"{ahora_us:.1f}µs ({cambio:+.0%}, margen {margen:+.0%})"
            )
    return not regresiones, regresiones


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=3,
                        help="Veces que se mide cada escenario con veredicto; se "
                             "queda con la MEDIANA para filtrar ruido del sistema.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--save", type=Path, metavar="FICHERO",
                        help="Guarda esta medición en JSON para usarla como base.")
    parser.add_argument("--baseline", type=Path, metavar="FICHERO",
                        help="Compara contra una medición previa (misma máquina).")
    parser.add_argument("--comparar", nargs=2, metavar=("BASE", "NUEVO"),
                        help="Compara dos mediciones YA hechas (misma máquina) sin "
                             "volver a medir: es lo que usa el job `bench` del CI, "
                             "donde el codigo del PR y el de main se miden por "
                             "separado y luego se comparan.")
    parser.add_argument("--margen", type=float, default=0.25,
                        help="Tolerancia relativa del --baseline (0.25 = 25%%).")
    parser.add_argument("--recursos", action="store_true",
                        help="Mide ademas CPU (µs/peticion) y memoria pico (KiB).")
    parser.add_argument("--ruido", action="store_true",
                        help="Mide el ruido entre varias corridas del MISMO codigo: "
                             "es el numero que decide si un umbral en CI es viable.")
    parser.add_argument("--redis-caido", action="store_true",
                        help="Mede el coste de una peticion con Redis sin responder.")
    args = parser.parse_args(argv)

    # El modo --comparar NO mide: solo compara dos mediciones ya hechas. Si
    # midiera aqui, el job `bench` del CI haria tres mediciones en vez de dos
    # (y la tercera, ya con la maquina caliente, no seria comparable).
    if args.comparar:
        base_path, nuevo_path = args.comparar
        for ruta in (base_path, nuevo_path):
            if not Path(ruta).exists():
                print(f"no existe la medición: {ruta}", file=sys.stderr)
                return 2
        antes = json.loads(Path(base_path).read_text(encoding="utf-8"))
        ahora = json.loads(Path(nuevo_path).read_text(encoding="utf-8"))
        print(f"Comparando {nuevo_path} contra {base_path} "
              f"(margen {args.margen:+.0%}, misma máquina):")
        ok, fallos = comparar(antes, ahora, args.margen)
        if not ok:
            print("\nREGRESIÓN DE LATENCIA respecto a la medición base:")
            for fallo in fallos:
                print(f"  - {fallo}")
            return 1
        print("\n✅ sin regresión respecto a la medición base")
        return 0

    data = run_benchmark(args.iterations, args.rounds, args.repeats)

    if args.recursos:
        recursos = []
        for name, config, kwargs in scenarios():
            if name.startswith("sin middleware"):
                continue
            fila = {"scenario": name}
            fila.update(medir_recursos(make_app(config), **{
                k: v for k, v in kwargs.items() if k in {"query", "method", "body"}
            }))
            recursos.append(fila)
        data["recursos"] = recursos

    if args.ruido:
        data["ruido"] = medir_ruido(args.iterations, args.rounds)

    if args.redis_caido:
        data["redis_caido"] = medir_redis_caido()

    if args.save:
        args.save.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"medición guardada en {args.save}")

    if args.baseline:
        if not args.baseline.exists():
            print(f"no existe la medición base: {args.baseline}", file=sys.stderr)
            return 2
        antes = json.loads(args.baseline.read_text(encoding="utf-8"))
        print(f"Comparando contra {args.baseline} "
              f"(margen {args.margen:+.0%}, misma máquina):")
        ok, fallos = comparar(antes, data, args.margen)
        if not ok:
            print("\nREGRESIÓN DE LATENCIA respecto a la medición base:")
            for fallo in fallos:
                print(f"  - {fallo}")
            return 1
        print("\n✅ sin regresión respecto a la medición base")
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

    if "recursos" in data:
        print("\nCPU y memoria por escenario (tracemalloc multiplica el coste, va aparte):")
        print("| Escenario | CPU µs/petición | pico memoria (KiB) |")
        print("|---|---|---|")
        for fila in data["recursos"]:
            print(f"| {fila['scenario']} | {fila['cpu_us']:.1f} | "
                  f"{fila['pico_memoria_kib']:.1f} |")

    if "ruido" in data:
        ruido = data["ruido"]
        print(f"\nRuido entre {ruido['repeticiones']} corridas del MISMO código "
              f"(misma máquina): máx {ruido['ruido_max_relativo']:.1%}, "
              f"medio {ruido['ruido_medio_relativo']:.1%}.")

    if "redis_caido" in data:
        caido = data["redis_caido"]
        if not caido.get("disponible"):
            print("\nRedis caído: el extra [redis] no está instalado, no se puede medir.")
        else:
            print(f"\nRedis caído: {caido['ms_por_peticion']} ms por petición "
                  f"(min {caido['ms_min']}, max {caido['ms_max']}). El timeout de "
                  f"conexión está fijado en 2 s y no es configurable.")

    print("\nPara comparar dos versiones en tu máquina:")
    print("  python benchmarks/latency.py --save base.json")
    print("  # ... cambia el código ...")
    print("  python benchmarks/latency.py --baseline base.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
