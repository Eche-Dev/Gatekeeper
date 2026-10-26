#!/usr/bin/env python3
"""Mide el coste de una peticion cuando Redis NO responde.

El plan de la Fase 6 pide medir el escenario "Redis caido". Con
`rate_fail_open=True` (por defecto) la peticion se admite, pero antes hay que
intentar hablar con Redis: si ese intento tarda, cada peticion lo paga, y eso
es un vector de disponibilidad (el atacante no hace falta: basta con que
Redis se caiga).

Este script mide:
  - cuanto tarda UNA peticion con Redis caido (fail-open y fail-closed);
  - si el fallo es rapido (connection refused) o lento (reintentos);
  - si el timeout es configurable.
"""
from __future__ import annotations

import asyncio
import time

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

# Puerto cerrado: nada escuchando -> connection refused (o reintentos).
URL_CAIDO = "redis://127.0.0.1:6399/0"


def medir(config: Config, etiqueta: str) -> None:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(GatekeeperMiddleware, config=config)
    cliente = TestClient(app)
    t0 = time.perf_counter()
    try:
        respuesta = cliente.get("/")
        estado = str(respuesta.status_code)
    except Exception as exc:  # noqa: BLE001 - aqui interesa el fallo
        estado = f"excepcion: {type(exc).__name__}: {exc}"
    dt = time.perf_counter() - t0
    print(f"{etiqueta}: {dt * 1000:.1f} ms  ->  {estado}")


def main() -> int:
    try:
        import redis  # noqa: F401
    except ImportError:
        print("El extra [redis] no esta instalado: no se puede medir.")
        return 0

    print("Redis caido (puerto cerrado), una peticion:\n")
    medir(
        Config(rate_backend="redis", redis_url=URL_CAIDO, rate_fail_open=True),
        "fail-open (por defecto)",
    )
    medir(
        Config(rate_backend="redis", redis_url=URL_CAIDO, rate_fail_open=False),
        "fail-closed (503)",
    )

    print("\nTimeout configurable en la Config?")
    campos = [f for f in Config.__dataclass_fields__ if "timeout" in f or "redis" in f]
    print(f"   campos con 'timeout' o 'redis': {campos}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
