#!/usr/bin/env python3
"""Comprueba que el Redis configurado responde y soporta lo que Gatekeeper necesita.

Es el chequeo de humo del job `redis` de CI: antes de lanzar la suite contra
Redis, verifica que el servicio está vivo y que habla el protocolo que
Gatekeeper usa.

Uso:
    GATEKEEPER_REDIS_URL=redis://127.0.0.1:6379/0 python tools/check_redis.py

Por qué RESP2 explícito:
el cliente `redis-py` moderno (8.x) hace handshake RESP3 por defecto, y un
Redis 5.x o 6.0 no lo entiende ("unknown command HELLO"). Gatekeeper fuerza
RESP2 al conectar (ver `build_limiter` en src/gatekeeper/middleware.py), y este
script comprueba la conexión con la misma opción: si el servicio no acepta
RESP2, Gatekeeper tampoco podría usarlo.

Sale con código 1 si el Redis no responde o no soporta lo necesario.
"""
from __future__ import annotations

import os
import sys

DEFAULT_URL = "redis://127.0.0.1:6379/0"


def main() -> int:
    url = os.environ.get("GATEKEEPER_REDIS_URL", DEFAULT_URL)
    print(f"Redis: {url}")

    try:
        import redis
    except ImportError:
        print("ERROR: falta el extra [redis] (pip install 'gatekeeper-asgi[redis]')")
        return 1

    try:
        client = redis.Redis.from_url(
            url,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
            protocol=2,
        )
        if not client.ping():
            print("ERROR: PING no devolvio True")
            return 1
        info = client.info("server")
        version = info.get("redis_version", "?")
    except Exception as exc:
        print(f"ERROR: no se pudo conectar con Redis: {exc}")
        return 1

    print("PING -> OK")
    print(f"VERSION -> {version}")

    # El script Lua de la ventana deslizante tiene que poder ejecutarse: es lo
    # unico que Redis tiene que soportar de mas alla de los comandos basicos.
    try:
        resultado = client.eval("return 1 + 1", 0)
    except Exception as exc:
        print(f"ERROR: Redis no puede ejecutar scripts Lua: {exc}")
        return 1
    if int(resultado) != 2:
        print(f"ERROR: el script Lua devolvio {resultado}, se esperaba 2")
        return 1

    print("EVAL -> OK (la ventana deslizante puede funcionar)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
