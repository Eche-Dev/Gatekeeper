"""Comprobaciones adicionales — revision independiente (Cursor Composer).

Hipotesis de bypass / configuracion hostil. Solo ASGI en memoria (TestClient).
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "gatekeeper-v0.3" / "gatekeeper" / "src"))

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from gatekeeper import Config, GatekeeperMiddleware  # noqa: E402

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"

logging.getLogger("gatekeeper").addHandler(logging.NullHandler())


def _app(**cfg: object) -> Starlette:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return app


def poc_multipart_payload_en_contenido(
    resultados: list[tuple[str, str, str]],
) -> None:
    """El contenido de un fichero multipart no se inspecciona (limite documentado).

    Si el atacante mete SQLi solo en el body del fichero (no en filename),
    el middleware deja pasar: es bypass solo si la app procesa ese contenido.
    """
    boundary = "----gktest"
    cuerpo = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"1' OR '1'='1\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    cliente = TestClient(_app(rate_limit=0))
    estado = cliente.post(
        "/",
        content=cuerpo,
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    ).status_code
    if estado == 200:
        resultados.append(
            (
                INFO,
                "multipart: SQLi en contenido de fichero pasa (limite v0.4)",
                f"estado {estado}; documentado en docs/amenazas.md",
            )
        )
    else:
        resultados.append(
            (
                PASA,
                "multipart: contenido de fichero inspeccionado",
                f"estado {estado}",
            )
        )


def poc_cross_carrier_sin_flag(
    resultados: list[tuple[str, str, str]],
) -> None:
    """Sin inspect_cross_carrier, mitades inocuas en query y body pueden unirse en la app."""
    cliente = TestClient(_app(rate_limit=0, inspect_cross_carrier=False))
    # Cada mitad sola no dispara UNION SELECT tipico en muchos WAFs simples;
    # aqui usamos un caso donde la regla necesita contexto completo.
    q = "1"
    body = json.dumps({"x": " UNION SELECT 1"}).encode()
    estado = cliente.post(
        f"/?id={q}",
        content=body,
        headers={"content-type": "application/json"},
    ).status_code
    if estado == 200:
        resultados.append(
            (
                INFO,
                "cross-carrier desactivado: payload repartido puede pasar",
                f"estado {estado}; activar inspect_cross_carrier mitiga (documentado)",
            )
        )
    else:
        resultados.append(
            (
                PASA,
                "cross-carrier: reparto query+body bloqueado igualmente",
                f"estado {estado}",
            )
        )


def poc_monitor_only_deja_pasar(
    resultados: list[tuple[str, str, str]],
) -> None:
    """monitor_only registra pero no bloquea: no es bypass del escaneo, es modo operativo."""
    cliente = TestClient(_app(rate_limit=0, monitor_only=True))
    estado = cliente.post("/", json={"q": "1' OR '1'='1"}).status_code
    if estado == 200:
        resultados.append(
            (
                INFO,
                "monitor_only: ataque llega a la app con 200 (esperado)",
                "operador debe usar solo en despliegue controlado; docs/operacion.md",
            )
        )
    else:
        resultados.append(
            (FALLA, "monitor_only bloqueo inesperado", f"estado {estado}")
        )


def poc_xff_spoof_sin_trust_proxy(
    resultados: list[tuple[str, str, str]],
) -> None:
    """Sin trust_proxy, XFF no debe usarse para rate limit (peer real)."""
    # Dos peticiones con XFF distinto pero mismo peer: con rate_limit=1 la segunda 429
    cfg = {"rate_limit": 1, "rate_window": 60, "trust_proxy": False}
    cliente = TestClient(_app(**cfg))
    h1 = {"x-forwarded-for": "1.2.3.4"}
    h2 = {"x-forwarded-for": "5.6.7.8"}
    s1 = cliente.get("/", headers=h1).status_code
    s2 = cliente.get("/", headers=h2).status_code
    if s1 == 200 and s2 == 429:
        resultados.append(
            (
                PASA,
                "XFF ignorado sin trust_proxy (rate limit por peer)",
                f"primera {s1}, segunda {s2}",
            )
        )
    elif s1 == 200 and s2 == 200:
        resultados.append(
            (
                FALLA,
                "XFF rota rate limit sin trust_proxy",
                f"ambas {s1}: el atacante evita 429 cambiando XFF",
            )
        )
    else:
        resultados.append(
            (INFO, "rate limit XFF", f"estados {s1}/{s2}")
        )


def poc_presupuesto_campos_fail_closed(
    resultados: list[tuple[str, str, str]],
) -> None:
    """Superar max_fields debe dar 413, no inspeccion parcial silenciosa."""
    limite = 5
    cliente = TestClient(_app(rate_limit=0, max_fields=limite))
    # JSON con muchas claves
    obj = {f"k{i}": "v" for i in range(50)}
    estado = cliente.post("/", json=obj).status_code
    if estado == 413:
        resultados.append(
            (
                PASA,
                "max_fields agotado: fail-closed 413",
                f"50 claves, limite {limite}, estado {estado}",
            )
        )
    elif estado == 200:
        resultados.append(
            (
                FALLA,
                "max_fields: payload paso sin inspeccion completa",
                f"estado {estado}",
            )
        )
    else:
        resultados.append(
            (INFO, "max_fields", f"estado {estado} (puede ser 403 si detecto antes)")
        )


def poc_doble_codificacion_sqli_query(
    resultados: list[tuple[str, str, str]],
) -> None:
    """Intento clasico: %2527 para ' — debe detectarse tras rondas de decode."""
    cliente = TestClient(_app(rate_limit=0))
    ruta = "/?q=1%252527+OR+%2525271%252527%3D%2525271"
    estado = cliente.get(ruta).status_code
    if estado == 403:
        resultados.append(
            (
                PASA,
                "doble codificacion en query bloqueada",
                f"estado {estado}",
            )
        )
    else:
        resultados.append(
            (
                FALLA,
                "doble codificacion en query escapa",
                f"estado {estado}, ruta {ruta[:60]}...",
            )
        )


COMPROBACIONES = [
    (
        "multipart_contenido",
        poc_multipart_payload_en_contenido,
        "SQLi en contenido de fichero multipart (limite conocido)",
    ),
    (
        "cross_carrier",
        poc_cross_carrier_sin_flag,
        "payload repartido query+body sin inspect_cross_carrier",
    ),
    (
        "monitor_only",
        poc_monitor_only_deja_pasar,
        "monitor_only no bloquea (modo operativo)",
    ),
    (
        "xff",
        poc_xff_spoof_sin_trust_proxy,
        "XFF no debe eludir rate limit sin trust_proxy",
    ),
    (
        "max_fields",
        poc_presupuesto_campos_fail_closed,
        "max_fields fail-closed",
    ),
    (
        "doble_encode",
        poc_doble_codificacion_sqli_query,
        "doble URL-encoding en query",
    ),
]
