"""Segunda ronda: configuracion, proxy, rutas exentas y cabeceras de rechazo."""
from __future__ import annotations

import sys

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

OK, KO = "OK  ", "FALLO"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f"\n        {detail}" if detail else ""))


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home, methods=["GET", "POST"]),
                            Route("/salud", home, methods=["GET", "POST"]),
                            Route("/docs", home, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return TestClient(app)


def test_proxy():
    # Con trust_proxy=True y 1 proxy de confianza, la IP real es la ULTIMA
    # entrada del XFF (la escribe tu proxy). El cliente puede rotar las
    # anteriores: no debe poder saltarse el rate limit.
    c = make_client(rate_limit=1, rate_window=60, trust_proxy=True, trusted_proxies=1)
    r1 = c.get("/", headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2"})
    r2 = c.get("/", headers={"x-forwarded-for": "9.9.9.9, 2.2.2.2"})
    record(OK if r2.status_code == 429 else KO,
           "XFF rotado por el cliente: el rate limit aguanta",
           f"1a={r1.status_code} 2a={r2.status_code} (se espera 200 y 429). "
           "La IP de conteo es la ultima entrada del XFF (la del proxy).")

    # Si el peer NO esta en trusted_proxy_cidrs, el XFF se ignora.
    c2 = make_client(rate_limit=1, rate_window=60, trust_proxy=True,
                     trusted_proxies=1, trusted_proxy_cidrs={"10.0.0.0/8"})
    a = c2.get("/", headers={"x-forwarded-for": "5.5.5.5"})
    b = c2.get("/", headers={"x-forwarded-for": "5.5.5.5"})
    record(OK if b.status_code == 429 else KO,
           "XFF ignorado si el peer no es de confianza",
           f"1a={a.status_code} 2a={b.status_code} (se espera 200 y 429: "
           "el XFF no debe cambiar la identidad del cliente).")

    # blocked_ips con CIDR y el cliente real detras de proxy
    c3 = make_client(rate_limit=0, blocked_ips={"2.2.2.0/24"}, trust_proxy=True,
                     trusted_proxies=1)
    r = c3.get("/", headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2"})
    record(OK if r.status_code == 403 else KO,
           "blocked_ips con CIDR bloquea la IP real detras de proxy",
           f"status={r.status_code} (se espera 403).")


def test_allow_paths():
    c = make_client(allow_paths=["/salud"])
    r = c.get("/salud?q=union%20select%20password%20from%20users")
    record(OK if r.status_code == 200 else KO,
           "allow_paths exime de inspeccion",
           f"status={r.status_code} (se espera 200: la ruta exenta no se inspecciona).")

    # una ruta exenta NO puede servir de trampolin con traversal codificado
    r2 = c.get("/salud/../admin?q=union%20select%20password%20from%20users")
    record(OK if r2.status_code == 403 else KO,
           "allow_paths no es trampolin con traversal codificado",
           f"status={r2.status_code} (se espera 403). paths.py:19 lo bloquea si "
           "la ruta cambia al decodificarse.")

    # el rate limit sigue aplicando en rutas exentas
    c2 = make_client(allow_paths=["/salud"], rate_limit=1, rate_window=60)
    a = c2.get("/salud")
    b = c2.get("/salud")
    record(OK if b.status_code == 429 else KO,
           "allow_paths mantiene el rate limit",
           f"1a={a.status_code} 2a={b.status_code} (se espera 200 y 429).")


def test_reject_headers():
    c = make_client()
    r = c.get("/?q=union%20select%201")
    cabeceras = ["x-content-type-options", "x-frame-options", "strict-transport-security",
                 "referrer-policy"]
    faltan = [h for h in cabeceras if h not in r.headers]
    record(OK if not faltan else KO,
           "El 403 incluye cabeceras de seguridad",
           f"status={r.status_code}; faltan: {faltan or 'ninguna'}.")


def test_content_types():
    """Que content-types dejan de inspeccionarse y cuales si."""
    c = make_client()
    casos = {
        "application/json": True,
        "application/json; charset=utf-8": True,
        "text/plain": True,
        "text/html": True,
        "application/xml": True,
        "": True,
        "application/octet-stream": False,
        "multipart/form-data; boundary=x": False,
        "image/png": False,
        "application/x-www-form-urlencoded": True,
    }
    for ctype, debe_inspeccionar in casos.items():
        r = c.post("/", content=b'{"q":"union select password from users"}',
                   headers={"content-type": ctype} if ctype else {})
        inspeccionado = r.status_code == 403
        marca = OK if inspeccionado == debe_inspeccionar else KO
        record(marca, f"content-type {ctype!r}",
               f"inspeccionado={inspeccionado} (esperado={debe_inspeccionar}), status={r.status_code}")


def test_orden_de_inspeccion():
    """El header se inspecciona aunque el body sea binario."""
    c = make_client()
    r = c.post("/", content=b"binario",
               headers={"content-type": "application/octet-stream",
                        "user-agent": "union select password from users"})
    record(OK if r.status_code == 403 else KO,
           "Las cabeceras se inspeccionan aunque el body sea binario",
           f"status={r.status_code} (se espera 403).")


def main() -> None:
    print("=" * 78)
    print("RONDA 2 - configuracion, proxy, rutas exentas y cabeceras")
    print("=" * 78)
    test_proxy()
    test_allow_paths()
    test_reject_headers()
    test_content_types()
    test_orden_de_inspeccion()
    fallos = sum(1 for s, _, _ in results if s == "FALLO")
    print()
    print(f"RESUMEN: {fallos} hallazgos, {len(results)-fallos} controles correctos")


if __name__ == "__main__":
    main()
