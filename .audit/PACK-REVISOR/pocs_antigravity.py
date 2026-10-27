"""Comprobaciones de seguridad independientes — Antigravity.

Contiene las pruebas de concepto (PoC) reproducibles correspondientes a los
hallazgos nuevos descubiertos de forma independiente durante la auditoria de
seguridad de Gatekeeper 0.9.0 (rama fase7-cobertura):

- AG-1: Nombres de campo (`name="..."`) en `multipart/form-data` no se inspeccionan
  pese a estar prometido en documentacion y comentarios del codigo.
- AG-2: Punto y coma entrecomillado en `Content-Type: multipart/form-data; dummy="a; boundary=fake"; boundary=real`
  provoca diferencial de parser frente a Starlette/FastAPI (`_multipart_boundary` hace `split(";")`).
- AG-3: `inspect_cross_carrier=True` ignora los campos de texto de `multipart/form-data`
  (`cross_values` nunca se alimenta cuando `es_multipart` es `True`).
- AG-4: `looks_like_json` solo comprueba UTF-8/ASCII, permitiendo evadir la heuristica
  en `application/octet-stream` o sin `Content-Type` enviando JSON en UTF-16/UTF-32
  que `await request.json()` (`json.loads(bytes)`) decodifica nativamente.
- AG-5: `Config.field_excluded` compara `segmentos[0]` y divide por `/` cualquier nombre,
  desactivando la inspeccion de subarboles JSON enteros (`{"bio": {"sql": "..."}}`) y de
  parametros query con barra (`?evil/bio=...` o `?bio/evil=...`), ademas de compilar
  globs (`_exclude_globs`) con sensibilidad a mayusculas contradiciendo el docstring.
- AG-6: `_header(scope, name)` devuelve solo la primera tupla de cabecera en ASGI,
  permitiendo evadir la inspeccion de `Cookie`/`User-Agent`/`Referer` con cabeceras
  duplicadas (legitimas en HTTP/2 RFC 9113 §8.2.3) y falsificar `X-Forwarded-For`
  detras de proxies que anaden una segunda tupla `x-forwarded-for`.
- AG-7: `analizar_redos` no detecta alternativas solapadas con clases de caracteres
  (`(\\w|\\d)+$`, `([a-z]|a)+$`) ni cuantificadores anidados dentro de grupos con
  flags en linea (`(?:(?i:(a+))+)$`).
- AG-8: `tests/test_prefilter.py` evalua `corpus/attacks.json` sin relleno >= 128 bytes
  (`_UMBRAL_LONGITUD_PREFILTRO = 128`), ocultando que 7 ataques del propio `attacks.json`
  y 59 de `crs_payloads.json` pierden su deteccion cuando tienen >= 128 caracteres.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.redos import analizar_redos
from gatekeeper.rules import scan_detailed

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"

RAIZ_PAQUETE = Path(__file__).resolve().parents[2] / "gatekeeper-v0.3" / "gatekeeper"


def _app_form(**kwargs_cfg: object) -> Starlette:
    async def endpoint(request: Request) -> JSONResponse:
        form = await request.form()
        datos = {
            k: (v.filename if hasattr(v, "filename") else str(v))
            for k, v in form.multi_items()
        }
        return JSONResponse({"recibido": datos})

    app = Starlette(routes=[Route("/form", endpoint, methods=["POST", "GET"])])
    cfg = Config(rate_limit=0, **kwargs_cfg)  # type: ignore[arg-type]
    app.add_middleware(GatekeeperMiddleware, config=cfg)
    return app


def _app_json(**kwargs_cfg: object) -> Starlette:
    async def endpoint(request: Request) -> JSONResponse:
        datos = await request.json()
        return JSONResponse({"recibido": datos})

    app = Starlette(routes=[Route("/json", endpoint, methods=["POST", "GET"])])
    cfg = Config(rate_limit=0, **kwargs_cfg)  # type: ignore[arg-type]
    app.add_middleware(GatekeeperMiddleware, config=cfg)
    return app


# =============================================================================
# AG-1: Nombre de campo (`name="..."`) en multipart/form-data sin inspeccionar
# =============================================================================
def poc_ag1_multipart_field_name(resultados: list[tuple[str, str, str]]) -> None:
    client = TestClient(_app_form(), raise_server_exceptions=False)
    cuerpo = (
        b"--xyz\r\n"
        b'Content-Disposition: form-data; name="1 UNION SELECT password FROM users"\r\n\r\n'
        b"valor_inocuo\r\n"
        b"--xyz--\r\n"
    )
    r_mp = client.post(
        "/form",
        content=cuerpo,
        headers={"content-type": "multipart/form-data; boundary=xyz"},
    )
    r_url = client.post(
        "/form",
        content=b"1+UNION+SELECT+password+FROM+users=valor_inocuo",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    if r_mp.status_code == 403:
        resultados.append((
            PASA,
            "AG-1: nombre de campo multipart con SQLi bloqueado con 403",
            f"multipart={r_mp.status_code}, urlencoded={r_url.status_code}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-1: nombre de campo (`name=...`) en multipart/form-data NO se inspecciona",
            f"multipart devolvio {r_mp.status_code} ({r_mp.text[:80]}) mientras urlencoded devolvio {r_url.status_code}",
        ))


# =============================================================================
# AG-2: Punto y coma entrecomillado antes de boundary en Content-Type multipart
# =============================================================================
def poc_ag2_multipart_quoted_semicolon_boundary(resultados: list[tuple[str, str, str]]) -> None:
    client = TestClient(_app_form(), raise_server_exceptions=False)
    cuerpo = (
        b"--real\r\n"
        b'Content-Disposition: form-data; name="q"\r\n\r\n'
        b"1 UNION SELECT password FROM users\r\n"
        b"--real--\r\n"
    )
    ct = 'multipart/form-data; dummy="a; boundary=fake"; boundary=real'
    r = client.post("/form", content=cuerpo, headers={"content-type": ct})
    if r.status_code == 403:
        resultados.append((
            PASA,
            "AG-2: Content-Type con ';' entrecomillado antes de boundary bloqueado con 403",
            f"estado {r.status_code}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-2: ';' entrecomillado en Content-Type engaña a _multipart_boundary y evade el WAF",
            f"estado {r.status_code}, app recibio: {r.text[:80]}",
        ))


# =============================================================================
# AG-3: inspect_cross_carrier=True ignora los campos de multipart/form-data
# =============================================================================
def poc_ag3_multipart_cross_carrier(resultados: list[tuple[str, str, str]]) -> None:
    client = TestClient(_app_form(inspect_cross_carrier=True), raise_server_exceptions=False)
    cuerpo = (
        b"--xyz\r\n"
        b'Content-Disposition: form-data; name="b"\r\n\r\n'
        b"select password from users\r\n"
        b"--xyz--\r\n"
    )
    r_mp = client.post(
        "/form?a=1%20union",
        content=cuerpo,
        headers={"content-type": "multipart/form-data; boundary=xyz"},
    )
    r_url = client.post(
        "/form?a=1%20union",
        content=b"b=select+password+from+users",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    if r_mp.status_code == 403:
        resultados.append((
            PASA,
            "AG-3: ataque fragmentado entre query y multipart detectado en modo cross-carrier",
            f"multipart={r_mp.status_code}, urlencoded={r_url.status_code}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-3: inspect_cross_carrier=True NO incluye campos de multipart/form-data en cross_values",
            f"multipart={r_mp.status_code} ({r_mp.text[:70]}), urlencoded={r_url.status_code}",
        ))


# =============================================================================
# AG-4: JSON en UTF-16 con Content-Type: application/octet-stream evade looks_like_json
# =============================================================================
def poc_ag4_octet_stream_utf16_json(resultados: list[tuple[str, str, str]]) -> None:
    client = TestClient(_app_json(), raise_server_exceptions=False)
    payload_utf16 = '{"q": "1 UNION SELECT password FROM users"}'.encode("utf-16")
    payload_utf8 = b'{"q": "1 UNION SELECT password FROM users"}'
    r_utf16 = client.post(
        "/json",
        content=payload_utf16,
        headers={"content-type": "application/octet-stream"},
    )
    r_utf8 = client.post(
        "/json",
        content=payload_utf8,
        headers={"content-type": "application/octet-stream"},
    )
    if r_utf16.status_code == 403:
        resultados.append((
            PASA,
            "AG-4: JSON UTF-16 bajo application/octet-stream detectado por looks_like_json",
            f"utf16={r_utf16.status_code}, utf8={r_utf8.status_code}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-4: JSON UTF-16 bajo application/octet-stream evade looks_like_json y llega a request.json()",
            f"utf16={r_utf16.status_code} ({r_utf16.text[:70]}), utf8={r_utf8.status_code}",
        ))


# =============================================================================
# AG-5: Config.field_excluded excluye subarboles JSON enteros y parametros query con '/'
# =============================================================================
def poc_ag5_field_excluded_subtree_and_slash(resultados: list[tuple[str, str, str]]) -> None:
    client = TestClient(_app_json(exclude_fields=["bio", "token*"]), raise_server_exceptions=False)
    r_sub = client.post(
        "/json",
        json={"bio": {"admin_sql": "1 UNION SELECT password FROM users", "rce": "; id"}},
    )
    r_query = client.post(
        "/json?evil/bio=1+UNION+SELECT+password+FROM+users&bio/xss=<script>alert(1)</script>",
        json={"ok": "benigno"},
    )
    r_case = client.post(
        "/json",
        json={"TOKEN_SECRET": "1 UNION SELECT password FROM users"},
    )
    if r_sub.status_code == 403 and r_query.status_code == 403:
        resultados.append((
            PASA,
            "AG-5: exclude_fields=['bio'] no excluye subarboles ni parametros query con '/'",
            f"subarbol={r_sub.status_code}, query={r_query.status_code}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-5: exclude_fields=['bio'] desactiva la inspeccion de cualquier subarbol /bio/* y de parametros ?evil/bio=",
            f"subarbol={r_sub.status_code}, query_con_barra={r_query.status_code}, glob_mayusculas={r_case.status_code}",
        ))


# =============================================================================
# AG-6: Cabeceras HTTP duplicadas en ASGI (Cookie y X-Forwarded-For)
# =============================================================================
def poc_ag6_duplicate_headers_bypass(resultados: list[tuple[str, str, str]]) -> None:
    async def ejecutar() -> tuple[int, int]:
        async def inner_app(scope: dict, receive: object, send: object) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[misc]
            await send({"type": "http.response.body", "body": b"ok"})  # type: ignore[misc]

        mw = GatekeeperMiddleware(
            inner_app,
            config=Config(
                rate_limit=0,
                trust_proxy=True,
                trusted_proxies=1,
                blocked_ips=["198.51.100.99"],
            ),
        )

        async def recv() -> dict[str, object]:
            return {"type": "http.request", "body": b"", "more_body": False}

        resp_cookie: list[dict[str, object]] = []
        async def send_cookie(msg: dict[str, object]) -> None:
            resp_cookie.append(msg)

        scope_cookie = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"cookie", b"session=inocuo"),
                (b"cookie", b"evil=1 UNION SELECT password FROM users"),
            ],
        }
        await mw(scope_cookie, recv, send_cookie)

        resp_xff: list[dict[str, object]] = []
        async def send_xff(msg: dict[str, object]) -> None:
            resp_xff.append(msg)

        scope_xff = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b"203.0.113.1"),
                (b"x-forwarded-for", b"198.51.100.99"),
            ],
        }
        await mw(scope_xff, recv, send_xff)
        return int(resp_cookie[0]["status"]), int(resp_xff[0]["status"])  # type: ignore[arg-type]

    st_cookie, st_xff = asyncio.run(ejecutar())
    if st_cookie == 403 and st_xff == 403:
        resultados.append((
            PASA,
            "AG-6: cabeceras Cookie y X-Forwarded-For duplicadas se combinan e inspeccionan",
            f"cookie={st_cookie}, xff={st_xff}",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-6: _header() lee solo la primera tupla; ignora 2a Cookie y permite falsificar X-Forwarded-For",
            f"2a_cookie_sqli={st_cookie}, 2o_xff_bloqueado={st_xff}",
        ))


# =============================================================================
# AG-7: Evasion del analizador estatico de ReDoS (redos.py)
# =============================================================================
def poc_ag7_redos_analyzer_bypass(resultados: list[tuple[str, str, str]]) -> None:
    patrones = [r"(\w|\d)+$", r"([a-z]|a)+$", r"(?:(?i:(a+))+)$"]
    no_detectados = [p for p in patrones if analizar_redos(p) is None]
    if not no_detectados:
        resultados.append((
            PASA,
            "AG-7: analizar_redos detecta clases solapadas y grupos con flags en linea",
            "3/3 detectados",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-7: analizar_redos NO detecta ReDoS exponencial con clases de caracteres o flags en linea",
            f"aceptados como seguros: {no_detectados}",
        ))


# =============================================================================
# AG-8: 7 ataques de attacks.json y 59 de crs_payloads.json caen con relleno >= 128
# =============================================================================
def poc_ag8_corpus_prefilter_drop(resultados: list[tuple[str, str, str]]) -> None:
    attacks_data = json.loads(
        (RAIZ_PAQUETE / "corpus" / "attacks.json").read_text(encoding="utf-8")
    )["payloads"]
    caidos_propios = [
        item["id"]
        for item in attacks_data
        if scan_detailed("a" * 150 + " " + item["payload"], use_prefilter=False)
        and not scan_detailed("a" * 150 + " " + item["payload"], use_prefilter=True)
    ]
    if not caidos_propios:
        resultados.append((
            PASA,
            "AG-8: ningún payload de corpus/attacks.json se pierde al superar 128 caracteres",
            "0 caidos",
        ))
    else:
        resultados.append((
            FALLA,
            "AG-8: 7 payloads del propio corpus/attacks.json se pierden cuando la entrada mide >= 128 chars",
            f"IDs perdidos: {', '.join(caidos_propios)}",
        ))


COMPROBACIONES = [
    ("ag1_multipart_field_name", poc_ag1_multipart_field_name,
     "AG-1: nombre de campo (name=...) en multipart/form-data sin inspeccionar"),
    ("ag2_multipart_quoted_semicolon", poc_ag2_multipart_quoted_semicolon_boundary,
     "AG-2: punto y coma entrecomillado antes de boundary en Content-Type multipart"),
    ("ag3_multipart_cross_carrier", poc_ag3_multipart_cross_carrier,
     "AG-3: inspect_cross_carrier=True ignora campos de multipart/form-data"),
    ("ag4_octet_stream_utf16_json", poc_ag4_octet_stream_utf16_json,
     "AG-4: JSON UTF-16 bajo application/octet-stream evade looks_like_json"),
    ("ag5_field_excluded_subtree", poc_ag5_field_excluded_subtree_and_slash,
     "AG-5: exclude_fields desactiva subarboles JSON enteros y parametros con '/'"),
    ("ag6_duplicate_headers", poc_ag6_duplicate_headers_bypass,
     "AG-6: cabeceras duplicadas en ASGI evaden inspeccion de Cookie y X-Forwarded-For"),
    ("ag7_redos_analyzer_bypass", poc_ag7_redos_analyzer_bypass,
     "AG-7: analizar_redos no detecta clases solapadas (\\w|\\d)+ ni grupos (?i:(a+))+"),
    ("ag8_corpus_prefilter_drop", poc_ag8_corpus_prefilter_drop,
     "AG-8: 7 payloads de corpus/attacks.json caen en el prefiltro al superar 128 chars"),
]
