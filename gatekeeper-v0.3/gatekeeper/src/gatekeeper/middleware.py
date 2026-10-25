from __future__ import annotations

import json
import logging
import time
from urllib.parse import parse_qsl, urlencode

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .body import (
    content_type_of,
    extract_strings,
    extract_strings_and_values,
    is_inspectable,
    read_body,
    replay,
)
from .config import Config
from .paths import is_path_allowed
from .ratelimit import BackendUnavailable, MemoryBackend, RateLimitBackend, RedisBackend
from .rules import scan_detailed

logger = logging.getLogger("gatekeeper")

BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def build_limiter(config: Config) -> RateLimitBackend | None:
    """Crea el backend de rate limiting según la configuración (None = desactivado)."""
    if config.rate_limit <= 0:
        return None
    if config.rate_backend == "memory":
        return MemoryBackend(config.rate_limit, config.rate_window)
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise ImportError(
            'rate_backend="redis" necesita el extra: pip install "gatekeeper-asgi[redis]"'
        ) from exc
    return RedisBackend(
        Redis.from_url(
            config.redis_url,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
            # RESP2 explícito: el cliente redis-py moderno (8.x) hace handshake
            # RESP3 por defecto y un Redis < 6 no lo entiende ("unknown command
            # HELLO"). Forzando RESP2, Gatekeeper habla con cualquier Redis
            # >= 5.0, que es lo que promete el extra [redis]. La ventana
            # deslizante solo usa EVAL/ZADD/ZRANGE: no necesita RESP3.
            protocol=2,
        ),
        config.rate_limit,
        config.rate_window,
        prefix=config.redis_prefix,
    )


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            decoded: str = value.decode("latin-1")
            return decoded
    return None


def _client_ip(scope: Scope, cfg: Config) -> str:
    """IP del cliente para rate limiting y bloqueo.

    Con `trust_proxy`, X-Forwarded-For se lee de DERECHA a IZQUIERDA: cada
    proxy tuyo añade una entrada al final, así que el cliente real es
    `ips[-trusted_proxies]`. La PRIMERA entrada la escribe el cliente — leerla
    (el bug original) permitía rotarla y saltarse el rate limit y `blocked_ips`.
    Si hay `trusted_proxy_cidrs` y el peer no pertenece a ellas, el XFF se
    ignora por completo (nadie cree XFF llegando directo a la app).
    """
    client = scope.get("client")
    peer = client[0] if client else "unknown"
    if not cfg.trust_proxy or not cfg.trusted_peer(peer):
        return peer
    forwarded = _header(scope, b"x-forwarded-for")
    if not forwarded:
        return peer
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    if len(hops) < cfg.trusted_proxies:
        # Cadena inconsistente: alguien saltó el proxy o borró entradas.
        return peer
    return hops[-cfg.trusted_proxies]


def _content_length(scope: Scope) -> int | None:
    raw = _header(scope, b"content-length")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def _query_field(path: str, query: str, cfg: Config) -> str | None:
    """Atribución del campo: el parámetro cuyo nombre/valor coincide, `path`,
    o None si el payload cruza parámetros (la detección es sobre el conjunto)."""
    disabled = cfg.disabled_rules
    extra = cfg.compiled_custom
    for key, value in parse_qsl(query, keep_blank_values=True):
        if scan_detailed(key, disabled, extra, cfg.active_rules):
            return key
        if scan_detailed(value, disabled, extra, cfg.active_rules):
            return key
    if scan_detailed(path, disabled, extra, cfg.active_rules):
        return "path"
    return None


def _query_without_excluded(query: str, cfg: Config) -> str:
    """Reconstruye la query sin los parámetros exentos.

    La detección sigue siendo sobre el objetivo COMPLETO (un payload puede
    cruzar parámetros), pero excluir un campo significa excluirlo de verdad: se
    quita del objetivo lo que el usuario marcó como exento y se escanea el
    resto. Si todo era exento, se devuelve la query original vacía y no hay
    detección sobre ella (pero el path y los headers siguen inspeccionándose).
    """
    if not cfg.exclude_fields:
        return query
    pares = [
        (key, value)
        for key, value in parse_qsl(query, keep_blank_values=True)
        if not cfg.field_excluded(key)
    ]
    return urlencode(pares)


class GatekeeperMiddleware:
    def __init__(self, app: ASGIApp, config: Config | None = None) -> None:
        self.app = app
        self.config = config or Config()
        self.limiter: RateLimitBackend | None = build_limiter(self.config)

    def _audit(self, event: str, ip: str, scope: Scope, **extra: object) -> None:
        # Nunca se registra el contenido del payload: sí la regla, el campo y
        # el patrón que lo disparó, que es lo que hace falta para tunear FP.
        logger.warning(
            json.dumps(
                {
                    "ts": time.time(),
                    "event": event,
                    "ip": ip,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    **extra,
                }
            )
        )

    async def _reject(self, status: int, detail: str, scope: Scope, receive: Receive, send: Send,
                      headers: dict[str, str] | None = None) -> None:
        """Responde con un rechazo, INCLUDINGO las cabeceras de seguridad.

        Las cabeceras de seguridad (nosniff, X-Frame-Options, HSTS...) tienen que
        ir tambien en los rechazos: una respuesta 403 sin `X-Frame-Options` ni
        HSTS es una respuesta MAS débil que la de 200, y el rechazo es
        justamente la respuesta que un atacante puede ver.

        Se envian antes que las de la app para no poder ser sobrescritas por
        ella (la app no deberia poder quitar una cabecera de seguridad del
        middleware).
        """
        cabeceras = {**self.config.headers(), **(headers or {})}
        await JSONResponse({"detail": detail}, status_code=status, headers=cabeceras)(
            scope, receive, send
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cfg = self.config
        ip = _client_ip(scope, cfg)

        blocked_entry = cfg.blocked_match(ip)
        if blocked_entry is not None:
            self._audit("blocked_ip", ip, scope, entry=blocked_entry)
            await self._reject(403, "Forbidden", scope, receive, send)
            return

        if self.limiter:
            try:
                allowed = await self.limiter.allow(ip)
                retry_after = 0 if allowed else await self.limiter.retry_after(ip)
            except BackendUnavailable as exc:
                # Redis no responde: la política (seguir o 503) es rate_fail_open.
                self._audit(
                    "rate_backend_error", ip, scope,
                    fail_open=cfg.rate_fail_open, error=str(exc)[:200],
                )
                if not cfg.rate_fail_open:
                    await self._reject(503, "Service Unavailable", scope, receive, send)
                    return
                allowed = True
            if not allowed:
                self._audit("rate_limited", ip, scope)
                await self._reject(
                    429, "Too Many Requests", scope, receive, send,
                    headers={"Retry-After": str(retry_after)},
                )
                return

        path = scope.get("path", "")
        if cfg.inspect_requests and not is_path_allowed(path, cfg.allow_paths):
            query = scope.get("query_string", b"").decode("latin-1")
            # Los campos exentos se quitan del objetivo ANTES de escanear: la
            # detección sigue cruzando parámetros, pero no sobre lo excluido.
            target = path + "?" + _query_without_excluded(query, cfg)

            # 1) ruta + query string: la detección va sobre el objetivo completo
            #    (un payload puede cruzar parámetros); el campo es atribución.
            hit = scan_detailed(target, cfg.disabled_rules, cfg.compiled_custom,
                                cfg.active_rules)
            individually_detected = hit is not None
            if hit:
                rule, pattern = hit
                self._audit("attack_detected", ip, scope, rule=rule, source="query",
                            field=_query_field(path, query, cfg), pattern=pattern[:160],
                            blocked=not cfg.monitor_only)
                if not cfg.monitor_only:
                    await self._reject(403, "Forbidden", scope, receive, send)
                    return

            # 2) cabeceras inspeccionables: ahí viven los scanners y los
            #    payloads tipo Log4Shell (User-Agent, Referer, Cookie...)
            for header_name in sorted(cfg.inspect_headers):
                if cfg.field_excluded(header_name):
                    continue
                raw_header = _header(scope, header_name.encode("latin-1"))
                if not raw_header:
                    continue
                hit = scan_detailed(raw_header, cfg.disabled_rules, cfg.compiled_custom,
                                    cfg.active_rules)
                if hit:
                    individually_detected = True
                    rule, pattern = hit
                    self._audit("attack_detected", ip, scope, rule=rule, source="header",
                                field=header_name, pattern=pattern[:160],
                                blocked=not cfg.monitor_only)
                    if not cfg.monitor_only:
                        await self._reject(403, "Forbidden", scope, receive, send)
                        return

            # 3) body: cualquier content-type textual (JSON, form, text/plain,
            #    XML o incluso sin content-type); los binarios y multipart no.
            ctype = content_type_of(_header(scope, b"content-type"))
            if (
                cfg.inspect_body
                and scope.get("method") in BODY_METHODS
                and is_inspectable(ctype)
            ):
                declared = _content_length(scope)
                if declared is not None and declared > cfg.max_body_size:
                    self._audit("body_too_large", ip, scope, size=declared)
                    await self._reject(413, "Payload Too Large", scope, receive, send)
                    return

                messages, body = await read_body(receive, cfg.max_body_size)
                if body is None:
                    self._audit("body_too_large", ip, scope, size=None)
                    await self._reject(413, "Payload Too Large", scope, receive, send)
                    return
                receive = replay(messages, receive)

                has_inspectable_body_value = False
                if cfg.inspect_cross_carrier:
                    body_fields, cross_values = extract_strings_and_values(ctype, body)
                else:
                    body_fields = extract_strings(ctype, body)
                    cross_values = []

                for pointer, value in body_fields:
                    if cfg.field_excluded(pointer):
                        continue
                    has_inspectable_body_value = True
                    hit = scan_detailed(value, cfg.disabled_rules, cfg.compiled_custom,
                                        cfg.active_rules)
                    if not hit:
                        continue
                    individually_detected = True
                    rule, pattern = hit
                    self._audit("attack_detected", ip, scope, rule=rule, source="body",
                                field=pointer, pattern=pattern[:160],
                                blocked=not cfg.monitor_only)
                    if not cfg.monitor_only:
                        await self._reject(403, "Forbidden", scope, receive, send)
                        return
                    break  # monitor_only: un evento basta; seguimos hacia la app

                if (
                    cfg.inspect_cross_carrier
                    and not individually_detected
                    and has_inspectable_body_value
                ):
                    # Only non-excluded fields participate; audit never stores
                    # their text. The body size is bounded before this join.
                    cross_body = " ".join(
                        value
                        for pointer, value in cross_values
                        if not cfg.field_excluded(pointer)
                    )
                    hit = (
                        scan_detailed(
                            target,
                            cfg.disabled_rules,
                            cfg.compiled_custom,
                            cfg.active_rules,
                            carriers=[cross_body],
                            allow_cross_carrier=True,
                        )
                        if cross_body
                        else None
                    )
                    if hit:
                        rule, pattern = hit
                        self._audit(
                            "attack_detected",
                            ip,
                            scope,
                            rule=rule,
                            source="query_body",
                            field="request target + body",
                            pattern=pattern[:160],
                            blocked=not cfg.monitor_only,
                        )
                        if not cfg.monitor_only:
                            await self._reject(403, "Forbidden", scope, receive, send)
                            return

        headers = cfg.headers()

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for key, value in headers.items():
                    if key not in h:
                        h[key] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)
