from __future__ import annotations

import json
import logging
import time

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .body import content_type_of, extract_strings, is_inspectable, read_body, replay
from .config import Config
from .paths import is_path_allowed
from .ratelimit import RateLimiter
from .rules import scan, scan_all

logger = logging.getLogger("gatekeeper")

BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


def _client_ip(scope: Scope, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = _header(scope, b"x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


def _content_length(scope: Scope) -> int | None:
    raw = _header(scope, b"content-length")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


class GatekeeperMiddleware:
    def __init__(self, app: ASGIApp, config: Config | None = None) -> None:
        self.app = app
        self.config = config or Config()
        self.limiter = (
            RateLimiter(self.config.rate_limit, self.config.rate_window)
            if self.config.rate_limit > 0
            else None
        )

    def _audit(self, event: str, ip: str, scope: Scope, **extra: object) -> None:
        # Nunca se registra el contenido del payload, solo la regla y el origen.
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
        await JSONResponse({"detail": detail}, status_code=status, headers=headers)(
            scope, receive, send
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cfg = self.config
        ip = _client_ip(scope, cfg.trust_proxy)

        if ip in cfg.blocked_ips:
            self._audit("blocked_ip", ip, scope)
            await self._reject(403, "Forbidden", scope, receive, send)
            return

        if self.limiter and not self.limiter.allow(ip):
            self._audit("rate_limited", ip, scope)
            await self._reject(
                429, "Too Many Requests", scope, receive, send,
                headers={"Retry-After": str(self.limiter.retry_after(ip))},
            )
            return

        path = scope.get("path", "")
        if cfg.inspect_requests and not is_path_allowed(path, cfg.allow_paths):
            # 1) ruta + query string
            target = path + "?" + scope.get("query_string", b"").decode("latin-1")
            rule = scan(target, cfg.disabled_rules, cfg.compiled_custom)
            if rule:
                self._audit("attack_detected", ip, scope, rule=rule, source="query",
                            blocked=not cfg.monitor_only)
                if not cfg.monitor_only:
                    await self._reject(403, "Forbidden", scope, receive, send)
                    return

            # 2) body (solo JSON y formularios urlencoded)
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

                rule = scan_all(
                    extract_strings(ctype, body), cfg.disabled_rules, cfg.compiled_custom
                )
                if rule:
                    self._audit("attack_detected", ip, scope, rule=rule, source="body",
                                blocked=not cfg.monitor_only)
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
