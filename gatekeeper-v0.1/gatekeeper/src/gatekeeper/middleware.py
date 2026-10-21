from __future__ import annotations

import json
import logging
import time

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Config
from .ratelimit import RateLimiter
from .rules import scan

logger = logging.getLogger("gatekeeper")


def _client_ip(scope: Scope, trust_proxy: bool) -> str:
    if trust_proxy:
        for k, v in scope.get("headers", []):
            if k == b"x-forwarded-for":
                return v.decode("latin-1").split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


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

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cfg = self.config
        ip = _client_ip(scope, cfg.trust_proxy)

        if ip in cfg.blocked_ips:
            self._audit("blocked_ip", ip, scope)
            await JSONResponse({"detail": "Forbidden"}, status_code=403)(scope, receive, send)
            return

        if self.limiter and not self.limiter.allow(ip):
            self._audit("rate_limited", ip, scope)
            await JSONResponse(
                {"detail": "Too Many Requests"},
                status_code=429,
                headers={"Retry-After": str(self.limiter.retry_after(ip))},
            )(scope, receive, send)
            return

        if cfg.inspect_requests:
            # v0.1: se inspecciona ruta y query string (no el body).
            target = scope.get("path", "") + "?" + scope.get("query_string", b"").decode("latin-1")
            rule = scan(target, cfg.disabled_rules)
            if rule:
                self._audit("attack_detected", ip, scope, rule=rule, blocked=not cfg.monitor_only)
                if not cfg.monitor_only:
                    await JSONResponse({"detail": "Forbidden"}, status_code=403)(
                        scope, receive, send
                    )
                    return

        headers = cfg.headers()

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for k, v in headers.items():
                    if k not in h:
                        h[k] = v
            await send(message)

        await self.app(scope, receive, send_with_headers)
