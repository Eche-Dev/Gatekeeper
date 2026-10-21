from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


@dataclass
class Config:
    """Configuración de Gatekeeper. Los valores por defecto son conservadores."""

    # Rate limiting (0 = desactivado)
    rate_limit: int = 100
    rate_window: float = 60.0

    # Detección de patrones
    inspect_requests: bool = True
    monitor_only: bool = False  # True: solo registra, no bloquea
    disabled_rules: set[str] = field(default_factory=set)

    # Red
    blocked_ips: set[str] = field(default_factory=set)
    trust_proxy: bool = False  # True solo si estás detrás de un proxy de confianza

    # Cabeceras
    security_headers: dict[str, str] | None = None  # None = DEFAULT_SECURITY_HEADERS

    def headers(self) -> dict[str, str]:
        if self.security_headers is None:
            return DEFAULT_SECURITY_HEADERS
        return self.security_headers
