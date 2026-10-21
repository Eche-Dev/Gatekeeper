from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .rules import RULES

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
    # Backend del rate limit:
    #   "memory" -> un proceso (el límite se multiplica con varios workers)
    #   "redis"  -> compartido entre procesos, requiere el extra [redis]
    rate_backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"
    redis_prefix: str = "gatekeeper:rl:"
    # Política si Redis no responde: True -> se admiten peticiones (disponibilidad)
    # False -> 503 (seguridad estricta). En ambos casos se audita el fallo.
    rate_fail_open: bool = True

    # Detección de patrones
    inspect_requests: bool = True
    monitor_only: bool = False  # True: solo registra, no bloquea
    disabled_rules: set[str] = field(default_factory=set)
    # Reglas propias: {nombre: regex} o [{name:, pattern:}]. Se evalúan sobre texto
    # decodificado y en minúsculas.
    custom_rules: Any = field(default_factory=dict)

    # Inspección del body (solo JSON y application/x-www-form-urlencoded)
    inspect_body: bool = True
    max_body_size: int = 1_048_576  # bytes; si se excede -> 413

    # Rutas exentas de inspección (globs). El rate limit y el bloqueo de IP se mantienen.
    allow_paths: list[str] = field(default_factory=list)

    # Red
    blocked_ips: set[str] = field(default_factory=set)
    trust_proxy: bool = False  # True solo si estás detrás de un proxy de confianza

    # Cabeceras
    security_headers: dict[str, str] | None = None  # None = DEFAULT_SECURITY_HEADERS

    compiled_custom: dict[str, list[re.Pattern[str]]] = field(
        init=False, repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        if self.rate_limit < 0:
            raise ValueError("rate_limit no puede ser negativo")
        if self.rate_window <= 0:
            raise ValueError("rate_window debe ser mayor que 0")
        if self.rate_backend not in ("memory", "redis"):
            raise ValueError("rate_backend debe ser 'memory' o 'redis'")
        if self.rate_backend == "redis" and not self.redis_url:
            raise ValueError("redis_url no puede estar vacío con rate_backend='redis'")
        if self.max_body_size <= 0:
            raise ValueError("max_body_size debe ser mayor que 0")

        rules = self.custom_rules
        if isinstance(rules, list):
            converted: dict[str, str] = {}
            for item in rules:
                if not isinstance(item, dict) or "name" not in item or "pattern" not in item:
                    raise ValueError("Cada regla personalizada necesita 'name' y 'pattern'")
                converted[str(item["name"])] = str(item["pattern"])
            rules = converted
        if not isinstance(rules, dict):
            raise TypeError("custom_rules debe ser un diccionario o una lista")
        self.custom_rules = rules

        for name, pattern in rules.items():
            if not name:
                raise ValueError("Una regla personalizada tiene el nombre vacío")
            if name in RULES:
                raise ValueError(f"La regla personalizada '{name}' choca con una regla integrada")
            if not pattern:
                raise ValueError(f"Regla personalizada '{name}': el patrón está vacío")
            try:
                self.compiled_custom[name] = [re.compile(pattern)]
            except (re.error, OverflowError) as exc:
                raise ValueError(f"Regla personalizada '{name}': patrón inválido ({exc})") from exc

        unknown = set(self.disabled_rules) - set(RULES) - set(rules)
        if unknown:
            raise ValueError(f"disabled_rules contiene reglas inexistentes: {sorted(unknown)}")

    def headers(self) -> dict[str, str]:
        if self.security_headers is None:
            return DEFAULT_SECURITY_HEADERS
        return self.security_headers

    @classmethod
    def from_dict(cls, data: Any) -> Config:
        if not isinstance(data, dict):
            raise TypeError("La configuración debe ser un mapa clave: valor")
        known = {f.name for f in fields(cls) if f.init}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Claves desconocidas en la configuración: {sorted(unknown)}")
        kwargs = dict(data)
        for key in ("disabled_rules", "blocked_ips"):
            if key in kwargs:
                kwargs[key] = set(kwargs[key])
        return cls(**kwargs)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("Instala el extra: pip install 'gatekeeper-asgi[yaml]'") from exc
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict({} if data is None else data)
