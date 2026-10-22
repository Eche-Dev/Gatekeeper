from __future__ import annotations

import ipaddress
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

# Cabeceras cuyo valor se inspecciona (además de ruta, query y body): las vías
# típicas de scanners y de payloads tipo Log4Shell.
DEFAULT_INSPECT_HEADERS = frozenset({"user-agent", "referer", "cookie", "x-forwarded-for"})

_IPvNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """IP normalizada (`::ffff:1.2.3.4` → `1.2.3.4`) o None si no es una IP."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped or addr


def _compile_ips(
    entries: set[str], context: str, allow_literal: bool
) -> tuple[frozenset[str], tuple[tuple[str, _IPvNetwork], ...]]:
    """Separa identificadores literales de redes CIDR compiladas.

    Una entrada que parece IP/máscara (contiene `/` o `:`, o es un cuadrante
    completo) DEBE parsear: un typo en una máscara es silencioso en producción
    y eso deja al usuario creído que bloquea una red cuando no lo hace.
    Lo demás (p. ej. `testclient`, `unknown`) queda como literal si se permite.
    """
    literals: set[str] = set()
    nets: list[tuple[str, _IPvNetwork]] = []
    for raw in entries:
        entry = str(raw).strip()
        if not entry:
            raise ValueError(f"{context}: entrada vacía")
        looks_ip = "/" in entry or ":" in entry or entry.count(".") == 3
        try:
            nets.append((entry, ipaddress.ip_network(entry, strict=False)))
        except ValueError:
            if looks_ip or not allow_literal:
                raise ValueError(f"{context}: '{entry}' no es una IP ni una red CIDR válida") from None
            literals.add(entry)
    return frozenset(literals), tuple(nets)


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

    # Inspección del body: TODO content-type textual (JSON, form, text/plain,
    # XML o incluso sin content-type); solo se saltan binarios y multipart (v0.4).
    inspect_body: bool = True
    max_body_size: int = 1_048_576  # bytes; si se excede -> 413

    # Cabeceras cuyo valor se inspecciona con las mismas reglas (en minúsculas;
    # vacío = desactivado).
    inspect_headers: set[str] = field(default_factory=lambda: set(DEFAULT_INSPECT_HEADERS))

    # Rutas exentas de inspección (globs). El rate limit y el bloqueo de IP se mantienen.
    allow_paths: list[str] = field(default_factory=list)

    # Red
    # IP exacta, CIDR ("10.0.0.0/8") o identificador literal del peer ("unknown").
    blocked_ips: set[str] = field(default_factory=set)
    trust_proxy: bool = False  # True solo si estás detrás de un proxy de confianza
    # Cuántos proxies tuyos hay en la cadena. X-Forwarded-For se lee de DERECHA
    # a IZQUIERDA: tu último proxy escribe la última entrada, así que el cliente
    # real es ips[-trusted_proxies]. Leer ips[0] (el bug original) daba el valor
    # que escribe el cliente: rotándolo se saltaba rate limit y blocked_ips.
    trusted_proxies: int = 1
    # Si se define, solo se cree el XFF si el peer TCP está en estas redes
    # (blindaje si la app es alcanzable saltándose el proxy). Vacío = sin esto.
    trusted_proxy_cidrs: set[str] = field(default_factory=set)

    # Cabeceras
    security_headers: dict[str, str] | None = None  # None = DEFAULT_SECURITY_HEADERS

    compiled_custom: dict[str, list[re.Pattern[str]]] = field(
        init=False, repr=False, default_factory=dict
    )
    # Compilados en __post_init__ (la entrada original se conserva para auditarla):
    _blocked_literals: frozenset[str] = field(
        init=False, repr=False, default_factory=frozenset
    )
    _blocked_nets: tuple[tuple[str, _IPvNetwork], ...] = field(
        init=False, repr=False, default=()
    )
    _trusted_proxy_nets: tuple[_IPvNetwork, ...] = field(
        init=False, repr=False, default=()
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
        if self.trusted_proxies < 1:
            raise ValueError(
                "trusted_proxies debe ser >= 1: con trust_proxy la IP real del "
                "cliente es ips[-trusted_proxies], nunca ips[0]"
            )

        self._blocked_literals, self._blocked_nets = _compile_ips(
            self.blocked_ips, context="blocked_ips", allow_literal=True
        )
        _, trusted_nets = _compile_ips(
            self.trusted_proxy_cidrs,
            context="trusted_proxy_cidrs",
            allow_literal=False,
        )
        self._trusted_proxy_nets = tuple(net for _, net in trusted_nets)
        self.inspect_headers = {
            name.strip().lower() for name in self.inspect_headers if name and name.strip()
        }

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

    def blocked_match(self, ip: str) -> str | None:
        """Entrada de `blocked_ips` que coincide con esta IP (literal, normalizada o CIDR)."""
        if ip in self._blocked_literals:
            return ip
        addr = _parse_ip(ip)
        if addr is None:
            return None
        for entry, net in self._blocked_nets:
            if addr in net:
                return entry
        return None

    def trusted_peer(self, ip: str) -> bool:
        """False si hay `trusted_proxy_cidrs` y el peer no pertenece a ellas."""
        if not self._trusted_proxy_nets:
            return True
        addr = _parse_ip(ip)
        return addr is not None and any(addr in net for net in self._trusted_proxy_nets)

    @classmethod
    def from_dict(cls, data: Any) -> Config:
        if not isinstance(data, dict):
            raise TypeError("La configuración debe ser un mapa clave: valor")
        known = {f.name for f in fields(cls) if f.init}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Claves desconocidas en la configuración: {sorted(unknown)}")
        kwargs = dict(data)
        for key in ("disabled_rules", "blocked_ips", "trusted_proxy_cidrs", "inspect_headers"):
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
