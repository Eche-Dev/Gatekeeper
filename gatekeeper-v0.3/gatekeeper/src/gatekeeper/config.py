from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .redos import (
    MAX_CUSTOM_RULES,
    MAX_PATTERN_LENGTH,
    NIVEL_EXPONENCIAL,
    analizar_redos,
)
from .rules import RULES, resolve_rules
from .sanitize import sanear_y_acotar

logger = logging.getLogger("gatekeeper")

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


def _normalize_net(net: _IPvNetwork) -> _IPvNetwork:
    """Convierte una red IPv4-mapped IPv6 a su equivalente IPv4.

    `::ffff:0:0/96` es el rango reservado para IPv4 dentro de IPv6. Sin esta
    conversion, una entrada en esa forma NUNCA coincide con nada: la IP que
    llega se normaliza a IPv4 (ver `_parse_ip`) y se compara contra una red
    IPv6, y IPv4 no pertenece a IPv6. Es decir, `blocked_ips={"::ffff:0:0/96"}`
    se aceptaba al arrancar y no bloqueaba NADA: una proteccion que no protege.
    """
    if net.version != 6 or net.prefixlen < 96:
        return net
    mapped = getattr(net.network_address, "ipv4_mapped", None)
    if mapped is None:
        return net
    return ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}", strict=False)


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
            nets.append((entry, _normalize_net(ipaddress.ip_network(entry, strict=False))))
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
    # Timeout de conexion y de lectura contra Redis, en segundos.
    #
    # Con Redis caido, cada peticion espera este tiempo antes de decidir
    # (con `rate_fail_open=True` la admite, con `False` devuelve 503). Medido
    # con el valor por defecto: 2,0 s por peticion. Bajalo si tu Redis esta en
    # la misma red (0,2 s basta) y subelo si esta en otra.
    #
    # Ojo: un timeout MUY corto hace que un Redis lento parezca caido, y con
    # `rate_fail_open=True` eso desactiva el rate limit en silencio. Si lo
    # bajas, baja tambien el riesgo de que el limite se esquive.
    redis_timeout: float = 2.0
    # Política si Redis no responde: True -> se admiten peticiones (disponibilidad)
    # False -> 503 (seguridad estricta). En ambos casos se audita el fallo.
    rate_fail_open: bool = True
    # Tope de claves distintas que el backend en memoria recuerda (LRU al
    # llegar al tope). Sin tope, inundar de IPs distintas agotaba la RAM del
    # proceso: medido, 300.000 IPs costaban ~245 MB. El limite acota la
    # memoria; el limite por IP sigue mandando sobre el cubo de cada cliente.
    rate_max_keys: int = 10_000
    # Prefijo IPv6 (en bits) que se agrupa al contar. Un /64 es el prefijo
    # delegable mas pequeno (RFC 6177): sin agrupar, quien tenga un /64 evade
    # el limite rotando direcciones. 128 = una direccion por cubo (sin agrupar).
    rate_ipv6_prefix: int = 64

    # Detección de patrones
    inspect_requests: bool = True
    monitor_only: bool = False  # True: solo registra, no bloquea
    # Combina el objetivo de ruta/query con los campos textuales del body.
    # Opt-in porque combinar contextos puede aumentar los falsos positivos.
    inspect_cross_carrier: bool = False
    disabled_rules: set[str] = field(default_factory=set)
    # Reglas propias: {nombre: regex} o [{name:, pattern:}]. Se evalúan sobre texto
    # decodificado y en minúsculas.
    custom_rules: Any = field(default_factory=dict)
    # Acepta reglas propias con estructuras de regex peligrosas (cuantificadores
    # anidados, alternativas solapadas). Por defecto se RECHAZAN al arrancar:
    # una regex catastrofica es un DoS que el usuario se introduce en su
    # propio WAF, sin necesidad de adversario.
    allow_unsafe_custom_rules: bool = False

    # Inspección del body: TODO content-type textual (JSON, form, text/plain,
    # XML o incluso sin content-type); solo se saltan binarios y multipart (v0.4).
    inspect_body: bool = True
    # 256 KiB por defecto (antes 1 MiB). Es el limite de lo que se LEE: la
    # inspeccion de un body consume CPU proporcional a su tamano.
    max_body_size: int = 262_144  # bytes; si se excede -> 413
    # Presupuesto de campos por peticion: numero maximo de TEXTOS a
    # inspeccionar (una clave y su valor cuentan como dos). Al superarlo, la
    # peticion se RECHAZA con 413. 0 = sin limite.
    #
    # Medido: el coste de la inspeccion escala con el numero de campos
    # (~67 us por campo), no con el tamano del body: 20.000 campos costaban
    # 1,34 s, y el limite de tamano no los cubria.
    max_fields: int = 1000
    # Presupuesto de tiempo de inspeccion, en milisegundos. 0 = sin limite.
    #
    # Al superarlo, la peticion se RECHAZA con 413. No hay modo "fail open":
    # un presupuesto que se pudiera agotar a proposito para saltarse la
    # deteccion seria un bypass, no un matiz.
    #
    # El defecto es holgado (1 s) a proposito: con `max_fields` por defecto,
    # el peor caso legitimo es ~100 ms en una maquina normal (~335 ms en una
    # maquina cinco veces mas lenta), asi que 1 s deja margen de sobra. La
    # proteccion principal es `max_fields`, que no depende de la maquina.
    max_inspection_ms: int = 1000

    # Inspección de multipart/form-data: se miran los NOMBRES de campo y de
    # fichero (no el contenido de los ficheros). Implica LEER el body, asi que
    # el limite `max_body_size` tambien se aplica a las subidas: si tu app
    # acepta ficheros grandes, sube el limite o pon esto a False.
    inspect_multipart: bool = True

    # Inspección del handshake de WebSocket (ruta, query y cabeceras) y rate
    # limit por IP. Los FRAMES no se inspeccionan: llegan despues de aceptar
    # la conexion. False = los WebSockets pasan sin tocar (como antes).
    inspect_websockets: bool = True

    # Cabeceras cuyo valor se inspecciona con las mismas reglas (en minúsculas;
    # vacío = desactivado).
    inspect_headers: set[str] = field(default_factory=lambda: set(DEFAULT_INSPECT_HEADERS))

    # Rutas exentas de inspección (globs). El rate limit y el bloqueo de IP se mantienen.
    allow_paths: list[str] = field(default_factory=list)

    # Campos (parámetros de query, claves de cabecera o punteros JSON) exentos de
    # inspección: nombres exactos (sin distinguir mayúsculas) o globs. Útil cuando
    # tu app acepta por diseño un valor que la firma bloquearía (un buscador que
    # indexa documentación de seguridad, un parámetro `template` con Jinja...).
    # Un payload que cruza varios campos se sigue detectando con los campos NO
    # excluidos: se reconstruye el objetivo sin los exentos y se escanea eso.
    exclude_fields: list[str] = field(default_factory=list)

    # Packs de reglas a activar (ver rules.PACK_NAMES). None = `web`, el defecto.
    # Combinar con `disabled_rules` para apagar familias concretas del pack.
    rule_packs: list[str] | None = None

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
    # Exenciones de campo compiladas (globs con la semántica de fnmatch).
    _exclude_globs: tuple[re.Pattern[str], ...] = field(
        init=False, repr=False, default=()
    )
    # Familias efectivamente activas (pack menos `disabled_rules`).
    active_rules: frozenset[str] = field(init=False, repr=False, default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.rate_limit < 0:
            raise ValueError("rate_limit no puede ser negativo")
        if self.rate_window <= 0:
            raise ValueError("rate_window debe ser mayor que 0")
        if self.rate_backend not in ("memory", "redis"):
            raise ValueError("rate_backend debe ser 'memory' o 'redis'")
        if self.rate_backend == "redis" and not self.redis_url:
            raise ValueError("redis_url no puede estar vacío con rate_backend='redis'")
        if self.redis_timeout <= 0:
            raise ValueError("redis_timeout debe ser mayor que 0")
        if self.rate_max_keys < 1:
            raise ValueError("rate_max_keys debe ser >= 1")
        if not 16 <= self.rate_ipv6_prefix <= 128:
            raise ValueError("rate_ipv6_prefix debe estar entre 16 y 128 bits")
        if self.max_body_size <= 0:
            raise ValueError("max_body_size debe ser mayor que 0")
        if self.max_fields < 0:
            raise ValueError("max_fields no puede ser negativo")
        if self.max_inspection_ms < 0:
            raise ValueError("max_inspection_ms no puede ser negativo")
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

        # Toda exclusión pasa por fnmatch (igual que `allow_paths`): un nombre
        # sin comodines coincide solo consigo mismo, uno con `*`/`?`/`[]` es un
        # glob. Se compila una vez aquí para no resolverlo en cada petición.
        self._exclude_globs = tuple(
            re.compile(fnmatch.translate(str(raw).strip()), re.IGNORECASE)
            for raw in self.exclude_fields
            if str(raw).strip()
        )

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
        if len(rules) > MAX_CUSTOM_RULES:
            raise ValueError(
                f"custom_rules: como mucho {MAX_CUSTOM_RULES} reglas "
                f"(hay {len(rules)}); cada una se evalua en cada texto inspeccionado"
            )

        for name, pattern in rules.items():
            # El nombre de la regla lo elige quien configura, pero eso no lo
            # hace de fiar: puede traer un ESC (que limpia la terminal de
            # quien lee el log) o ser larguisimo (una linea de log de 100 KB).
            # Al log y al traceback va saneado y acotado, como el resto del
            # texto que sale del proceso (ver `sanitize.py`).
            nombre_log = sanear_y_acotar(str(name))
            if not name:
                raise ValueError("Una regla personalizada tiene el nombre vacío")
            if name in RULES:
                raise ValueError(f"La regla personalizada '{nombre_log}' choca con una regla integrada")
            if not pattern:
                raise ValueError(f"Regla personalizada '{nombre_log}': el patrón está vacío")
            if len(pattern) > MAX_PATTERN_LENGTH:
                raise ValueError(
                    f"Regla personalizada '{nombre_log}': el patrón es demasiado largo "
                    f"({len(pattern)} caracteres; máximo {MAX_PATTERN_LENGTH})"
                )
            # Una regex catastrofica es un DoS en el propio WAF: se comprueba
            # al arrancar, no en produccion (ver `redos.analizar_redos`).
            analisis = analizar_redos(pattern)
            if analisis is not None:
                nivel, motivo = analisis
                # El motivo incluye fragmentos del propio patron: es texto no
                # confiable y va acotado antes de escribirlo.
                motivo_log = sanear_y_acotar(motivo)
                if nivel == NIVEL_EXPONENCIAL:
                    if not self.allow_unsafe_custom_rules:
                        raise ValueError(
                            f"Regla personalizada '{nombre_log}': patrón con riesgo de ReDoS "
                            f"({motivo_log}). Reescríbelo sin cuantificadores anidados ni "
                            f"alternativas solapadas, o pon "
                            f"allow_unsafe_custom_rules=True si aceptas el riesgo."
                        )
                    logger.warning(
                        "Regla personalizada '%s': patrón con riesgo de ReDoS (%s), "
                        "aceptado porque allow_unsafe_custom_rules=True",
                        nombre_log,
                        motivo_log,
                    )
                else:
                    # Riesgo cuadratico: no cuelga con una entrada corta, pero se
                    # degrada con el tamaño. Son patrones legitimos (una regex de
                    # dominio, por ejemplo): se avisa, no se rechaza.
                    logger.warning(
                        "Regla personalizada '%s': patrón con riesgo de backtracking "
                        "cuadrático (%s). Con entradas grandes puede tardar mucho; "
                        "considera acotarlo",
                        nombre_log,
                        motivo_log,
                    )
            try:
                self.compiled_custom[name] = [re.compile(pattern)]
            except (re.error, OverflowError) as exc:
                raise ValueError(f"Regla personalizada '{nombre_log}': patrón inválido ({sanear_y_acotar(str(exc))})") from exc

        unknown = set(self.disabled_rules) - set(RULES) - set(rules)
        if unknown:
            raise ValueError(f"disabled_rules contiene reglas inexistentes: {sorted(unknown)}")

        # El pack decide qué familias se EVALÚAN; `disabled_rules` apaga las
        # concretas. Un nombre de `disabled_rules` que no está en el pack es
        # inocuo (no hace falta que dé error: el usuario puede activar y
        # desactivar reglas en archivos de configuración distintos).
        self.active_rules = frozenset(
            resolve_rules(self.rule_packs) - set(self.disabled_rules)
        )

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

    def field_excluded(self, name: str | None) -> bool:
        """¿Este campo (parámetro, cabecera o puntero JSON) está exento?

        Un puntero JSON como `/user/bio` se compara por su ÚLTIMO segmento
        (`bio`) y por el puntero completo, para que puedas exentar `bio` o
        `/user/bio` sin ensuciar la lista. Vacío = nada excluido (caso normal).

        También se compara por el PRIMER segmento: un puntero muy profundo se
        recorta (`/bio/…/nivel`) para que su longitud no crezca sin límite, y
        el nombre que el usuario escribió (`bio`) queda en ese primer
        segmento. Sin esta comparación, excluir un campo dejaría de funcionar
        en los punteros recortados.
        """
        if not self._exclude_globs or not name:
            return False
        # El puntero empieza por "/", así que el primer elemento de la lista
        # es vacío: el primer segmento DE VERDAD es el segundo.
        segmentos = [s for s in name.split("/") if s] if name.startswith("/") else []
        candidates = {name}
        if segmentos:
            candidates.add(segmentos[-1])
            if len(segmentos) > 1 and "…" in segmentos:
                candidates.add(segmentos[0])
        return any(
            pattern.match(candidate) for pattern in self._exclude_globs
            for candidate in candidates
        )

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
        for key in ("exclude_fields", "allow_paths", "rule_packs"):
            if key in kwargs and kwargs[key] is not None:
                kwargs[key] = list(kwargs[key])
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
