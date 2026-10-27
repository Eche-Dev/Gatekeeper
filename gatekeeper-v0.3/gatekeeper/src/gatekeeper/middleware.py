from __future__ import annotations

import json
import logging
import time
import zlib
from urllib.parse import parse_qsl, urlencode

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .body import (
    SNIFFABLE_CONTENT_TYPES,
    BudgetExceeded,
    InspectionBudget,
    TooManyFields,
    content_type_of,
    effective_content_type,
    escape_pointer,
    extract_multipart,
    extract_strings,
    extract_strings_and_values,
    is_inspectable,
    read_body,
    replay,
)
from .config import Config
from .paths import is_path_allowed
from .ratelimit import (
    BackendUnavailable,
    MemoryBackend,
    RateLimitBackend,
    RedisBackend,
    normalize_rate_key,
)
from .rules import scan_detailed, scan_plus_as_space
from .sanitize import sanear, sanear_y_acotar

logger = logging.getLogger("gatekeeper")

BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def build_limiter(config: Config) -> RateLimitBackend | None:
    """Crea el backend de rate limiting según la configuración (None = desactivado)."""
    if config.rate_limit <= 0:
        return None
    if config.rate_backend == "memory":
        return MemoryBackend(
            config.rate_limit, config.rate_window, max_keys=config.rate_max_keys
        )
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise ImportError(
            'rate_backend="redis" necesita el extra: pip install "gatekeeper-asgi[redis]"'
        ) from exc
    return RedisBackend(
        Redis.from_url(
            config.redis_url,
            socket_connect_timeout=config.redis_timeout,
            socket_timeout=config.redis_timeout,
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
    target = name.lower()
    if target in (b"content-type", b"content-length"):
        for key, value in scope.get("headers", []):
            if key.lower() == target:
                return bytes(value).decode("latin-1")
        return None
    valores = [
        bytes(value).decode("latin-1")
        for key, value in scope.get("headers", [])
        if key.lower() == target
    ]
    if not valores:
        return None
    if len(valores) == 1:
        return valores[0]
    sep = "; " if target == b"cookie" else ", "
    return sep.join(valores)


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
        if scan_plus_as_space(key, disabled, extra, cfg.active_rules):
            return key
        if scan_plus_as_space(value, disabled, extra, cfg.active_rules):
            return key
    if scan_plus_as_space(path, disabled, extra, cfg.active_rules):
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


async def _close_websocket(send: Send, code: int) -> None:
    """Cierra un WebSocket antes de aceptar la conexión (rechaza el handshake).

    En ASGI, enviar `websocket.close` sin haber enviado `websocket.accept`
    hace que el servidor rechace el handshake. El cliente ve un 403.
    """
    await send({"type": "websocket.close", "code": code})


class GatekeeperMiddleware:
    def __init__(self, app: ASGIApp, config: Config | None = None) -> None:
        self.app = app
        self.config = config or Config()
        self.limiter: RateLimitBackend | None = build_limiter(self.config)

    def _audit(self, event: str, ip: str, scope: Scope, **extra: object) -> None:
        # Nunca se registra el contenido del payload: sí la regla, el campo y
        # el patrón que lo disparó, que es lo que hace falta para tunear FP.
        #
        # TODO lo que se escribe aqui es texto que puede haber puesto el
        # atacante (la ruta, el nombre del campo, el propio patron), asi que
        # se sanea y se acota ANTES de escribir: sin eso, un `\x1b[2J` en la
        # URL llega a la terminal de quien lee el log.
        datos: dict[str, object] = {
            "ts": time.time(),
            "event": event,
            "ip": sanear(ip),
            "method": scope.get("method"),
            "path": sanear(str(scope.get("path", ""))),
            **extra,
        }
        for clave, valor in list(datos.items()):
            if isinstance(valor, str):
                datos[clave] = sanear_y_acotar(valor)
        logger.warning(json.dumps(datos))

    def _auditar_presupuesto(self, exc: BudgetExceeded, ip: str, scope: Scope) -> None:
        """Audita el agotamiento del presupuesto con el nombre de su evento.

        El nombre va escrito aqui a proposito: el catalogo de eventos
        (`corpus/events.json`) se comprueba contra el codigo, y un evento que
        solo existe como constante en otro modulo no se podria verificar.
        """
        if isinstance(exc, TooManyFields):
            self._audit("too_many_fields", ip, scope, limite=exc.limite, campos=exc.campos)
        else:
            self._audit("inspection_timeout", ip, scope, limite=exc.limite, campos=exc.campos)

    async def _rechazar_presupuesto(self, exc: BudgetExceeded, ip: str, scope: Scope,
                                    receive: Receive, send: Send) -> None:
        """Rechaza (413) la peticion que agota el presupuesto de inspeccion.

        Agotar el presupuesto NO es un modo fail-open: la peticion se
        rechaza. Si se admitiera, el atacante podria gastar el presupuesto a
        proposito para que su payload se quedara SIN inspeccionar, y eso seria
        un bypass, no una degradacion.
        """
        self._auditar_presupuesto(exc, ip, scope)
        await self._reject(413, "Payload Too Large", scope, receive, send)

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

    async def _handle_websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Aplica el rate limit y la inspección al HANDSHAKE de un WebSocket.

        Antes el middleware salía con `scope["type"] != "http"` y dejaba pasar
        TODO lo que no fuera HTTP: los WebSockets no tenían ni rate limit ni
        inspección, y un handshake como `/ws?q=union%20select...` se aceptaba
        sin mirar. Para un atacante, un WAF con un hueco de WebSocket es un
        WAF con un hueco.

        Lo que se inspecciona es el HANDSHAKE (ruta, query y cabeceras). Los
        FRAMES no se inspeccionan: llegan después de aceptar la conexión y
        revisarlos exigiría interceptar cada mensaje. Queda documentado como
        límite conocido.

        Rechazar un handshake en ASGI es enviar `websocket.close` antes de
        `websocket.accept`: el servidor responde 403 y el cliente no entra.
        """
        cfg = self.config
        if not cfg.inspect_websockets:
            await self.app(scope, receive, send)
            return

        ip = _client_ip(scope, cfg)

        blocked_entry = cfg.blocked_match(ip)
        if blocked_entry is not None:
            self._audit("blocked_ip", ip, scope, entry=blocked_entry)
            await _close_websocket(send, 1008)
            return

        if self.limiter:
            try:
                allowed = await self.limiter.allow(
                    normalize_rate_key(ip, cfg.rate_ipv6_prefix)
                )
            except BackendUnavailable as exc:
                # Redis no responde: la política (seguir o cortar) es
                # rate_fail_open, igual que en HTTP.
                self._audit(
                    "rate_backend_error", ip, scope,
                    fail_open=cfg.rate_fail_open, error=str(exc)[:200],
                )
                if not cfg.rate_fail_open:
                    await _close_websocket(send, 1013)
                    return
                allowed = True
            if not allowed:
                self._audit("rate_limited", ip, scope)
                await _close_websocket(send, 1008)
                return

        path = scope.get("path", "")
        if cfg.inspect_requests and not is_path_allowed(path, cfg.allow_paths):
            query = scope.get("query_string", b"").decode("latin-1")
            # Mismo presupuesto que en HTTP: el handshake tambien se inspecciona.
            presupuesto = InspectionBudget(
                max_fields=cfg.max_fields, max_ms=cfg.max_inspection_ms
            )
            try:
                presupuesto.cuenta(2 * (query.count("&") + 1) if query else 0)
            except BudgetExceeded as exc:
                self._auditar_presupuesto(exc, ip, scope)
                await _close_websocket(send, 1008)
                return
            # El `+` de la RUTA es literal para la app (el servidor ya la
            # decodificó); el de la query es un espacio (así lo parsea el
            # servidor). Se protege el de la ruta para no confundirlos.
            target = path.replace("+", "%2B") + "?" + _query_without_excluded(query, cfg)

            hit = scan_plus_as_space(target, cfg.disabled_rules, cfg.compiled_custom,
                                     cfg.active_rules)
            if hit:
                rule, pattern = hit
                self._audit("attack_detected", ip, scope, rule=rule, source="query",
                            field=_query_field(path, query, cfg), pattern=pattern[:160],
                            blocked=not cfg.monitor_only)
                if not cfg.monitor_only:
                    await _close_websocket(send, 1008)
                    return

            for header_name in sorted(cfg.inspect_headers):
                if cfg.field_excluded(header_name):
                    continue
                raw_header = _header(scope, header_name.encode("latin-1"))
                if not raw_header:
                    continue
                hit = scan_detailed(raw_header, cfg.disabled_rules, cfg.compiled_custom,
                                    cfg.active_rules)
                if hit:
                    rule, pattern = hit
                    self._audit("attack_detected", ip, scope, rule=rule, source="header",
                                field=header_name, pattern=pattern[:160],
                                blocked=not cfg.monitor_only)
                    if not cfg.monitor_only:
                        await _close_websocket(send, 1008)
                        return

        await self.app(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send)
            return
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
            # La clave de conteo es normalizada (IPv4-mapped, IPv6 por /64);
            # la IP CRUDA es la que se audita, para no perder el dato real.
            key = normalize_rate_key(ip, cfg.rate_ipv6_prefix)
            try:
                allowed = await self.limiter.allow(key)
                retry_after = 0 if allowed else await self.limiter.retry_after(key)
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
        # El presupuesto es por peticion: campos y tiempo de inspeccion. Se
        # agota (rechazando), nunca se ignora.
        presupuesto = InspectionBudget(
            max_fields=cfg.max_fields, max_ms=cfg.max_inspection_ms
        )
        if cfg.inspect_requests and not is_path_allowed(path, cfg.allow_paths):
            query = scope.get("query_string", b"").decode("latin-1")
            # Los parametros de la query se cuentan ANTES de parsearlos: un
            # query enorme no llega a convertirse en una lista enorme en
            # memoria. Cada parametro aporta dos textos (clave y valor).
            try:
                presupuesto.cuenta(2 * (query.count("&") + 1) if query else 0)
            except BudgetExceeded as exc:
                await self._rechazar_presupuesto(exc, ip, scope, receive, send)
                return
            # Los campos exentos se quitan del objetivo ANTES de escanear: la
            # detección sigue cruzando parámetros, pero no sobre lo excluido.
            # El `+` de la RUTA es literal para la app (el servidor ya la
            # decodificó); el de la query es un espacio (así lo parsea el
            # servidor). Se protege el de la ruta para no confundirlos.
            target = path.replace("+", "%2B") + "?" + _query_without_excluded(query, cfg)

            # 1) ruta + query string: la detección va sobre el objetivo completo
            #    (un payload puede cruzar parámetros); el campo es atribución.
            hit = scan_plus_as_space(target, cfg.disabled_rules, cfg.compiled_custom,
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
            #    XML o incluso sin content-type); los binarios que no se
            #    sniffean, no.
            # El content-type CRUDO se guarda aparte: el `boundary` de un
            # multipart va en sus parametros, y `content_type_of` los tira.
            ctype_crudo = _header(scope, b"content-type")
            ctype = content_type_of(ctype_crudo)
            es_multipart = ctype.startswith("multipart/form-data")
            # El body se lee si su content-type es inspeccionable, si es un
            # binario "generico" (octet-stream) cuyo contenido decide el sniff
            # del primer byte, o si es multipart (que tiene su parser propio
            # para los nombres de campo y de fichero).
            se_lee = (
                is_inspectable(ctype)
                or ctype in SNIFFABLE_CONTENT_TYPES
                or (es_multipart and cfg.inspect_multipart)
            )
            declared = _content_length(scope)
            tiene_cuerpo = (
                scope.get("method") in BODY_METHODS
                or (declared is not None and declared > 0)
                or _header(scope, b"transfer-encoding") is not None
            )
            if (
                cfg.inspect_body
                and tiene_cuerpo
                and se_lee
            ):
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
                codificacion = (_header(scope, b"content-encoding") or "").strip().lower()
                if body and codificacion in ("gzip", "x-gzip", "deflate"):
                    try:
                        descompresor = zlib.decompressobj(zlib.MAX_WBITS | 32)
                        descomprimido = descompresor.decompress(body, cfg.max_body_size + 1)
                        if not descompresor.unconsumed_tail:
                            descomprimido += descompresor.flush(
                                max(1, cfg.max_body_size + 1 - len(descomprimido))
                            )
                    except zlib.error:
                        descomprimido = body
                    else:
                        if len(descomprimido) > cfg.max_body_size or descompresor.unconsumed_tail:
                            self._audit("body_too_large", ip, scope, size=None)
                            await self._reject(413, "Payload Too Large", scope, receive, send)
                            return
                        body = descomprimido
                # Leer el body no es inspeccionarlo: el tiempo de espera por
                # la red no cuenta contra el presupuesto de CPU.
                presupuesto.reinicia_reloj()

                has_inspectable_body_value = False
                cross_values: list[tuple[str, str]] = []
                try:
                    if es_multipart:
                        # multipart: se inspeccionan los NOMBRES de campo y de
                        # fichero (ahi van los `../../etc/passwd`), no el contenido
                        # binario de los ficheros.
                        body_fields = [
                            (f"/{escape_pointer(nombre)}", valor)
                            for nombre, valor in extract_multipart(
                                ctype_crudo or "", body, presupuesto
                            )
                        ]
                        if cfg.inspect_cross_carrier:
                            cross_values = body_fields[1::2]
                    else:
                        # El content-type generico lo decide el CONTENIDO, no la
                        # cabecera (que controla el atacante): un octet-stream con
                        # cuerpo JSON se inspecciona como JSON.
                        ctype_real = effective_content_type(ctype, body)
                        if not is_inspectable(ctype_real):
                            body_fields = []
                        elif cfg.inspect_cross_carrier:
                            body_fields, cross_values = extract_strings_and_values(
                                ctype_real, body, presupuesto
                            )
                        else:
                            body_fields = extract_strings(
                                ctype_real, body, budget=presupuesto
                            )
                except BudgetExceeded as exc:
                    await self._rechazar_presupuesto(exc, ip, scope, receive, send)
                    return

                for pointer, value in body_fields:
                    if cfg.field_excluded(pointer):
                        continue
                    has_inspectable_body_value = True
                    try:
                        presupuesto.comprueba_tiempo()
                    except BudgetExceeded as exc:
                        await self._rechazar_presupuesto(exc, ip, scope, receive, send)
                        return
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
                    try:
                        presupuesto.comprueba_tiempo()
                    except BudgetExceeded as exc:
                        await self._rechazar_presupuesto(exc, ip, scope, receive, send)
                        return
                    cross_body = " ".join(
                        value
                        for pointer, value in cross_values
                        if not cfg.field_excluded(pointer)
                    )
                    hit = (
                        scan_plus_as_space(
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
