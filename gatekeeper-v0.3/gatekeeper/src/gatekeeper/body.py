from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import parse_qsl

from starlette.types import Message, Receive


class BudgetExceeded(Exception):
    """El presupuesto de inspeccion de la peticion se ha agotado.

    Agotar el presupuesto RECHAZA la peticion (413). Ignorar en silencio los
    campos que sobran seria un BYPASS: el atacante mandaria el payload en el
    campo que se queda sin inspeccionar y la deteccion no lo veria nunca.
    """

    code = "budget_exceeded"

    def __init__(self, limite: int, campos: int | None = None):
        self.limite = limite
        self.campos = campos
        super().__init__(f"{self.code}: limite={limite} campos={campos}")


class TooManyFields(BudgetExceeded):
    """La peticion tiene mas campos de los que permite `max_fields`."""

    code = "too_many_fields"


class InspectionTimeout(BudgetExceeded):
    """La inspeccion ha superado el presupuesto de `max_inspection_ms`."""

    code = "inspection_timeout"


class InspectionBudget:
    """Presupuesto de trabajo por peticion: cuantos campos y cuanto tiempo.

    El tiempo que se cuenta es el de CPU (extraer y escanear), no el de
    espera: leer un body de una red lenta no es trabajo de Gatekeeper, y
    penalizarlo seria un falso positivo. Por eso el reloj se reinicia
    despues de leer el body.

    Medido: el coste de la inspeccion escala con el numero de campos (~67 us
    por campo), no con el tamano del body. Un body de 1 MiB con 20.000 campos
    tardaba 1,34 s en inspeccionarse, y el limite de tamano no lo cubria.
    """

    def __init__(
        self,
        max_fields: int = 0,
        max_ms: int = 0,
        clock: Callable[[], float] = time.perf_counter,
    ):
        self.max_fields = max_fields
        self.max_ms = max_ms
        self.clock = clock
        self.campos = 0
        self.deadline = self._plazo()

    def _plazo(self) -> float | None:
        if self.max_ms <= 0:
            return None
        return self.clock() + self.max_ms / 1000.0

    def reinicia_reloj(self) -> None:
        """Reinicia el reloj: esperar por la red no es inspeccionar."""
        self.deadline = self._plazo()

    def cuenta(self, n: int = 1) -> None:
        """Cuenta n campos inspeccionados y comprueba los dos presupuestos."""
        self.campos += n
        if self.max_fields and self.campos > self.max_fields:
            raise TooManyFields(self.max_fields, self.campos)
        self.comprueba_tiempo()

    def comprueba_tiempo(self) -> None:
        if self.deadline is not None and self.clock() > self.deadline:
            raise InspectionTimeout(self.max_ms, self.campos)


def content_type_of(raw: str | None) -> str:
    return (raw or "").split(";")[0].strip().lower()


# Content-types BINARIOS: su contenido no son cadenas que inspeccionar. Todo lo
# demás —incluido el ausente— SÍ se inspecciona: un `text/plain` o un POST sin
# content-type lo parsea `await request.json()` igual, y con la allowlist
# anterior el payload pasaba sin verlo. multipart queda fuera hasta su parser
# propio (v0.4).
_BINARY_CONTENT_TYPES = frozenset({
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/wasm",
    "application/java-archive",
    "application/x-bzip2",
})
_BINARY_PREFIXES = ("image/", "video/", "audio/", "font/")


def is_inspectable(content_type: str) -> bool:
    """True salvo que el body sea binario conocido o multipart (ver arriba)."""
    if not content_type:
        return True
    if content_type == "multipart/form-data":
        return False
    if content_type.startswith(_BINARY_PREFIXES):
        return False
    return content_type not in _BINARY_CONTENT_TYPES


# Content-type GENERICO de "te mando bytes y tu decides". La cabecera no dice
# nada, pero el contenido si: si el cuerpo es JSON, la app lo parsea igual con
# `await request.json()`. Se SNIFFEA el primer byte en vez de fiarse de la
# cabecera, que la controla el atacante.
OCTET_STREAM = "application/octet-stream"

# Los content-types cuyo contenido decide si se inspeccionan. Los demas
# binarios (image/*, application/pdf, application/zip...) NO se sniffean: son
# binarios de verdad y leerlos seria gastar CPU y memoria a cambio de nada.
SNIFFABLE_CONTENT_TYPES = frozenset({OCTET_STREAM})

# El prefijo que `json.loads` ACEPTA antes del primer { o [:
#   - los cuatro espacios en blanco del JSON (espacio, tab, LF, CR);
#   - y, en modo bytes, un BOM UTF-8 al principio (json usa detect_encoding(),
#     que devuelve 'utf-8-sig' y lo quita).
# El sniffeo tiene que coincidir EXACTAMENTE con eso: si se acepta un JSON que
# el sniffeo no ve, el atacante tiene un bypass gratis mandando el mismo cuerpo
# con el content-type equivocado. Por eso el prefijo se mide con una regex (en
# C, sin copiar el body) y no con una ventana de N bytes: un JSON con 5.000
# espacios delante lo parsea `json.loads`, y tambien lo tiene que ver Gatekeeper.
_JSON_LEADING = re.compile(rb"\xef\xbb\xbf[ \t\n\r]*|[ \t\n\r]*")


def looks_like_json(body: bytes) -> bool:
    """¿El cuerpo parece JSON? Se mira el primer byte no blanco.

    `{` o `[` al principio (ignorando los espacios en blanco del JSON y un
    posible BOM UTF-8) es la señal de que el cuerpo es JSON. No es un parser:
    decide COMO se inspecciona, no si es valido.
    """
    match = _JSON_LEADING.match(body)
    if match is None:
        return False
    return body[match.end():match.end() + 1] in (b"{", b"[")


def effective_content_type(content_type: str, body: bytes) -> str:
    """El content-type con el que se INSPECTA el body.

    Un `application/octet-stream` cuyo cuerpo es JSON se inspecciona como
    JSON. Sin esto, mandar la consulta con el content-type equivocado
    esquivaba la deteccion entera.
    """
    if content_type in SNIFFABLE_CONTENT_TYPES and looks_like_json(body):
        return "application/json"
    return content_type


def _split_params(value: str) -> list[str]:
    """Divide `a="1; b"; c="2"` en partes, sin partir dentro de comillas."""
    partes: list[str] = []
    actual: list[str] = []
    en_comillas = False
    for ch in value:
        if ch == '"':
            en_comillas = not en_comillas
            actual.append(ch)
        elif ch == ";" and not en_comillas:
            partes.append("".join(actual))
            actual = []
        else:
            actual.append(ch)
    partes.append("".join(actual))
    return partes


def _multipart_boundary(content_type: str) -> str | None:
    """Saca el `boundary` de un Content-Type multipart/form-data."""
    for piece in content_type.split(";")[1:]:
        nombre, _, valor = piece.strip().partition("=")
        if nombre.strip().lower() == "boundary":
            return valor.strip().strip('"') or None
    return None


def _content_disposition_params(value: str) -> dict[str, str]:
    """Parametros de un Content-Disposition: `name="x"; filename="y"`."""
    params: dict[str, str] = {}
    for piece in _split_params(value):
        nombre, _, valor = piece.partition("=")
        params[nombre.strip().lower()] = valor.strip().strip('"')
    return params


def extract_multipart(
    content_type: str, body: bytes, budget: InspectionBudget | None = None
) -> list[tuple[str, str]]:
    """`(campo, valor)` de las partes de un body multipart/form-data.

    - de una parte de TEXTO, el valor es su contenido;
    - de una parte de FICHERO, el valor es su `filename` (el contenido
      binario no se inspecciona, pero el nombre del fichero si: ahi van los
      `../../etc/passwd` y los payloads).

    Es un parser MINIMO y conservador: si el multipart no se entiende,
    devuelve `[]` en vez de inventarse una estructura. No es un parser de
    RFC 7578 (para eso esta `python-multipart`), pero cubre lo que se
    ataca de verdad —los nombres de campo y de fichero— sin anadir una
    dependencia ni abrir superficie de parsing.
    """
    boundary = _multipart_boundary(content_type)
    if not boundary:
        return []
    separador = b"--" + boundary.encode("latin-1", "replace")
    campos: list[tuple[str, str]] = []
    for parte in body.split(separador)[1:]:
        if parte.startswith(b"--"):
            break  # cierre del multipart
        parte = parte.lstrip(b"\r\n")
        cabecera, _, datos = parte.partition(b"\r\n\r\n")
        if not cabecera:
            continue
        disposicion = None
        for linea in cabecera.decode("latin-1", "replace").split("\r\n"):
            if linea.lower().startswith("content-disposition:"):
                disposicion = linea.split(":", 1)[1]
                break
        if disposicion is None:
            continue
        params = _content_disposition_params(disposicion)
        nombre = params.get("name")
        if not nombre:
            continue
        if budget is not None:
            # Cada parte aporta un campo (el nombre) y su valor: dos textos.
            budget.cuenta(2)
        if "filename" in params:
            campos.append((nombre, params["filename"]))
        else:
            campos.append((nombre, datos.rstrip(b"\r\n").decode("utf-8", "replace")))
    return campos


async def read_body(receive: Receive, max_size: int) -> tuple[list[Message], bytes | None]:
    """Lee el body completo. Devuelve (mensajes originales, body) o (mensajes, None) si excede.

    Los bytes se guardan **una sola vez**: los mensajes de ASGI ya llevan el
    `body` de cada fragmento, así que no hace falta una lista de chunks aparte.
    Con la duplicación, un body de 8 MiB ocupaba 16 MiB de memoria (el doble de
    lo que ocupa el body), y el pico de memoria de un proceso era el doble de
    lo que el limite `max_body_size` sugiere.

    El body se devuelve unido (`b"".join`) porque es lo que se inspecciona; los
    mensajes se conservan sueltos para poder reproducirlos tal cual llegaron
    (`replay`), que es lo que espera la app.
    """
    messages: list[Message] = []
    size = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break  # http.disconnect
        size += len(message.get("body", b""))
        if size > max_size:
            return messages, None
        if not message.get("more_body", False):
            break
    return messages, b"".join(m.get("body", b"") for m in messages)


def replay(messages: list[Message], receive: Receive) -> Receive:
    """Reproduce los mensajes ya leídos y después delega en el `receive` original."""
    it = iter(messages)

    async def wrapped() -> Message:
        try:
            return next(it)
        except StopIteration:
            return await receive()

    return wrapped


def escape_pointer(token: str) -> str:
    """Escapado RFC 6901 para los punteros de campo de los eventos de auditoría."""
    return token.replace("~", "~0").replace("/", "~1")


# Profundidad máxima del puntero JSON que se construye.
#
# El puntero identifica el campo en la auditoría y es lo que se compara con
# `exclude_fields`. Su longitud crece UN NIVEL POR NIVEL: a profundidad N, cada
# puntero mide O(N) caracteres. Con N campos, el total es O(N^2).
#
# Medido: un body de 60 KiB con 10.000 niveles de anidamiento producía 100 MB
# de punteros (193 MB con las tuplas), y 10 peticiones simultáneas llegaban a
# 1,9 GB. Es un DoS con cuerpos pequeños: el `max_body_size` no lo acota,
# porque 60 KiB están muy por debajo de 1 MiB.
#
# El límite corta la cadena por arriba. NO se pierde nada de lo que importa:
#   - `exclude_fields` compara por el ÚLTIMO segmento (`bio`) y por el puntero
#     completo; el último segmento se conserva intacto;
#   - la atribución por campo sigue diciendo QUÉ campo saltó;
#   - lo que se pierde es la RUTA COMPLETA a ese campo, que en un JSON de
#     100 niveles es información de relleno.
#
# 64 niveles cubren de sobra cualquier JSON real (los que usan las APIs
# habituales van de 3 a 10), y dejan el consumo lineal en el tamaño del body.
MAX_POINTER_DEPTH = 64

# Longitud maxima del puntero, en caracteres. El limite de PROFUNDIDAD no
# basta: una sola clave puede tener miles de caracteres, asi que el puntero
# tambien tiene que estar acotado en longitud.
MAX_POINTER_LENGTH = 256

# Longitud maxima de un segmento suelto (una clave). Sin este limite, una
# clave de 10.000 caracteres haria que el puntero fuera enorme aunque el
# numero de segmentos fuera pequeno.
MAX_SEGMENT_LENGTH = 64


def _render_pointer(segmentos: list[str]) -> str:
    """Convierte la lista de segmentos en el puntero final, acotando la longitud.

    La lista esta acotada en NUMERO de segmentos, pero cada segmento puede
    tener varios caracteres (una clave larga), asi que el limite real tiene que
    estar en la LONGITUD de la cadena.

    Cuando hay que recortar, se conservan los dos extremos:
    - el primero (la clave exterior, la que nombra el usuario en
      `exclude_fields`);
    - el ultimo (el campo concreto que salto);
    y se marca el corte con `…`.
    """
    if len(segmentos) <= MAX_POINTER_DEPTH:
        puntero = "/" + "/".join(segmentos)
        if len(puntero) <= MAX_POINTER_LENGTH:
            return puntero

    # Hay que recortar por longitud. Los extremos se recortan ellos mismos si
    # son exageradamente largos: una clave de 10.000 caracteres no puede caber
    # en un puntero de 256.
    primero = _clip_segment(segmentos[0])
    ultimo = _clip_segment(segmentos[-1])
    intermedios = [_clip_segment(s) for s in segmentos[1:-1]]

    # Cuantos intermedios caben, por CARACTERES (no por segmentos): cada uno
    # consume su longitud mas la barra.
    presupuesto = MAX_POINTER_LENGTH - len(primero) - len(ultimo) - len("/…/")
    if presupuesto <= 0:
        # Los dos extremos ya llenan el presupuesto: se quedan ellos y el
        # corte, y nada mas.
        return (f"/{primero}/…/{ultimo}")[:MAX_POINTER_LENGTH]

    mitad_presupuesto = presupuesto // 2

    izquierda = []
    gastado = 0
    for segmento in intermedios:
        coste = len(segmento) + 1
        if gastado + coste > mitad_presupuesto:
            break
        gastado += coste
        izquierda.append(segmento)

    derecha = []
    gastado = 0
    for segmento in reversed(intermedios[len(izquierda):]):
        coste = len(segmento) + 1
        if gastado + coste > mitad_presupuesto:
            break
        gastado += coste
        derecha.append(segmento)
    derecha.reverse()

    if not izquierda and not derecha:
        return f"/{primero}/…/{ultimo}"
    return "/" + "/".join([primero, *izquierda, "…", *derecha, ultimo])


def _clip_segment(segment: str) -> str:
    """Recorta un segmento individual que es demasiado largo.

    Una clave de 10.000 caracteres tiene que caber en el puntero: si no, el
    puntero seguiría siendo enorme y el problema volvería.
    """
    if len(segment) <= MAX_SEGMENT_LENGTH:
        return segment
    return segment[: MAX_SEGMENT_LENGTH - 1] + "…"


def _child_pointer(segmentos: list[str], segment: str) -> list[str]:
    """Añade un segmento a la ruta, manteniendo la lista acotada.

    La lista nunca crece más de `MAX_POINTER_DEPTH + 2` elementos: el primero
    (la clave exterior, que es la que nombra el usuario en `exclude_fields`), un
    `…` en el sitio del corte, y el último (el campo concreto que saltó).
    """
    if len(segmentos) < MAX_POINTER_DEPTH:
        segmentos.append(segment)
        return segmentos
    # Al límite: se descarta el segmento intermedio más antiguo (el segundo,
    # que no es el primero ni el último) y se marca el corte.
    if len(segmentos) > 1 and segmentos[1] != "…":
        segmentos[1] = "…"
    else:
        # Ya marcado: se hace sitio para el nuevo segmento.
        segmentos.insert(-1, segment)
        segmentos.pop(-2)
    return segmentos


def _iter_fields(
    obj: Any, pointer: str = "", include_keys: bool = True
) -> Iterator[tuple[str, str, bool]]:
    """`(puntero, texto, es_clave)` de los campos de texto.

    La ruta se lleva como una LISTA de segmentos acotada (ver
    `MAX_POINTER_DEPTH`): concatenarla como cadena hacia que un JSON
    profundamente anidado consumiese memoria cuadrática.
    """
    inicial = [s for s in pointer.split("/") if s]
    stack: list[tuple[list[str], Any, bool]] = [(inicial, obj, False)]
    while stack:
        segmentos, cur, is_key = stack.pop()
        if is_key:
            yield _render_pointer(segmentos), str(cur), True
        elif isinstance(cur, str):
            yield _render_pointer(segmentos), cur, False
        elif isinstance(cur, dict):
            for key, value in cur.items():
                hijo = _child_pointer(list(segmentos), escape_pointer(str(key)))
                stack.append((hijo, value, False))
                if include_keys:
                    stack.append((list(hijo), str(key), True))
        elif isinstance(cur, list):
            for pos, value in enumerate(cur):
                stack.append((_child_pointer(list(segmentos), str(pos)), value, False))


def _iter_body_fields(
    content_type: str, body: bytes, budget: InspectionBudget | None = None
) -> Iterator[tuple[str, str, bool]]:
    """Campos del body, contando el presupuesto en cada texto entregado.

    El conteo es perezoso (el generador se detiene en cuanto se agota el
    presupuesto), asi que el trabajo se corta en el limite y no despues.
    """
    if budget is None:
        yield from _iter_body_fields_raw(content_type, body)
        return
    for puntero, texto, es_clave in _iter_body_fields_raw(content_type, body):
        budget.cuenta()
        yield puntero, texto, es_clave


def _iter_body_fields_raw(
    content_type: str, body: bytes
) -> Iterator[tuple[str, str, bool]]:
    text = body.decode("utf-8", errors="replace")
    if content_type == "application/x-www-form-urlencoded":
        for key, value in parse_qsl(text, keep_blank_values=True):
            pointer = f"/{escape_pointer(key)}"
            yield pointer, key, True
            yield pointer, value, False
        return
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        yield "", text, False
        return
    yield from _iter_fields(obj)


def extract_strings(
    content_type: str,
    body: bytes,
    include_keys: bool = True,
    budget: InspectionBudget | None = None,
) -> list[tuple[str, str]]:
    """Extrae `(puntero, texto)` a inspeccionar.

    El puntero identifica el campo en los eventos de auditoría: JSON pointer
    (`/users/0/name`) en JSON, `/campo` en formularios y cadena vacía cuando se
    inspecciona el cuerpo en bruto. `include_keys=False` devuelve solo valores
    textuales estructurados.
    """
    return [
        (pointer, value)
        for pointer, value, is_key in _iter_body_fields(content_type, body, budget)
        if include_keys or not is_key
    ]


def extract_strings_and_values(
    content_type: str, body: bytes, budget: InspectionBudget | None = None
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Extrae una vez todos los textos y separa valores de claves."""
    fields: list[tuple[str, str]] = []
    values: list[tuple[str, str]] = []
    for pointer, text, is_key in _iter_body_fields(content_type, body, budget):
        fields.append((pointer, text))
        if not is_key:
            values.append((pointer, text))
    return fields, values
