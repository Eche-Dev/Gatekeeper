#!/usr/bin/env python3
"""Tests diferenciales del body: el middleware y la app interpretan IGUAL.

El middleware lee el body para inspeccionarlo y despues se lo reinyecta a la
aplicacion (`read_body` + `replay`). Si los dos interpretaran el body de
forma distinta, el middleware estaria inspeccionando una cosa y la app
usando otra: eso es un BYPASS (el payload pasa por el campo que el middleware
no vio) o un falso positivo (el middleware bloquea lo que la app no iba a
usar).

Este modulo hace TRES comprobaciones:

1. **IGUALDAD**: la misma peticion con y sin middleware. La app tiene que ver
   EXACTAMENTE lo mismo (los mismos bytes, el mismo JSON, el mismo formulario).
   Si el middleware se comiera una parte del body o lo reinyectara distinto,
   esto falla.

2. **MARCADOR**: el middleware tiene que INSPECCIONAR el valor que la app usa.
   Se mide con una regla propia que solo casa con el valor exacto que la app
   ha declarado (por ejemplo `sleep(10+6)`): si el middleware inspeccionara
   otra cosa (`sleep(10 6)`, con el `+` convertido en espacio), la regla no
   casaria y la peticion pasaria. Con las reglas integradas desactivadas, el
   403 solo puede venir del marcador.

   Esta comprobacion es la que encuentra bypasses: el `+` de un body es
   LITERAL para la app (el operador de MySQL), y perderlo era un ataque que
   llegaba intacto a la aplicacion.

3. **ATAQUES**: los payloads conocidos tienen que estar bloqueados, con la
   regla esperada. Comprueba el 403 y el evento de auditoria.

Este modulo NO usa pytest a proposito: la matriz de compatibilidad
(`tools/compat_matrix.py`) lo ejecuta dentro de un venv con una version
concreta de Starlette o FastAPI, y ahi no hay pytest instalado. El test de
pytest (`tests/test_diferencial_body.py`) llama a las mismas funciones, asi
que lo que se comprueba en cada version es exactamente lo mismo.

Donde NO pueden coincidir (y por eso el limite esta documentado en
`docs/amenazas.md`): una aplicacion que interprete el body por su cuenta
-parsear `q=1' OR '1'='1` a mano sin decir que es un form- ve cosas que el
middleware no puede ver, porque el content-type es lo unico que le dice como
inspeccionar. Eso no lo arregla un test: lo arregla decir el content-type
correcto.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from contextlib import contextmanager
from typing import Any, Iterator

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import RULES, Config, GatekeeperMiddleware

# Sin esto, el `logging` de Python imprime cada evento de auditoria por
# stderr (el "lastResort"), y la salida del script es inservible. El colector
# de mas abajo se engancha al mismo logger, asi que sigue viendo los eventos.
logging.getLogger("gatekeeper").addHandler(logging.NullHandler())

# --- cuerpos borde --------------------------------------------------------
# Cada caso: (nombre, content-type, cuerpo).
CASOS: list[tuple[str, str, bytes]] = [
    ("json simple", "application/json", b'{"q":"hola"}'),
    ("json con charset", "application/json; charset=utf-8", b'{"q":"hola"}'),
    ("json con espacios delante", "application/json", b'   \n\t{"q":"hola"}'),
    ("json con BOM utf-8", "application/json", b'\xef\xbb\xbf{"q":"hola"}'),
    ("json con escapes unicode", "application/json", b'{"q":"\\u00e9\\u00f1"}'),
    ("json con numero", "application/json", b'{"q":42}'),
    ("json con bool", "application/json", b'{"q":true}'),
    ("json con null", "application/json", b'{"q":null}'),
    ("json con array", "application/json", b'{"q":["a","b"]}'),
    ("json con objeto anidado", "application/json", b'{"a":{"b":{"c":"d"}}}'),
    ("json con lista de objetos", "application/json", b'{"a":[{"b":1},{"b":2}]}'),
    ("json malformado", "application/json", b'{"q":'),
    ("json vacio", "application/json", b""),
    ("json que es una lista", "application/json", b'[{"q":"hola"}]'),
    ("form simple", "application/x-www-form-urlencoded", b"q=hola&page=2"),
    ("form con charset", "application/x-www-form-urlencoded; charset=utf-8",
     b"q=hola&page=2"),
    ("form con campos duplicados", "application/x-www-form-urlencoded",
     b"q=uno&q=dos&q=tres"),
    ("form con valor vacio", "application/x-www-form-urlencoded", b"q=&page=2"),
    ("form con percent-encoding", "application/x-www-form-urlencoded",
     b"q=caf%C3%A9%26m%C3%A1s"),
    ("form con mas y mas", "application/x-www-form-urlencoded", b"a=1&a=2&b=3"),
    ("text/plain", "text/plain", b"q=hola"),
    ("sin content-type", "", b'{"q":"hola"}'),
    ("octet-stream con json", "application/octet-stream", b'{"q":"hola"}'),
    ("octet-stream con texto", "application/octet-stream", b"q=hola"),
    ("multipart simple", "multipart/form-data; boundary=XYZ",
     b"--XYZ\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nhola\r\n"
     b"--XYZ--\r\n"),
    ("multipart con fichero", "multipart/form-data; boundary=XYZ",
     b"--XYZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
     b"Content-Type: text/plain\r\n\r\ncontenido\r\n--XYZ--\r\n"),
]

# --- el valor que la app usa (comprobacion del MARCADOR) -------------------
# El valor sale del parseo de la app, no de una constante: asi el test mide
# de verdad si el middleware inspecciona lo mismo que la app.
#
# El valor NO puede llevar `%`: el middleware decodifica mas rondas que la app
# (a proposito, por si la app decodifica otra vez), asi que un `%2B` en el
# cuerpo llegaria a las reglas como `+` y el marcador —que es el valor tal
# cual— no casaria. Eso no es un fallo: es el middleware viendo MAS que la
# app, que es la direccion segura.
MARCADORES: list[tuple[str, str, bytes]] = [
    ("form con %2B (el mas es literal)", "application/x-www-form-urlencoded",
     b"q=sleep(10%2B6)"),
    ("form con %2B en el segundo valor", "application/x-www-form-urlencoded",
     b"q=benigno&q=a%2Bb"),
    ("form con + crudo (el mas es espacio)", "application/x-www-form-urlencoded",
     b"q=hola+adios"),
    ("json con + crudo", "application/json", b'{"q":"sleep(10+6)"}'),
    ("json con acento", "application/json", b'{"q":"caf\\u00e9"}'),
    ("form con acento percent-encoded", "application/x-www-form-urlencoded",
     b"q=caf%C3%A9"),
    ("text/plain con +", "text/plain", b"q=a+b"),
]

# --- ataques escondidos ---------------------------------------------------
# El body es el MISMO que la app leeria: si el middleware lo(parsea) de otra
# forma, el ataque llegaria intacto a la aplicacion.
ATAQUES: list[tuple[str, str, bytes, str]] = [
    ("sqli en json", "application/json", b'{"q":"1\' OR \'1\'=\'1"}', "sqli"),
    ("sqli en json con escapes unicode", "application/json",
     b'{"q":"1\\u0027 OR \\u00271\\u0027=\\u00271"}', "sqli"),
    ("sqli en json anidado", "application/json",
     b'{"a":{"b":{"c":"1\' OR \'1\'=\'1"}}}', "sqli"),
    ("sqli en json en un array", "application/json",
     b'{"q":["benigno","1\' OR \'1\'=\'1"]}', "sqli"),
    ("sqli en form", "application/x-www-form-urlencoded",
     b"q=1%27+OR+%271%27%3D%271", "sqli"),
    ("sqli en el segundo valor de un form duplicado",
     "application/x-www-form-urlencoded", b"q=benigno&q=1%27+OR+%271%27%3D%271",
     "sqli"),
    ("sqli en text/plain", "text/plain", b"q=1' OR '1'='1", "sqli"),
    ("sqli en json con content-type equivocado", "text/plain",
     b'{"q":"1\' OR \'1\'=\'1"}', "sqli"),
    ("xss en json", "application/json", b'{"q":"<script>alert(1)</script>"}', "xss"),
    ("xss en form", "application/x-www-form-urlencoded",
     b"q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss"),
    # El `+` del body es LITERAL para la app: sin esto, el payload llega
    # intacto a la base de datos (el operador de MySQL en `sleep(10+6)`).
    ("sqli con el mas literal en un form", "application/x-www-form-urlencoded",
     b"q=sleep(10%2B6)", "sqli"),
    ("sqli con el mas literal en json", "application/json",
     b'{"q":"sleep(10+6)"}', "sqli"),
]


def _valor_de_formulario(valor: object) -> str:
    """El valor de un campo del formulario, sin direcciones de memoria.

    `str(UploadFile)` trae la direccion del objeto, que cambia entre
    ejecuciones: el comparador veria una diferencia que no existe.
    """
    nombre = getattr(valor, "filename", None)
    if nombre is not None:
        tamano = getattr(valor, "size", None)
        return f"<fichero {nombre} ({tamano} bytes)>"
    return str(valor)


async def eco(request):
    """Devuelve lo que la aplicacion VE del body, de todas las formas."""
    crudo = await request.body()
    info: dict[str, object] = {
        "bytes": crudo.decode("utf-8", "replace"),
        "longitud": len(crudo),
        "content_type": request.headers.get("content-type", ""),
    }
    try:
        info["json"] = await request.json()
    except Exception as exc:  # noqa: BLE001 - aqui el TIPO del error importa
        info["json_error"] = type(exc).__name__
    try:
        form = await request.form()
        info["form"] = [
            [k, _valor_de_formulario(v)] for k, v in form.multi_items()
        ]
    except Exception as exc:  # noqa: BLE001
        info["form_error"] = type(exc).__name__
    return JSONResponse(info)


def _app_starlette(con_middleware: bool, config: Config | None = None) -> Starlette:
    app = Starlette(routes=[Route("/eco", eco, methods=["GET", "POST"])])
    if con_middleware:
        app.add_middleware(
            GatekeeperMiddleware, config=config or Config(rate_limit=0)
        )
    return app


def _app_fastapi(con_middleware: bool, config: Config | None = None):
    """La app de FastAPI. Se importa aqui (no arriba) porque los venv de la
    matriz Starlette no tienen FastAPI instalado."""
    from fastapi import FastAPI, Request

    app = FastAPI()

    async def _eco(request):  # noqa: ANN001 - el tipo se fija abajo
        return await eco(request)

    # FastAPI lee la anotacion al REGISTRAR la ruta, y este modulo usa
    # `from __future__ import annotations`: la anotacion seria el TEXTO
    # "Request", que no se resuelve porque FastAPI solo mira el ambito del
    # modulo (y `Request` esta importado en una funcion). Se fija aqui, ya
    # como clase, ANTES de registrar la ruta.
    _eco.__annotations__ = {"request": Request}

    app.post("/eco")(_eco)
    app.get("/eco")(_eco)

    if con_middleware:
        app.add_middleware(
            GatekeeperMiddleware, config=config or Config(rate_limit=0)
        )
    return app


def _cliente(marco: str, con_middleware: bool, config: Config | None = None):
    if marco == "starlette":
        app = _app_starlette(con_middleware, config)
    else:
        app = _app_fastapi(con_middleware, config)
    return TestClient(app)


def _peticion(
    marco: str,
    con_middleware: bool,
    content_type: str,
    body: bytes,
    config: Config | None = None,
) -> tuple[int, Any]:
    """Hace la peticion y devuelve `(estado, cuerpo json)`."""
    cabeceras = {"content-type": content_type} if content_type else {}
    with _cliente(marco, con_middleware, config) as cliente:
        respuesta = cliente.post("/eco", content=body, headers=cabeceras)
        estado = respuesta.status_code
        try:
            contenido: Any = respuesta.json()
        except ValueError:
            contenido = {"_texto": respuesta.text[:200]}
    return estado, contenido


# --- auditoria: los eventos que emite el middleware ------------------------
class _Colector(logging.Handler):
    """Recoge los eventos de auditoria del middleware."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.eventos: list[dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.eventos.append(json.loads(record.getMessage()))
        except (ValueError, TypeError):
            pass


@contextmanager
def _escuchando_auditoria() -> Iterator[_Colector]:
    """Conecta un colector al logger de Gatekeeper y lo desconecta al salir.

    El nivel tambien se fija y se restaura: si otro codigo ha dejado el
    logger en CRITICAL (el benchmark lo hace para no imprimir los eventos),
    los eventos no llegarian al colector y la comprobacion diria que el
    ataque no se audito.
    """
    logger = logging.getLogger("gatekeeper")
    colector = _Colector()
    nivel_previo = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(colector)
    try:
        yield colector
    finally:
        logger.removeHandler(colector)
        logger.setLevel(nivel_previo)


# --- comprobaciones --------------------------------------------------------
def fallo_igualdad(
    marco: str, nombre: str, content_type: str, body: bytes
) -> str | None:
    """La app tiene que ver EXACTAMENTE lo mismo con y sin middleware."""
    sin_estado, sin_cuerpo = _peticion(marco, False, content_type, body)
    con_estado, con_cuerpo = _peticion(marco, True, content_type, body)
    if con_estado != sin_estado:
        return (
            f"{marco}/{nombre}: sin middleware {sin_estado}, con middleware "
            f"{con_estado}"
        )
    if con_cuerpo != sin_cuerpo:
        return (
            f"{marco}/{nombre}: la app ve distinto con y sin middleware\n"
            f"    sin: {json.dumps(sin_cuerpo, ensure_ascii=False)[:300]}\n"
            f"    con: {json.dumps(con_cuerpo, ensure_ascii=False)[:300]}"
        )
    return None


def _valor_que_usa_la_app(cuerpo: Any) -> str | None:
    """El valor que la app ha declarado (el primero que hay)."""
    if not isinstance(cuerpo, dict):
        return None
    form = cuerpo.get("form")
    if isinstance(form, list):
        for par in form:
            if isinstance(par, list) and len(par) == 2 and par[1]:
                return str(par[1])
    datos = cuerpo.get("json")
    if isinstance(datos, dict):
        for valor in datos.values():
            if isinstance(valor, str) and valor:
                return valor
    # Si la app no parsea el body (un `text/plain`), su vista es el cuerpo
    # crudo: eso tambien tiene que ser lo que inspecciona el middleware.
    crudo = cuerpo.get("bytes")
    if isinstance(crudo, str) and crudo:
        return crudo
    return None


def _motivo_no_medible(cuerpo: Any, content_type: str) -> str | None:
    """Por que el caso NO se puede medir aqui (o None si se puede).

    En Starlette viejo, `request.form()` exige `python-multipart` incluso para
    un formulario urlencoded: sin el, la propia app no sabe parsear el body y
    no hay nada que comparar. Eso es del entorno, no de Gatekeeper, asi que el
    caso se salta (y se dice) en vez de contarlo como un fallo.
    """
    if not isinstance(cuerpo, dict):
        return "la app no ha devuelto nada"
    base = content_type.split(";")[0].strip().lower()
    if base in ("application/x-www-form-urlencoded", "multipart/form-data"):
        if cuerpo.get("form_error"):
            return f"la app no puede parsear el formulario ({cuerpo['form_error']})"
    if base == "application/json" and cuerpo.get("json_error"):
        return f"la app no puede parsear el JSON ({cuerpo['json_error']})"
    return None


def fallo_marcador(
    marco: str, nombre: str, content_type: str, body: bytes
) -> str | None:
    """El middleware tiene que inspeccionar el valor que la app usa.

    La regla propia solo casa con el valor exacto que la app ha declarado, y
    las reglas integradas estan todas desactivadas: asi, un 403 solo puede
    venir de que el middleware ha visto ese valor. Si el middleware
    inspeccionara otra cosa, la peticion pasaria.

    Devuelve None si todo va bien, un texto con "SKIP: " si el caso no se
    puede medir en este entorno, y el motivo del fallo si lo hay.
    """
    _, cuerpo = _peticion(marco, False, content_type, body)
    motivo = _motivo_no_medible(cuerpo, content_type)
    if motivo is not None:
        return f"SKIP: {motivo}"
    valor = _valor_que_usa_la_app(cuerpo)
    if not valor:
        return f"{marco}/{nombre}: la app no ha declarado ningun valor"
    # El texto se normaliza a minusculas antes de escanearlo.
    patron = re.escape(valor.lower())
    config = Config(
        rate_limit=0,
        disabled_rules=set(RULES),
        custom_rules={"marcador": patron},
    )
    estado, _ = _peticion(marco, True, content_type, body, config)
    if estado != 403:
        return (
            f"{marco}/{nombre}: el middleware NO ha inspeccionado el valor que "
            f"usa la app ({valor!r}); el patron {patron!r} no casaba"
        )
    return None


def fallo_ataque(
    marco: str, nombre: str, content_type: str, body: bytes, regla: str
) -> str | None:
    """Los payloads conocidos tienen que estar bloqueados con su regla."""
    with _escuchando_auditoria() as colector:
        estado, _ = _peticion(marco, True, content_type, body)
    if estado != 403:
        return (
            f"{marco}/{nombre}: el middleware dejo pasar el payload "
            f"(estado {estado})"
        )
    ataques = [e for e in colector.eventos if e.get("event") == "attack_detected"]
    if not ataques:
        return f"{marco}/{nombre}: se bloqueo pero no se audito el ataque"
    reglas = {e.get("rule") for e in ataques}
    if reglas != {regla}:
        return (
            f"{marco}/{nombre}: se esperaba la regla {regla!r} y saltaron {reglas}"
        )
    if not ataques[0].get("blocked"):
        return f"{marco}/{nombre}: el evento no dice que se bloqueo"
    return None


def comprobar_igualdad(marco: str) -> list[str]:
    """Todos los fallos de la comprobacion de igualdad del marco dado."""
    fallos = [
        fallo
        for fallo in (
            fallo_igualdad(marco, nombre, content_type, body)
            for nombre, content_type, body in CASOS
        )
        if fallo
    ]
    return fallos


def _resultados_marcadores(marco: str) -> tuple[list[str], list[str]]:
    """`(fallos, no medibles)` de la comprobacion de marcadores.

    Los casos que no se pueden medir en este entorno (la app no sabe parsear
    el body) se cuentan aparte: no son fallos, pero tampoco se pueden decir
    que estan bien.
    """
    fallos: list[str] = []
    no_medibles: list[str] = []
    for nombre, content_type, body in MARCADORES:
        fallo = fallo_marcador(marco, nombre, content_type, body)
        if fallo is None:
            continue
        if fallo.startswith("SKIP: "):
            no_medibles.append(f"{marco}/{nombre}: {fallo[len('SKIP: '):]}")
        else:
            fallos.append(fallo)
    return fallos, no_medibles


def comprobar_marcadores(marco: str) -> list[str]:
    """Todos los fallos de la comprobacion de marcadores del marco dado."""
    return _resultados_marcadores(marco)[0]


def marcadores_no_medibles(marco: str) -> list[str]:
    """Los casos de marcador que no se pueden medir en este entorno."""
    return _resultados_marcadores(marco)[1]


def comprobar_ataques(marco: str) -> list[str]:
    """Todos los fallos de la comprobacion de ataques del marco dado."""
    fallos = [
        fallo
        for fallo in (
            fallo_ataque(marco, nombre, content_type, body, regla)
            for nombre, content_type, body, regla in ATAQUES
        )
        if fallo
    ]
    return fallos


def comprobar(marco: str) -> list[str]:
    """Todos los fallos del marco dado (vacio si todo va bien)."""
    fallos: list[str] = []
    fallos.extend(comprobar_igualdad(marco))
    fallos.extend(comprobar_marcadores(marco))
    fallos.extend(comprobar_ataques(marco))
    return fallos


def marcos_disponibles() -> list[str]:
    """Los marcos que se pueden probar aqui (FastAPI puede no estar)."""
    disponibles = ["starlette"]
    try:
        import fastapi  # noqa: F401
    except ImportError:
        return disponibles
    return disponibles + ["fastapi"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--marco",
        choices=["starlette", "fastapi", "todos"],
        default="todos",
        help="que framework se prueba (por defecto, los que haya instalados)",
    )
    args = parser.parse_args(argv)

    if args.marco == "todos":
        marcos = marcos_disponibles()
    else:
        marcos = [args.marco]

    fallos: list[str] = []
    no_medibles: list[str] = []
    for marco in marcos:
        fallos.extend(comprobar(marco))
        no_medibles.extend(marcadores_no_medibles(marco))

    if no_medibles:
        print("Casos NO MEDIBLES en este entorno (la app no sabe parsear el body):")
        for caso in no_medibles:
            print(f"  - {caso}")

    if fallos:
        print("FALLOS:")
        for fallo in fallos:
            print(f"  - {fallo}")
        return 1

    import starlette

    versiones = [f"starlette={starlette.__version__}"]
    try:
        import fastapi

        versiones.append(f"fastapi={fastapi.__version__}")
    except ImportError:
        pass
    print(
        f"diferencial ok: {len(CASOS)} cuerpos, {len(MARCADORES)} marcadores y "
        f"{len(ATAQUES)} ataques en {', '.join(marcos)} ({', '.join(versiones)})"
        + (f"; {len(no_medibles)} no medibles" if no_medibles else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
