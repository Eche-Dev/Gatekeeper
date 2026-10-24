"""El middleware tiene que funcionar con los servidores ASGI de produccion.

La suite usa `TestClient` (que llama a la app en proceso). Eso no es lo mismo
que un servidor de verdad: no hay socket, no hay TLS, no hay un bucle de eventos
propio, y hay diferencias en como se entregan los cuerpos (fragmentados, con
`more_body`, con desconexiones del cliente).

Estos tests levantan servidores REALES (uvicorn, hypercorn y daphne) sobre un
socket local y mandan peticiones HTTP de verdad. Comprueban lo mismo que la
suite: que se bloquea lo que hay que bloquear y que lo legitimo pasa.

Los servidores se lanzan como SUBPROCESOS (no con los helpers de test de cada
uno): es como se usan en produccion y evita que un servidor mal apagado se
quede colgando el proceso de pytest.

Si un servidor no esta instalado, el test se omite con un motivo claro: la
suite tiene que pasar en una instalacion minima.
"""
from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware

TIMEOUT = 30.0
RAIZ = Path(__file__).resolve().parent.parent


def _puerto_libre() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _app():
    async def buscar(request):
        return JSONResponse({"ok": True, "q": request.query_params.get("q", "")})

    async def eco(request):
        cuerpo = await request.body()
        return JSONResponse({"ok": True, "len": len(cuerpo)})

    app = Starlette(routes=[
        Route("/buscar", buscar, methods=["GET"]),
        Route("/eco", eco, methods=["POST"]),
    ])
    return GatekeeperMiddleware(app, Config(rate_limit=100, rate_window=60))


def _esperar(puerto: int, proceso: subprocess.Popen) -> None:
    """Espera a que el servidor acepte conexiones."""
    fin = time.time() + TIMEOUT
    while time.time() < fin:
        if proceso.poll() is not None:
            raise AssertionError(
                f"el servidor termino antes de tiempo (codigo {proceso.returncode})"
            )
        try:
            with closing(socket.create_connection(("127.0.0.1", puerto), timeout=1)):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"el servidor no abrio el puerto {puerto}")


def _http(puerto: int, peticion: str) -> tuple[int, str]:
    """Manda una peticion HTTP cruda y devuelve (codigo, cuerpo).

    Se manda `Connection: close` porque daphne mantiene la conexion abierta
    por defecto (HTTP/2 y keep-alive) y, sin esa cabecera, el socket no se
    cierra y la lectura se queda esperando.
    """
    if "Connection:" not in peticion:
        peticion = peticion.replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
    with closing(socket.create_connection(("127.0.0.1", puerto), timeout=TIMEOUT)) as s:
        s.settimeout(TIMEOUT)
        s.sendall(peticion.encode("utf-8"))
        respuesta = b""
        while b"\r\n\r\n" not in respuesta:
            trozo = s.recv(65536)
            if not trozo:
                break
            respuesta += trozo
        partes = respuesta.split(b"\r\n\r\n", 1)
        cabecera = partes[0].decode("latin-1")
        cuerpo = partes[1] if len(partes) > 1 else b""
        while "content-length:" in cabecera.lower() and len(cuerpo) < 100000:
            trozo = s.recv(65536)
            if not trozo:
                break
            cuerpo += trozo
        codigo = 0
        for linea in cabecera.split("\r\n"):
            if linea.startswith("HTTP/1."):
                codigo = int(linea.split()[1])
                break
        return codigo, cuerpo.decode("utf-8", "replace")


# ------------------------------------------------- servidores de prueba


SERVERS = {
    "uvicorn": [
        sys.executable, "-m", "uvicorn", "app_servidor:app",
        "--host", "127.0.0.1", "--port", "{puerto}", "--log-level", "error",
    ],
    "hypercorn": [
        sys.executable, "-m", "hypercorn", "app_servidor:app",
        "--bind", "127.0.0.1:{puerto}",
    ],
    "daphne": [
        sys.executable, "-m", "daphne", "-b", "127.0.0.1", "-p", "{puerto}",
        "app_servidor:app",
    ],
}


@pytest.fixture
def servidor():
    """Levanta un servidor ASGI real en un subproceso."""
    import contextlib

    @contextlib.contextmanager
    def _arrancar(nombre: str):
        if importlib.util.find_spec(nombre) is None:
            pytest.skip(f"{nombre} no esta instalado")
        puerto = _puerto_libre()
        comando = [a.format(puerto=puerto) for a in SERVERS[nombre]]
        proceso = subprocess.Popen(
            comando,
            cwd=RAIZ,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _esperar(puerto, proceso)
            yield puerto
        finally:
            proceso.terminate()
            try:
                proceso.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proceso.kill()
                proceso.wait(timeout=5)

    return _arrancar


# ------------------------------------------------------------ los tests


@pytest.mark.parametrize("nombre", list(SERVERS))
def test_el_servidor_bloquea_el_ataque_y_deja_pasar_lo_legitimo(servidor, nombre):
    """La misma comprobacion con cada servidor: 200 al legitimo, 403 al ataque."""
    with servidor(nombre) as puerto:
        codigo_ok, cuerpo_ok = _http(
            puerto, "GET /buscar?q=hola HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        assert codigo_ok == 200, (nombre, codigo_ok, cuerpo_ok)

        codigo_malo, cuerpo_malo = _http(
            puerto,
            "GET /buscar?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\n"
            "Host: x\r\n\r\n",
        )
        assert codigo_malo == 403, (nombre, codigo_malo, cuerpo_malo)


@pytest.mark.parametrize("nombre", list(SERVERS))
def test_el_servidor_devuelve_413_con_el_content_length_declarado(servidor, nombre):
    """El 413 se decide con el Content-Length, sin leer el body entero.

    El Content-Length declarado es de 50 MB pero no se envia el body: el
    middleware comprueba el tamano declarado ANTES de leer, asi que responde
    413 sin esperar los 50 MB.

    Nota sobre daphne: espera a que llegue el body declarado antes de pasar
    la peticion a la app, asi que en daphne este caso concreto no se puede
    comprobar de esta forma. Los demas servidores si lo hacen, y el 413 con
    body real se comprueba aparte con el stream leido.
    """
    with servidor(nombre) as puerto:
        if nombre == "daphne":
            pytest.skip("daphne espera al body declarado antes de invocar la app")
        codigo, cuerpo = _http(
            puerto,
            "POST /eco HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            "Content-Length: 50000000\r\n\r\n",
        )
        assert codigo == 413, (nombre, codigo, cuerpo)


@pytest.mark.parametrize("nombre", list(SERVERS))
def test_el_servidor_anade_las_cabeceras_de_seguridad(servidor, nombre):
    """Las cabeceras de seguridad las anade el middleware: tienen que salir."""
    with servidor(nombre) as puerto:
        with closing(socket.create_connection(("127.0.0.1", puerto), timeout=TIMEOUT)) as s:
            s.settimeout(TIMEOUT)
            s.sendall(
                b"GET /buscar?q=hola HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            respuesta = b""
            while b"\r\n\r\n" not in respuesta:
                trozo = s.recv(65536)
                if not trozo:
                    break
                respuesta += trozo
    cabecera = respuesta.decode("latin-1").lower()
    assert "x-content-type-options: nosniff" in cabecera, (nombre, cabecera[:400])
    assert "x-frame-options: deny" in cabecera, (nombre, cabecera[:400])
