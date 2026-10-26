"""Medir la compatibilidad real con Starlette y FastAPI.

El plan pide "publicar una matriz explicita de compatibilidad". Para que la
matriz no sea una suposicion, hay que PROBAR las versiones y decir la verdad.

Lo que se mide en cada combinacion: que el middleware se pueda anadir, que
bloquee un ataque, que deje pasar lo legitimo y que las cabeceras de seguridad
lleguen (tambien en el rechazo).

Detalles del entorno que hay que fijar, y que no son culpa de Gatekeeper:
- `httpx`: las Starlette nuevas (>= 0.47) usan `httpx2` y las antiguas
  `httpx`. Instalar las dos a la vez rompe el `TestClient` de las antiguas.
- `starlette`: FastAPI 0.103.x exige `starlette<0.28`, FastAPI 0.110.x
  `starlette<0.38`. Sin fijarla, pip instala la ultima y rompe FastAPI.

Uso:
    python tools/compat_matrix.py            # mide y escribe el markdown
    python tools/compat_matrix.py --json     # salida JSON
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRUEBA_STARLETTE = """
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from gatekeeper import Config, GatekeeperMiddleware

async def ok(request):
    return PlainTextResponse("ok")

app = Starlette(routes=[Route("/{path:path}", ok)])
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100))
with TestClient(app) as c:
    assert c.get("/ok").status_code == 200, "no dejo pasar lo legitimo"
    r = c.get("/x?q=1%20UNION%20SELECT%20password%20FROM%20users")
    assert r.status_code == 403, f"no bloqueo el ataque: {r.status_code}"
    cabeceras = {k.lower() for k in r.headers}
    assert "x-content-type-options" in cabeceras, "faltan cabeceras de seguridad"
import starlette
print(f"starlette={starlette.__version__}")
"""

PRUEBA_FASTAPI = """
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()

@app.get("/saludo")
async def saludo():
    return {"ok": True}

app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100))
with TestClient(app) as c:
    assert c.get("/saludo").status_code == 200, "no dejo pasar lo legitimo"
    r = c.get("/saludo?q=1%20UNION%20SELECT%20password%20FROM%20users")
    assert r.status_code == 403, f"no bloqueo el ataque: {r.status_code}"
    cabeceras = {k.lower() for k in r.headers}
    assert "x-content-type-options" in cabeceras, "faltan cabeceras de seguridad"
import fastapi, starlette
print(f"fastapi={fastapi.__version__} starlette={starlette.__version__}")
"""

# (lo que se instala, etiqueta, starlette fijada, httpx)
CASOS_STARLETTE = [
    ("starlette==0.23.0", "0.23.0", "0.23.0", "httpx<0.28"),
    ("starlette==0.27.0", "0.27.0", "0.27.0", "httpx<0.28"),
    ("starlette==0.37.0", "0.37.0", "0.37.0", "httpx<0.28"),
    ("starlette==0.41.3", "0.41.3", "0.41.3", "httpx<0.28"),
    ("starlette==0.46.2", "0.46.2", "0.46.2", "httpx<0.28"),
    ("starlette", "última", None, "httpx2"),
]

CASOS_FASTAPI = [
    ("fastapi==0.103.2", "0.103.2", "starlette==0.27.0", "httpx<0.28"),
    ("fastapi==0.110.3", "0.110.3", "starlette==0.37.2", "httpx<0.28"),
    ("fastapi==0.115.6", "0.115.6", "starlette==0.41.3", "httpx<0.28"),
    ("fastapi", "última", None, "httpx2"),
]


def _probar(instalar: str, prueba: str, starlette: str | None, httpx: str,
            diferencial: str) -> dict:
    """Crea un venv limpio, instala y ejecuta la prueba.

    Ademas del ataque y de la peticion legitima, ejecuta el test DIFERENCIAL
    del body: el middleware y la aplicacion tienen que interpretar el body
    IGUAL en esa version de Starlette o FastAPI. Un 403 que llega donde no
    tocaba, o un body que la app ve distinto, son fallos de Gatekeeper.
    """
    with tempfile.TemporaryDirectory() as tmp:
        v = Path(tmp) / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", str(v)], check=True, capture_output=True
        )
        py = v / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

        # Para Starlette, `instalar` ya lleva la version fijada; el pin extra
        # solo hace falta en el caso de FastAPI (que exige un rango de
        # Starlette concreto). Si se pasan las dos, pip las ve como
        # requirements en conflicto.
        # `python-multipart` no es de Gatekeeper: lo necesita la APLICACION
        # para parsear un formulario (en Starlette viejo, `request.form()` lo
        # exige incluso para un urlencoded). Sin el, el test diferencial no
        # puede comparar la vista de la app con la del middleware.
        paquetes = [str(ROOT), instalar, httpx, "python-multipart"]
        if starlette and not instalar.startswith("starlette"):
            paquetes.append(starlette)
        r = subprocess.run(
            [str(py), "-m", "pip", "install", "-q", *paquetes],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            lineas = [x for x in r.stderr.strip().splitlines() if x.strip()]
            return {"ok": False, "error": lineas[-1][:140] if lineas else "instalacion fallida"}

        r = subprocess.run([str(py), "-c", prueba], capture_output=True, text=True)
        if r.returncode != 0:
            lineas = [x for x in r.stderr.strip().splitlines() if x.strip()]
            return {"ok": False, "diferencial": False,
                    "error": lineas[-1][:140] if lineas else "prueba fallida"}

        d = subprocess.run(
            [str(py), str(ROOT / "tools" / "diferencial_body.py"),
             "--marco", diferencial],
            capture_output=True, text=True,
        )
        if d.returncode != 0:
            # El motivo esta en stdout (la lista de fallos); stderr es el ruido.
            lineas = [
                x for x in d.stdout.strip().splitlines() if x.strip()
            ]
            if not lineas:
                lineas = [
                    x for x in d.stderr.strip().splitlines() if x.strip()
                ]
            return {"ok": False, "diferencial": False,
                    "error": "diferencial: "
                    + (lineas[-1][:160] if lineas else "fallo sin detalle")}
        return {"ok": True, "diferencial": True, "error": "",
                "versiones": r.stdout.strip()}


def medir() -> dict:
    resultados = {"starlette": [], "fastapi": []}
    for instalar, etiqueta, starlette, httpx in CASOS_STARLETTE:
        # En los venv de Starlette no hay FastAPI: solo se prueba Starlette.
        res = _probar(instalar, PRUEBA_STARLETTE, starlette, httpx, "starlette")
        resultados["starlette"].append({"etiqueta": etiqueta, **res})
    for instalar, etiqueta, starlette, httpx in CASOS_FASTAPI:
        # Con FastAPI instalado se prueban los dos marcos: la app de FastAPI
        # tiene su propio camino de parseo del body.
        res = _probar(instalar, PRUEBA_FASTAPI, starlette, httpx, "todos")
        resultados["fastapi"].append({"etiqueta": etiqueta, **res})
    return resultados


def a_markdown(datos: dict) -> str:
    lineas = [
        "| Framework | Versión | Ataque y 200 | Diferencial del body |",
        "|---|---|---|---|",
    ]
    for clave, titulo in (("starlette", "Starlette"), ("fastapi", "FastAPI")):
        for caso in datos[clave]:
            if caso["ok"]:
                lineas.append(
                    f"| {titulo} | {caso['etiqueta']} | OK | "
                    f"{'OK' if caso.get('diferencial') else 'NO PROBADO'} |"
                )
            else:
                lineas.append(f"| {titulo} | {caso['etiqueta']} | FALLO: {caso['error']} | |")
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    datos = medir()
    if args.json:
        print(json.dumps(datos, indent=2, ensure_ascii=False))
    else:
        print(a_markdown(datos))

    fallidos = [
        c for clave in datos for c in datos[clave] if not c["ok"]
    ]
    return 1 if fallidos else 0


if __name__ == "__main__":
    raise SystemExit(main())
