"""Demo desplegable de Gatekeeper.

Una "tienda" irreal delante del middleware: sirve para ver en vivo qué bloquea
Gatekeeper y qué deja pasar (playground con botones en la portada), y para
probar el rate limiting. Sin datos reales, sin estado, sin base de datos.

Ejecutar en local (desde esta carpeta):

    pip install -e .. fastapi uvicorn
    uvicorn app:app --reload

La auditoría de Gatekeeper sale por el logger ``gatekeeper``: mira la terminal
mientras pulsas los botones de la portada.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from gatekeeper import Config, GatekeeperMiddleware

# Los eventos de Gatekeeper (logger "gatekeeper", nivel WARNING) llegan a la
# terminal junto al resto de la app.
logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

app = FastAPI(title="Gatekeeper demo")

app.add_middleware(
    GatekeeperMiddleware,
    config=Config(
        # El rate limiting está activo a propósito: también es parte de la demo.
        rate_limit=120,
        rate_window=60.0,
        allow_paths=["/"],
    ),
)

CATALOGO = [
    "zapatillas deportivas",
    "silla ergonómica de oficina",
    "portátil 14 pulgadas",
    "mochila antirrobo",
]

# La portada es un playground: cada botón lanza una petición real contra
# /api/search y pinta el resultado. El texto del payload pasa por
# textContent (nunca por innerHTML): en un proyecto de seguridad, el ejemplo
# tiene que ser XSS-safe de verdad.
PAGINA = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gatekeeper · demo</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-monospace, Consolas, monospace; background: #0d1117;
         color: #c9d1d9; max-width: 46rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; } h1 span { color: #58a6ff; }
  p.lead { color: #8b949e; } b { color: #f85149; }
  button { display: block; width: 100%; text-align: left; margin: .4rem 0;
           padding: .6rem .8rem; background: #161b22; color: #c9d1d9;
           border: 1px solid #30363d; border-radius: 6px; cursor: pointer;
           font: inherit; }
  button:hover { border-color: #58a6ff; }
  pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
        padding: .8rem; min-height: 3rem; white-space: pre-wrap;
        word-break: break-all; }
  .ok { color: #3fb950; } .bloqueado { color: #f85149; }
</style>
</head>
<body>
<h1><span>Gatekeeper</span> · demo del middleware ASGI</h1>
<p class="lead">Cada botón envía <code>GET /api/search?q=…</code>. Gatekeeper
inspecciona la query antes de que llegue a la app: los patrones de ataque
reciben <b>403</b> y quedan en la auditoría del servidor.</p>
<div id="bots"></div>
<pre id="salida">$ toca un botón…</pre>
<script>
const casos = [
  ["zapatillas", "tráfico normal → 200"],
  ["' OR 1=1--", "SQLi → 403"],
  ["<script>alert(1)<\\/script>", "XSS → 403"],
  ["../../etc/shadow", "path traversal → 403"],
  ["/var/www/.env", "fichero sensible → 403"],
  ["1; SELECT pg_sleep(5)", "SQLi apilada → 403"],
];
const div = document.getElementById("bots"), salida = document.getElementById("salida");
for (const [payload, etiqueta] of casos) {
  const b = document.createElement("button");
  b.textContent = etiqueta + "   ·   " + payload;
  b.onclick = async () => {
    salida.textContent = '$ curl "/api/search?q=' + payload + '"\\n';
    const r = await fetch("/api/search?q=" + encodeURIComponent(payload));
    const span = document.createElement("span");
    span.className = r.ok ? "ok" : "bloqueado";
    span.textContent = r.status + " " + await r.text() + "\\n";
    salida.appendChild(span);
  };
  div.appendChild(b);
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def portada() -> str:
    return PAGINA


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/search")
async def buscar(q: str = "") -> dict[str, Any]:
    encontrados = [i for i in CATALOGO if q.lower() in i.lower()]
    return {"q": q, "count": len(encontrados), "results": encontrados}
