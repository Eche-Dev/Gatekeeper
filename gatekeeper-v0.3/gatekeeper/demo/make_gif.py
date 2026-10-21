"""Genera docs/assets/demo.gif a partir de la transcripción REAL de una sesión
local contra demo/app.py (uvicorn + curl, capturada el 21-oct-2026).

El GIF es una transcripción curada de esa sesión: las líneas de comando,
respuestas y eventos de auditoría son literales de la captura (solo se omitió
una petición ajena que lanzó algo del entorno). Para regenerarlo:

    pip install pillow
    python make_gif.py

Requiere Consolas (Windows) o cae a la fuente por defecto.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# (estilo, línea) de la sesión real. Estilos: cmd, resp200, resp403, info,
# audit, gap, footer.
LINEAS: list[tuple[str, str]] = [
    ("cmd", "$ python -m uvicorn app:app --port 8000"),
    ("info", "INFO:     Started server process [24816]"),
    ("info", "INFO:     Waiting for application startup."),
    ("info", "INFO:     Application startup complete."),
    ("info", "INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)"),
    ("gap", ""),
    ("cmd", '$ curl "http://127.0.0.1:8000/health"  -w "  <- HTTP %{http_code}"'),
    ("resp200", '{"status":"ok"}  <- HTTP 200'),
    ("info", 'INFO:     127.0.0.1:58767 - "GET /health HTTP/1.1" 200 OK'),
    ("gap", ""),
    ("cmd", '$ curl -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=zapatillas"'
            '  -w "  <- HTTP %{http_code}"'),
    ("resp200", '{"q":"zapatillas","count":1,"results":["zapatillas deportivas"]}  <- HTTP 200'),
    ("info", 'INFO:     127.0.0.1:58260 - "GET /api/search?q=zapatillas HTTP/1.1" 200 OK'),
    ("gap", ""),
    ("cmd", '$ curl -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=\' OR 1=1--"'
            '  -w "  <- HTTP %{http_code}"'),
    ("resp403", '{"detail":"Forbidden"}  <- HTTP 403'),
    ("audit", 'gatekeeper WARNING {"ts": 1792615399.0287766, "event": "attack_detected", '
              '"ip": "127.0.0.1", "method": "GET", "path": "/api/search", "rule": "sqli", '
              '"source": "query", "blocked": true}'),
    ("info", 'INFO:     127.0.0.1:58261 - "GET /api/search?q=%27+OR+1%3D1-- HTTP/1.1" 403 Forbidden'),
    ("gap", ""),
    ("cmd", '$ curl -G "http://127.0.0.1:8000/api/search" --data-urlencode '
            '"q=<script>alert(1)</script>"  -w "  <- HTTP %{http_code}"'),
    ("resp403", '{"detail":"Forbidden"}  <- HTTP 403'),
    ("audit", 'gatekeeper WARNING {"ts": 1792615399.0539842, "event": "attack_detected", '
              '"ip": "127.0.0.1", "method": "GET", "path": "/api/search", "rule": "xss", '
              '"source": "query", "blocked": true}'),
    ("info", 'INFO:     127.0.0.1:58262 - "GET /api/search?q=%3Cscript%3Ealert%281%29'
             '%3C%2Fscript%3E HTTP/1.1" 403 Forbidden'),
    ("gap", ""),
    ("cmd", '$ curl -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=../../etc/shadow"'
            '  -w "  <- HTTP %{http_code}"'),
    ("resp403", '{"detail":"Forbidden"}  <- HTTP 403'),
    ("audit", 'gatekeeper WARNING {"ts": 1792615399.0790052, "event": "attack_detected", '
              '"ip": "127.0.0.1", "method": "GET", "path": "/api/search", '
              '"rule": "path_traversal", "source": "query", "blocked": true}'),
    ("info", 'INFO:     127.0.0.1:58263 - "GET /api/search?q=..%2F..%2Fetc%2Fshadow HTTP/1.1"'
             ' 403 Forbidden'),
    ("gap", ""),
    ("cmd", '$ curl -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=1; SELECT pg_sleep(5)"'
            '  -w "  <- HTTP %{http_code}"'),
    ("resp403", '{"detail":"Forbidden"}  <- HTTP 403'),
    ("audit", 'gatekeeper WARNING {"ts": 1792615399.103816, "event": "attack_detected", '
              '"ip": "127.0.0.1", "method": "GET", "path": "/api/search", "rule": "sqli", '
              '"source": "query", "blocked": true}'),
    ("info", 'INFO:     127.0.0.1:58264 - "GET /api/search?q=1%3B+SELECT+pg_sleep%285%29'
             ' HTTP/1.1" 403 Forbidden'),
    ("gap", ""),
    ("footer", "Gatekeeper · middleware ASGI para FastAPI/Starlette · "
               "github.com/Eche-Dev/Gatekeeper"),
]

COLORES = {
    "fondo": "#0d1117",
    "barra": "#161b22",
    "texto": "#c9d1d9",
    "prompt": "#3fb950",
    "info": "#8b949e",
    "audit": "#d29922",
    "resp200": "#3fb950",
    "resp403": "#f85149",
    "footer": "#58a6ff",
}

FUENTE = 14
COLS = 112  # ancho de la "terminal" en columnas
ALTO_LINEA = FUENTE + 6
MARGEN = 16
BARRA = 28


def cargar_fuente() -> ImageFont.ImageFont:
    for nombre in ("consolas.ttf", "C:/Windows/Fonts/consolas.ttf"):
        try:
            return ImageFont.truetype(nombre, FUENTE)
        except OSError:
            continue
    return ImageFont.load_default()


def envolver(texto: str, fuente: ImageFont.ImageFont) -> list[str]:
    """Parte la línea como haría una terminal real, sin romper palabras."""
    if not texto:
        return [""]
    ancho_max = COLS * _avance(fuente)
    partes: list[str] = []
    actual = ""
    for palabra in texto.split(" "):
        candidata = palabra if not actual else f"{actual} {palabra}"
        if not actual or _medir(candidata, fuente) <= ancho_max:
            actual = candidata
        else:
            partes.append(actual)
            actual = palabra
    partes.append(actual)
    return partes


def _avance(fuente: ImageFont.ImageFont) -> float:
    return _medir("M" * 10, fuente) / 10


def _medir(texto: str, fuente: ImageFont.ImageFont) -> float:
    return fuente.getlength(texto)


def pintar(hasta: int, fuente: ImageFont.ImageFont) -> Image.Image:
    """Frame con las primeras `hasta` líneas de la transcripción."""
    filas: list[tuple[str, str]] = []
    for estilo, texto in LINEAS[:hasta]:
        for parte in envolver(texto, fuente):
            filas.append((estilo, parte))
    ancho = int(COLS * _avance(fuente)) + 2 * MARGEN
    alto = BARRA + 2 * MARGEN + len(filas) * ALTO_LINEA
    img = Image.new("RGB", (ancho, alto), COLORES["fondo"])
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, ancho, BARRA], fill=COLORES["barra"])
    for i, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        draw.ellipse([12 + i * 18, 9, 22 + i * 18, 19], fill=color)
    y = BARRA + MARGEN
    for estilo, parte in filas:
        color = COLORES.get(estilo, COLORES["texto"])
        if estilo == "cmd" and parte.startswith("$"):
            draw.text((MARGEN, y), "$", font=fuente, fill=COLORES["prompt"])
            draw.text((MARGEN + _medir("$ ", fuente), y), parte[1:].lstrip(),
                      font=fuente, fill=COLORES["texto"])
        else:
            draw.text((MARGEN, y), parte, font=fuente, fill=color)
        y += ALTO_LINEA
    return img


def main() -> None:
    fuente = cargar_fuente()
    # Un frame por intercambio (comando+respuesta+auditoría), con avance
    # progresivo y más tiempo en los frames donde aparece un bloqueo.
    cortes = [5, 9, 13, 17, 22, 27, len(LINEAS)]
    duraciones = [1400, 900, 900, 1600, 1600, 1600, 2600]
    rgb = [pintar(h, fuente) for h in cortes]
    # 256 colores por frame: con menos, la cuantización se come los grises del
    # texto. (Paletas compartidas entre frames no las guarda bien Pillow.)
    frames = [frame.quantize(colors=256) for frame in rgb]
    destino = Path(__file__).resolve().parent.parent / "docs" / "assets" / "demo.gif"
    destino.parent.mkdir(parents=True, exist_ok=True)
    # disposal=2: cada frame es completo, sin dependencias del anterior.
    frames[0].save(
        destino, save_all=True, append_images=frames[1:],
        duration=duraciones, loop=0, disposal=2,
    )
    print(f"{destino}  ({destino.stat().st_size // 1024} KiB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
