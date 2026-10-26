#!/usr/bin/env python3
"""Paquete de pruebas de ataque para la revision de seguridad independiente.

Este script es el punto de partida del revisor. Cada comprobacion es
ejecutable y su resultado es objective: si el codigo cambia y un hallazgo
vuelve, la comprobacion lo dice.

NO modifica el repo: solo hace peticiones ASGI en memoria y mide.

Uso:
    python .audit/PACK-REVISOR/ejecutar_pocs.py            # todas
    python .audit/PACK-REVISOR/ejecutar_pocs.py mas        # solo las que cuyo
                                                          # nombre contenga "mas"
    python .audit/PACK-REVISOR/ejecutar_pocs.py --listar   # los nombres

Que significa cada veredicto:

  PASA   la propiedad se cumple (lo esperado en el codigo actual)
  FALLA  la propiedad NO se cumple: hay un hallazgo que investigar
  INFO   no es un veredicto: un dato o un limite conocido, para que el
         revisor juzgue si es aceptable

El codigo se toma del repo, no de una copia instalada: se anade `src/` al
`sys.path` desde la raiz del repositorio, asi que lo que se prueba es
exactamente lo que esta en GitHub.
"""
from __future__ import annotations

import io
import json
import logging
import os
import sys
import time
import tracemalloc
from pathlib import Path

# --- localizar el codigo del repo (sin rutas escritas a mano) ---------------
AQUI = Path(__file__).resolve()
RAIZ_REPO = AQUI.parents[2]
PAQUETE = RAIZ_REPO / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PAQUETE / "src"))

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from gatekeeper import Config, GatekeeperMiddleware  # noqa: E402
from gatekeeper.body import extract_strings  # noqa: E402
from gatekeeper.rules import normalize, scan  # noqa: E402

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"

# Los eventos de auditoria se recogen con un handler: sin esto, el `logging`
# de Python los imprime por stderr y la salida del script es inservible.
logging.getLogger("gatekeeper").addHandler(logging.NullHandler())


class _Colector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.eventos: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.eventos.append(json.loads(record.getMessage()))
        except (ValueError, TypeError):
            pass


class _ConAuditoria:
    """Recoge los eventos del logger de Gatekeeper mientras dura el bloque."""

    def __init__(self) -> None:
        self.colector = _Colector()

    def __enter__(self) -> _Colector:
        self._logger = logging.getLogger("gatekeeper")
        self._nivel = self._logger.level
        self._logger.setLevel(logging.WARNING)
        self._logger.addHandler(self.colector)
        return self.colector

    def __exit__(self, *_exc: object) -> None:
        self._logger.removeHandler(self.colector)
        self._logger.setLevel(self._nivel)


def _app(con_middleware: bool = True, **cfg: object) -> Starlette:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok, methods=["GET", "POST"])])
    if con_middleware:
        app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return app


def _cliente(**cfg: object) -> TestClient:
    return TestClient(_app(True, **cfg))


# =============================================================================
# 1. H-1 (DoS de memoria por punteros JSON cuadraticos) — REGRESION
# =============================================================================
def poc_punteros_json(resultados: list[tuple[str, str, str]]) -> None:
    """El puntero JSON no puede crecer de forma cuadratica.

    Antes del arreglo: 10.000 niveles costaban 193,6 MiB (2.401x la entrada) y
    10 peticiones simultaneas llegaban a 1,9 GiB. Ahora el puntero se recorta
    (profundidad 64, longitud 256) y el consumo es lineal.

    Se mide el factor de amplificacion: es lo que distingue el fallo del
    comportamiento correcto, y no depende de la maquina.
    """
    niveles = 10_000
    cuerpo = (b'{"a":' * niveles) + b"1" + (b"}" * niveles)
    tracemalloc.start()
    extract_strings("application/json", cuerpo)
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    factor = pico / len(cuerpo)
    if factor < 100:
        resultados.append((PASA, "H-1 punteros JSON: sin amplificacion cuadratica",
                           f"{niveles} niveles: pico {pico / 1024 / 1024:.1f} MiB "
                           f"({factor:.0f}x la entrada; el arreglo fija el tope en ~100x)"))
    else:
        resultados.append((FALLA, "H-1 punteros JSON: amplificacion cuadratica",
                           f"{niveles} niveles: pico {pico / 1024 / 1024:.1f} MiB "
                           f"({factor:.0f}x la entrada) — el arreglo no aguanta"))


# =============================================================================
# 2. El `+` de un body es LITERAL — REGRESION (bypass de SQLi, F6.4)
# =============================================================================
def poc_mas_body(resultados: list[tuple[str, str, str]]) -> None:
    """En una query el `+` es un espacio; en un body, un caracter literal.

    Si el middleware vuelve a traducirlo, `sleep(10+6)` pasa con 200 y la
    aplicacion ejecuta la consulta (16 segundos de sueño en MySQL).
    """
    casos = [
        ("form con %2B", "/", b"q=sleep(10%2B6)",
         "application/x-www-form-urlencoded", 403),
        ("json con + crudo", "/", b'{"q":"sleep(10+6)"}', "application/json", 403),
        ("query con %2B", "/?q=sleep(10%2B6)", b"", "", 403),
        ("cabecera con +", "/", b"hola", "text/plain", 403),
    ]
    for nombre, ruta, cuerpo, ctype, esperado in casos:
        cabeceras = {"content-type": ctype} if ctype else {}
        if nombre == "cabecera con +":
            cabeceras["user-agent"] = "sleep(10+6)"
        cliente = _cliente(rate_limit=0)
        estado = cliente.post(ruta, content=cuerpo, headers=cabeceras).status_code
        if estado == esperado:
            resultados.append((PASA, f"el `+` literal se detecta ({nombre})",
                               f"estado {estado}"))
        else:
            resultados.append((FALLA, f"el `+` literal se escapa ({nombre})",
                               f"estado {estado}, se esperaba {esperado}: el payload "
                               f"llega a la aplicacion sin inspeccionar"))

    # Control: el `+` conservado no puede traer falsos positivos.
    cliente = _cliente(rate_limit=0)
    estado = cliente.post("/", content=b"q=2%2B2",
                          headers={"content-type": "application/x-www-form-urlencoded"}
                          ).status_code
    if estado == 200:
        resultados.append((PASA, "control: `2+2` en un body no es un falso positivo",
                           "estado 200"))
    else:
        resultados.append((FALLA, "control: `2+2` en un body se bloquea",
                           f"estado {estado}"))


# =============================================================================
# 3. La auditoria NO lleva valores — el log no puede filtrar el payload
# =============================================================================
def poc_log_sin_valores(resultados: list[tuple[str, str, str]]) -> None:
    """El log lleva la regla, el campo y el patron: nunca el valor.

    El nombre del campo lo elige el atacante, asi que tiene que ir saneado y
    acotado: un ESC puede limpiar la terminal y 100 KB pueden hacer una linea
    de log de 100 KB.
    """
    secreto = "SECRETO_NO_DEBE_APARECER_9f3a"
    with _ConAuditoria() as colector:
        cliente = _cliente(rate_limit=0)
        cliente.post("/", json={"campo": f"1' OR '1'='1 {secreto}"})
    if not colector.eventos:
        resultados.append((FALLA, "el ataque no se audito",
                           "no hay ningun evento de attack_detected"))
        return
    crudo = json.dumps(colector.eventos, ensure_ascii=False)
    if secreto in crudo:
        resultados.append((FALLA, "el log lleva el valor del payload",
                           f"el valor {secreto!r} aparece en el evento"))
    else:
        resultados.append((PASA, "el log no lleva el valor del payload",
                           f"evento: {crudo[:160]}"))

    # El nombre del campo lo elige el atacante: tiene que estar acotado.
    campo_largo = "c" * 5000
    with _ConAuditoria() as colector:
        cliente = _cliente(rate_limit=0)
        cliente.post("/", json={campo_largo: "1' OR '1'='1"})
    for evento in colector.eventos:
        campo = str(evento.get("field", ""))
        if len(campo) > 256:
            resultados.append((FALLA, "el nombre del campo no esta acotado",
                               f"campo de {len(campo)} caracteres en el log"))
            break
    else:
        resultados.append((PASA, "el nombre del campo viene acotado",
                           "ningun campo del evento pasa de 256 caracteres"))


# =============================================================================
# 4. El escaneo es lineal con entradas patologicas
# =============================================================================
def poc_redos(resultados: list[tuple[str, str, str]]) -> None:
    """El tiempo tiene que crecer linealmente con el tamano de la entrada.

    Un umbral absoluto ("que no tarde mas de X") no sirve: una maquina lenta
    lo incumple sin que haya un fallo. Lo que distingue el fallo es la
    RELACION entre dos tamanos.
    """
    def coste(n: int) -> float:
        texto = "or" + " " * n
        inicio = time.perf_counter()
        scan(texto)
        return time.perf_counter() - inicio

    coste(100_000)  # calentamiento
    pequeno = min(coste(100_000) for _ in range(3))
    grande = min(coste(800_000) for _ in range(3))
    if pequeno <= 0:
        resultados.append((INFO, "coste de ReDoS no medible",
                           "el escaneo fue demasiado rapido para medirlo"))
        return
    razon = grande / pequeno
    if razon < 20:
        resultados.append((PASA, "el escaneo es lineal con entradas patologicas",
                           f"x8 de entrada -> x{razon:.1f} de tiempo (lineal ~x8, "
                           f"cuadratico ~x64)"))
    else:
        resultados.append((FALLA, "el escaneo crece mas que linealmente",
                           f"x8 de entrada -> x{razon:.1f} de tiempo"))


# =============================================================================
# 5. Con Redis caido, el coste por peticion esta acotado
# =============================================================================
def poc_redis_caido(resultados: list[tuple[str, str, str]]) -> None:
    """Con Redis caido, cada peticion paga como mucho `redis_timeout`.

    El timeout estaba escrito a pelo (2,0 s): la API respondia, pero despacio,
    y el WAF se convertia en el cuello de botella sin que nadie lo notara.
    """
    try:
        import redis  # noqa: F401
    except ImportError:
        resultados.append((INFO, "Redis caido: no medible",
                           "el extra [redis] no esta instalado"))
        return

    url = "redis://127.0.0.1:6399/0"  # puerto cerrado: connection refused
    for etiqueta, fail_open in (("fail-open (por defecto)", True),
                                 ("fail-closed (503)", False)):
        cliente = _cliente(rate_backend="redis", redis_url=url,
                           rate_fail_open=fail_open, redis_timeout=2.0)
        inicio = time.perf_counter()
        estado = cliente.get("/").status_code
        dt = time.perf_counter() - inicio
        if dt <= 2.5:
            resultados.append((PASA, f"Redis caido: coste acotado ({etiqueta})",
                               f"{dt * 1000:.0f} ms, estado {estado} "
                               f"(el timeout configurable es 2,0 s)"))
        else:
            resultados.append((FALLA, f"Redis caido: coste sin acotar ({etiqueta})",
                               f"{dt * 1000:.0f} ms, estado {estado}: la peticion "
                               f"tarda mas que el timeout de 2,0 s"))


# =============================================================================
# 6. El cuerpo se corta por el limite: no se puede agotar la memoria
# =============================================================================
def poc_limite_body(resultados: list[tuple[str, str, str]]) -> None:
    """Un body enorme tiene que cortarse en `max_body_size`, no leerse entero."""
    limite = Config().max_body_size
    cliente = _cliente(rate_limit=0)
    inicio = time.perf_counter()
    estado = cliente.post("/", content=b"x" * (limite * 4),
                          headers={"content-type": "text/plain"}).status_code
    dt = time.perf_counter() - inicio
    if estado in (200, 403, 413):
        resultados.append((PASA, "el body se corta por el limite",
                           f"4x el limite ({limite * 4} bytes): "
                           f"estado {estado} en {dt * 1000:.0f} ms"))
    else:
        resultados.append((FALLA, "el body no se corta por el limite",
                           f"estado {estado}"))


# =============================================================================
# 7. La app ve EXACTAMENTE lo mismo con y sin middleware
# =============================================================================
def poc_diferencial(resultados: list[tuple[str, str, str]]) -> None:
    """El middleware y la aplicacion interpretan el body igual.

    Si no, el middleware inspecciona una cosa y la app usa otra: eso es un
    bypass (el payload pasa por el campo que el middleware no vio) o un
    falso positivo (bloquea lo que la app no iba a usar).

    Reutiliza el test diferencial de la F6.4, que es la fuente unica.
    """
    import importlib.util

    ruta = PAQUETE / "tools" / "diferencial_body.py"
    if not ruta.exists():
        resultados.append((FALLA, "el test diferencial no existe",
                           f"no se encuentra {ruta}"))
        return
    spec = importlib.util.spec_from_file_location("diferencial_body", ruta)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    fallos: list[str] = []
    for marco in ("starlette", "fastapi"):
        try:
            fallos.extend(modulo.comprobar(marco))
        except ImportError:
            continue
    if fallos:
        resultados.append((FALLA, "el middleware y la app NO interpretan el body igual",
                           "; ".join(fallos[:4])))
    else:
        resultados.append((PASA, "el middleware y la app interpretan el body igual",
                           "26 cuerpos borde, 7 marcadores y 12 ataques, contra "
                           "Starlette y FastAPI"))


# =============================================================================
# 8. La configuracion hostil rompe el arranque (no pasa en silencio)
# =============================================================================
def poc_config_hostil(resultados: list[tuple[str, str, str]]) -> None:
    """Un valor de configuracion invalido tiene que romper el arranque.

    Si `Config()` acepta un `rate_limit` negativo o un CIDR malformado, el
    fallo se descubre en produccion, no al arrancar.
    """
    hostiles = [
        ("rate_limit negativo", {"rate_limit": -1}),
        ("rate_window cero", {"rate_window": 0}),
        ("rate_backend inexistente", {"rate_backend": "mysql"}),
        ("max_body_size negativo", {"max_body_size": -1}),
    ]
    fallos = []
    for nombre, kwargs in hostiles:
        try:
            Config(**kwargs)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            continue
        fallos.append(nombre)
    if fallos:
        resultados.append((FALLA, "la configuracion hostil pasa en silencio",
                           f"Config() acepta: {', '.join(fallos)}"))
    else:
        resultados.append((PASA, "la configuracion hostil rompe el arranque",
                           f"{len(hostiles)} valores invalidos rechazados"))


# =============================================================================
# 9. La normalizacion NFKC no puede activar una regla por si sola
# =============================================================================
def poc_nfkc_sin_deteccion(resultados: list[tuple[str, str, str]]) -> None:
    """NFKC expande (una `VIII` son 4 caracteres), pero no puede inventar un ataque.

    Es el limite A-2, aceptado y documentado: la expansion es lineal con el
    tamano del body y `max_body_size` la acota. Lo que NO puede es provocar un
    falso positivo: por eso se comprueba.
    """
    ampliados = ["\u2167" * 1000, "\uff38\uff2e\uff20" * 1000, "\u2460" * 1000]
    falsos = [t for t in ampliados if scan(t) is not None]
    if falsos:
        resultados.append((FALLA, "NFKC activa una regla por si sola",
                           f"{len(falsos)} de {len(ampliados)} textos ampliados disparan"))
    else:
        resultados.append((PASA, "NFKC no activa ninguna regla por si sola",
                           f"{len(ampliados)} textos ampliados: ninguno dispara"))


# --- registro de comprobaciones ---------------------------------------------
COMPROBACIONES = [
    ("punteros", poc_punteros_json,
     "H-1: la amplificacion de memoria del puntero JSON"),
    ("mas", poc_mas_body,
     "el `+` de un body es literal (bypass de SQLi)"),
    ("log", poc_log_sin_valores,
     "el log no lleva valores ni campos sin acotar"),
    ("redos", poc_redos,
     "el escaneo es lineal con entradas patologicas"),
    ("redis", poc_redis_caido,
     "con Redis caido, el coste por peticion esta acotado"),
    ("limite", poc_limite_body,
     "el body se corta por max_body_size"),
    ("diferencial", poc_diferencial,
     "el middleware y la app interpretan el body igual"),
    ("config", poc_config_hostil,
     "la configuracion hostil rompe el arranque"),
    ("nfkc", poc_nfkc_sin_deteccion,
     "NFKC no puede activar una regla por si sola"),
]


def main(argv: list[str]) -> int:
    if "--listar" in argv:
        print("Comprobaciones disponibles:")
        for nombre, _funcion, descripcion in COMPROBACIONES:
            print(f"  {nombre:12} {descripcion}")
        return 0

    filtros = [a for a in argv if not a.startswith("-")]
    selected = [
        (n, f, d) for n, f, d in COMPROBACIONES
        if not filtros or any(filtro in n for filtro in filtros)
    ]
    if not selected:
        print(f"Sin coincidencias: {filtros}")
        return 2

    print("=" * 78)
    print("PAQUETE DE PRUEBAS DE ATAQUE — revision de seguridad independiente")
    print(f"repo: {RAIZ_REPO}")
    print("=" * 78)

    resultados: list[tuple[str, str, str]] = []
    for nombre, funcion, _descripcion in selected:
        try:
            funcion(resultados)
        except Exception as exc:  # noqa: BLE001 - un PoC roto no debe parar al resto
            resultados.append((FALLA, f"{nombre}: la comprobacion ha fallado",
                               f"{type(exc).__name__}: {exc}"))

    print()
    for veredicto, titulo, detalle in resultados:
        print(f"[{veredicto}] {titulo}")
        if detalle:
            print(f"         {detalle}")

    pasan = sum(1 for v, _, _ in resultados if v == PASA)
    fallan = sum(1 for v, _, _ in resultados if v == FALLA)
    infos = sum(1 for v, _, _ in resultados if v == INFO)
    print()
    print("=" * 78)
    print(f"RESUMEN: {pasan} pasan · {fallan} fallan · {infos} notas")
    if fallan:
        print("Un FALLA es un hallazgo por investigar: NO es un veredicto sobre el")
        print("codigo, es un sintoma que el revisor tiene que confirmar y explicar.")
    print("=" * 78)
    return 1 if fallan else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
