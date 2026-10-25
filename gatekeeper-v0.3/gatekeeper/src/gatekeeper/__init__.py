from .config import Config
from .middleware import GatekeeperMiddleware

__all__ = ["Config", "GatekeeperMiddleware"]


def _version_desde_fuente() -> str:
    """Version leyendo el `pyproject.toml` del arbol de fuentes.

    Solo se usa cuando el paquete NO esta instalado (import directo desde el
    repositorio). No se usa un parser de TOML porque `tomllib` es de Python
    3.11 y el paquete soporta la 3.10.
    """
    try:
        import re
        from pathlib import Path

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        texto = pyproject.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # No se puede leer: mejor "desconocida" que una version inventada.
        return "desconocida"

    encontrado = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', texto)
    if encontrado:
        return str(encontrado.group(1))
    return "desconocida"


def _version() -> str:
    """La version, leida de los metadatos del paquete instalado.

    Estaba escrita a mano (`__version__ = "0.3.1"`) y se quedo desfasada al
    subir la version: el paquete instalado decia 0.3.1 con el wheel 0.4.0.
    La unica fuente de verdad es la metadata que genera `pyproject.toml`,
    asi que se lee de ahi. Si el paquete no esta instalado, se busca en el
    arbol de fuentes.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        instalada = version("gatekeeper-asgi")
    except PackageNotFoundError:
        instalada = _version_desde_fuente()
    return str(instalada)


__version__ = _version()
