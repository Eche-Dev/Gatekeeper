from .config import Config
from .middleware import GatekeeperMiddleware

__all__ = ["Config", "GatekeeperMiddleware"]


def _version() -> str:
    """La version, leida de los metadatos del paquete instalado.

    Estaba escrita a mano (`__version__ = "0.3.1"`) y se quedo desfasada al
    subir la version: el paquete instalado decia 0.3.1 con el wheel 0.4.0. La
    unica fuente de verdad es la metadata que genera `pyproject.toml`, asi que
    se lee de ahi.

    Si el paquete no esta instalado (import directo desde el arbol de
    fuentes), se busca el `pyproject.toml` con una expresion regular: no hace
    falta un parser de TOML, y `tomllib` no existe en Python 3.10.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("gatekeeper-asgi")
        except PackageNotFoundError:
            pass
    except ImportError:  # pragma: no cover - Python < 3.8
        pass

    # Sin instalar: leerlo de pyproject.toml (el arbol de fuentes).
    try:
        import re
        from pathlib import Path

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        texto = pyproject.read_text(encoding="utf-8")
        encontrado = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', texto)
        if encontrado:
            return str(encontrado.group(1))
    except Exception:  # pragma: no cover - fallback
        pass
    return "desconocida"


__version__ = _version()
