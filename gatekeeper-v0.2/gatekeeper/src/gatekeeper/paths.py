from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from .rules import decode


def is_path_allowed(path: str, patterns: Iterable[str]) -> bool:
    """¿Esta ruta está exenta de inspección?

    Se compara con patrones glob (`fnmatch`, sensible a mayúsculas; `*` también
    cruza `/`). Una ruta con indicios de traversal o con codificación residual
    NUNCA se considera exenta, para que `/docs/../admin` no se cuele por `/docs/*`.
    """
    patterns = list(patterns)
    if not patterns:
        return False
    if decode(path) != path or "\\" in path or ".." in path.split("/"):
        return False
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)
