#!/usr/bin/env python3
"""F6: comprueba si al log de avisos le puede llegar texto sin sanear.

En `middleware._audit` todo lo que se escribe pasa por `sanear`/`sanear_y_acotar`
(la ruta, el nombre del campo, el patron). En `config.py`, en cambio, los avisos
de ReDoS escriben el nombre de la regla personalizada y el motivo del analisis
sin sanear. El motivo incluye fragmentos del propio patron.

Este script lo reproduce de verdad: crea la configuracion, captura el log y
busca el ESC.
"""
from __future__ import annotations

import io
import logging
import sys

from gatekeeper import Config

ESC = "\x1b[2J"  # borra la pantalla: el ESC que explica sanitize.py


def probar(nombre: str, patron: str) -> tuple[bool, str]:
    flujo = io.StringIO()
    manejador = logging.StreamHandler(flujo)
    registro = logging.getLogger("gatekeeper")
    registro.addHandler(manejador)
    nivel = registro.level
    registro.setLevel(logging.WARNING)
    try:
        Config(
            custom_rules={nombre: patron},
            allow_unsafe_custom_rules=True,
        )
    except ValueError as exc:  # pragma: no cover - solo si el patron no vale
        return False, f"ValueError: {exc}"
    finally:
        registro.removeHandler(manejador)
        registro.setLevel(nivel)
    salida = flujo.getvalue()
    return ESC in salida, salida.strip()


def main() -> int:
    # 1) El nombre de la regla lleva el ESC.
    lleva, salida = probar(f"regla{ESC}maliciosa", r"(a+)+")
    print("1) nombre de la regla con ESC")
    print(f"   ESC en el log: {lleva}")
    print(f"   log: {salida[:220]!r}")
    print()

    # 2) El patron lleva el ESC (el motivo incluye fragmentos del patron).
    lleva2, salida2 = probar("regla_normal", f"(a+)+x{ESC}")
    print("2) patron de la regla con ESC")
    print(f"   ESC en el log: {lleva2}")
    print(f"   log: {salida2[:220]!r}")
    print()

    if lleva or lleva2:
        print("HALLAZGO: al log le llega texto sin sanear")
        return 1
    print("OK: nada llega al log sin sanear")
    return 0


if __name__ == "__main__":
    sys.exit(main())
