"""PoC de la cuarta ronda independiente (IA, Claude) contra 0.9.2.

NUEVO-3 sigue abierto (confirmado: 0 cambios en src/ desde la ronda 3) y se
amplía con más variantes. Se añaden dos hallazgos nuevos en `ssrf`, uno de
ellos un error aritmético de un solo carácter con impacto concreto.
"""
from __future__ import annotations

from gatekeeper.rules import scan_detailed

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


def poc_r4_nuevo3_sigue_abierto_mas_variantes(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-3 (de la ronda 3) sigue sin parchear; se amplía el mapa de variantes."""
    variantes = {
        "corchetes": "document['cookie']",
        "optional_chaining": "document?.cookie",
        "optional_chaining+corchetes": "document?.['cookie']",
        "self.document corchetes": "self.document['cookie']",
        "globalThis corchetes anidado": "globalThis['document']['cookie']",
        "top optional-chaining": "top?.location",
        "template literal como clave": "window[`eval`]('1')",
        "concatenacion de strings como clave": "window['ev'+'al']('1')",
        "concatenacion en document": "document[`coo`+`kie`]",
        "setTimeout por corchetes": "window['setTimeout']('alert(1)',0)",
    }
    coladas = [n for n, p in variantes.items() if not scan_detailed(p)]
    if len(coladas) >= 5:
        resultados.append((
            FALLA,
            "NUEVO-3 (ronda 3) sigue abierto: ningún cambio en src/ desde entonces",
            (f"{len(coladas)}/{len(variantes)} variantes de acceso a "
            f"document/window/eval por corchetes, optional-chaining o "
            f"template-literal-como-clave siguen sin detectarse: {coladas}. "
            "Ver SECURITY_REVIEW-IA-Claude-R3.md para el PoC con exfiltración "
            "real en Node ya entregado"),
        ))
    else:
        resultados.append((PASA, "NUEVO-3 ha sido parcheado", ""))


def poc_r4_ssrf_octal_mal_calculado(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-5: el octal hardcodeado para 169.254.169.254 representa 170.254.170.254."""
    bien_calculado = "http://0251.0376.0251.0376/latest/meta-data/"  # 169.254.169.254 en octal real
    el_que_usa_gatekeeper = "http://0252.0376.0252.0376/latest/meta-data/"  # lo que SÍ detecta: 170.254.170.254
    decimal_control = scan_detailed("http://2852039166/latest/meta-data/")  # control: la forma decimal sí funciona
    r_correcto = scan_detailed(bien_calculado)
    r_actual = scan_detailed(el_que_usa_gatekeeper)
    if decimal_control and not r_correcto and r_actual:
        resultados.append((
            FALLA,
            "NUEVO-5: el octal de 169.254.169.254 en rules.py está mal calculado (170 en vez de 169)",
            ("0o252 == 170, no 169 (169 en octal es 0o251). El literal "
            "`0252\\.0376\\.0252\\.0376` de la línea ~469 de rules.py "
            "detecta la URL octal de 170.254.170.254 (una IP que no "
            "significa nada), no la de 169.254.169.254 (el metadata IMDS "
            "real) que el propio comentario del código dice que cubre. "
            "El mismo error se repite en el literal de la variante ECS "
            "(`0252\\.0376\\.0252\\.0002`, que debería ser "
            "`0251\\.0376\\.0251\\.0002` para codificar 169.254.170.2). "
            f"octal correcto (169.254.169.254) -> {r_correcto!r} (no detecta); "
            f"octal que SÍ detecta -> {r_actual!r} (detecta 170.254.170.254, "
            "una IP irrelevante); control decimal (sí funciona) -> "
            f"{decimal_control!r}"),
        ))
    else:
        resultados.append((PASA, "el octal del metadata IP está bien calculado", ""))


def poc_r4_loopback_decimal_no_cubierto(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-6: docs/amenazas.md promete loopback decimal 'sospechoso'; el código no lo cubre."""
    r = scan_detailed("http://2130706433/")  # 127.0.0.1 en decimal
    if r is None:
        resultados.append((
            FALLA,
            ("NUEVO-6: docs/amenazas.md promete detectar loopback en decimal; "
            "el código no tiene ningún literal para ello"),
            ("docs/amenazas.md, fila `ssrf`: 'Una IP de loopback codificada en "
            "decimal sí es sospechosa'. `http://2130706433/` (127.0.0.1 en "
            "decimal) -> None. La lista de literales de rules.py solo cubre "
            "las IPs de metadata cloud, ninguna forma de 127.0.0.1"),
        ))
    else:
        resultados.append((PASA, "el loopback decimal se detecta como promete la documentación", ""))


COMPROBACIONES = [
    ("r4_nuevo3_abierto", poc_r4_nuevo3_sigue_abierto_mas_variantes, "NUEVO-3 sigue sin parchear"),
    ("r4_ssrf_octal", poc_r4_ssrf_octal_mal_calculado, "octal del metadata IP mal calculado (170 vs 169)"),
    ("r4_loopback_decimal", poc_r4_loopback_decimal_no_cubierto, "loopback decimal: docs vs código"),
]
