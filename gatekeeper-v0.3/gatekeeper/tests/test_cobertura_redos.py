"""Cobertura del analisis estatico de ReDoS.

`redos.py` decide, SIN ejecutar la regex del usuario, si un patron propio es
peligroso. Esa decision se basa en la estructura del patron: cuantificadores
sin cota, alternativas que se solapan, referencias atras.

Los helpers internos (`_categorias`, `_se_solapan`, `_alternativas`...) son los
que toman esas decisiones, y sus ramas —una clase de caracteres, un escape, un
`|` de primer nivel— no se dan en los patrones de la vida diaria. Sin tests,
un cambio en esas ramas pasaria desapercibido.

No cambia ningun comportamiento: solo se comprueba lo que ya hace el codigo.
"""

from __future__ import annotations

from gatekeeper import redos


# ------------------------------------------------------- _salta_clase
def test_una_clase_negada_empieza_con_caret():
    """El `^` inicial de una clase no es parte de la clase."""
    # `[^a]`: el indice DESPUES de la clase es 4.
    assert redos._salta_clase("[^a]", 0) == 4


def test_un_corchete_inicial_es_literal():
    """Un `]` al principio de una clase es un literal, no el cierre.

    En Python, `[]a]` es la clase que casa con `]` o `a`.
    """
    assert redos._salta_clase("[]a]", 0) == 4


def test_un_caracter_escapado_dentro_de_la_clase():
    """Un `\\]` dentro de la clase no la cierra."""
    assert redos._salta_clase(r"[\]]", 0) == 4


# ------------------------------------------------------- _categorias
def test_las_categorias_de_un_literal():
    """Un caracter suelto solo casa consigo mismo."""
    assert redos._categorias("a") == {"lit:a"}


def test_las_categorias_de_los_escapes_con_clase():
    """`\\d`, `\\w` y `\\s` son clases conocidas: se pueden comparar."""
    assert redos._categorias(r"\d") == {"digito"}
    assert redos._categorias(r"\w") == {"digito", "letra", "guion"}
    assert redos._categorias(r"\s") == {"espacio"}


def test_las_categorias_de_los_escapes_negados():
    """`\\D`, `\\W` y `\\S` son "cualquiera": se solapan con todo."""
    for escape in (r"\D", r"\W", r"\S"):
        assert redos._categorias(escape) == {redos._TODAS}


def test_las_categorias_de_un_escape_de_un_caracter_desconocido():
    """`\\n` y `\\t` no se saben que casan: son None.

    None significa "no lo se", y el analisis lo trata como solapamiento
    (conservador): mejor avisar de mas que de menos.
    """
    assert redos._categorias(r"\n") is None
    assert redos._categorias(r"\t") is None
    assert redos._categorias(r"\0") is None


def test_las_categorias_de_un_escape_hexadecimal():
    r"""`\x41` se trata como un literal inventado, no como "no lo se".

    Es una aproximacion grosera (el escape casa `A`, no `x41`), pero solo
    importa para decidir si dos atomos se solapan, y un escape hexadecimal en
    una regla propia es un caso limite. Lo que se fija aqui es el
    comportamiento real, no una mejora.
    """
    assert redos._categorias(r"\x41") == {"lit:x41"}


def test_las_categorias_de_una_clase_de_caracteres():
    """Una clase con literales se descompone en los literales que casan."""
    assert redos._categorias("[abc]") == {"lit:a", "lit:b", "lit:c"}


def test_las_categorias_de_un_rango_no_se_saben():
    """Un rango (`[a-z]`) no se descompone: se trata como "cualquiera"."""
    assert redos._categorias("[a-z]") == {redos._TODAS}


# ------------------------------------------------------- _se_solapan
def test_dos_categorias_desconocidas_se_solapan():
    """Si no se sabe que casa una, se asume que se solapa (conservador)."""
    assert redos._se_solapan(None, {"lit:a"}) is True
    assert redos._se_solapan({"lit:a"}, None) is True


def test_cualquiera_se_solapa_con_todo():
    """Una categoria "cualquiera" se solapa con la que sea."""
    assert redos._se_solapan({redos._TODAS}, {"lit:a"}) is True
    assert redos._se_solapan({"lit:a"}, {redos._TODAS}) is True


def test_categorias_distintas_no_se_solapan():
    """Dos literales distintos no pueden casar el mismo caracter."""
    assert redos._se_solapan({"lit:a"}, {"lit:b"}) is False


# ------------------------------------------------------- _alternativas
def test_las_alternativas_se_parten_en_el_pipe_de_primer_nivel():
    """El `|` de primer nivel separa; el de dentro de un grupo no."""
    partes = redos._alternativas("foo|bar")
    assert partes == ["foo", "bar"]
    # El `|` dentro de `(...)` no separa.
    assert redos._alternativas("(a|b)c") == ["(a|b)c"]


def test_las_alternativas_saben_donde_hay_escapes():
    """Un `\\|` escapado no es un separador."""
    partes = redos._alternativas(r"a\|b|c")
    assert partes == [r"a\|b", "c"]


def test_las_alternativas_saben_donde_hay_clases():
    """Un `|` dentro de una clase no es un separador."""
    partes = redos._alternativas("[a|b]c|d")
    assert partes == ["[a|b]c", "d"]


def test_una_alternativa_vacia_se_solapa():
    """Una alternativa vacia puede casar sin consumir: hay infinitas formas.

    `(a|)+` con texto largo es un DoS clasico, y por eso se detecta.
    """
    assert redos._alternativas_solapadas(["", "a"]) is True
    assert redos._alternativas_solapadas(["a", ""]) is True


# ------------------------------------------- referencias atras
def test_detecta_una_referencia_atras_con_numero():
    """`\\1` es una referencia atras."""
    assert redos._tiene_referencia_atras(r"(a)\1") is True


def test_detecta_una_referencia_atras_con_g():
    """`\\g<1>` tambien es una referencia atras."""
    assert redos._tiene_referencia_atras(r"(a)\g<1>") is True


def test_una_escape_normal_no_es_referencia_atras():
    """`\\d` no es una referencia atras."""
    assert redos._tiene_referencia_atras(r"\d+\s") is False


# ------------------------------------------- riesgo anidado
# OJO: `_riesgo_anidado` recibe el CUERPO del grupo (lo que va dentro de los
# parentesis), no el patron completo. `analizar_redos` se lo pasa asi.
def test_un_cuantificador_anidado_sin_nada_detras_es_exponencial():
    """El cuerpo `a+` no tiene nada obligatorio detras: el motor puede partir
    el texto de infinitas formas."""
    nivel, motivo = redos._riesgo_anidado("a+")
    assert nivel == redos.NIVEL_EXPONENCIAL
    assert "no va seguido de nada obligatorio" in motivo


def test_un_cuantificador_anidado_con_separador_que_no_se_solapa_es_cuadratico():
    """El cuerpo `?:\\w+\\.` tiene un separador que el interior no puede casar.

    Las repeticiones quedan delimitadas: el coste es cuadratico, no
    exponencial. Es el caso de `(?:\\w+\\.)+\\w+`.
    """
    nivel, motivo = redos._riesgo_anidado(r"?:\w+\.")
    assert nivel == redos.NIVEL_CUADRATICO
    assert "cuadratico" in motivo


def test_un_cuantificador_anidado_con_separador_que_se_solapa_es_exponencial():
    """El cuerpo `?:a+a` tiene un separador que el interior SI puede casar.

    Es el caso en el que el motor puede probar las dos formas de partir el
    texto, y por eso es exponencial y no solo cuadratico.
    """
    nivel, motivo = redos._riesgo_anidado("?:a+a")
    assert nivel == redos.NIVEL_EXPONENCIAL
    assert "varias formas" in motivo


# ------------------------------------------- el analisis completo
def test_una_referencia_atras_dentro_de_un_grupo_repetido_se_detecta():
    """`(a|\\1)+` es peligroso: la referencia atras multiplica las formas."""
    nivel, motivo = redos.analizar_redos(r"(a|\1)+")
    assert nivel == redos.NIVEL_EXPONENCIAL
    assert "referencia atras" in motivo


def test_una_referencia_atras_repetida_por_fuera_se_detecta():
    """`(\\w+)\\1+` multiplica las formas por cada intento del grupo."""
    nivel, motivo = redos.analizar_redos(r"(\w+)\1+")
    assert nivel == redos.NIVEL_EXPONENCIAL
    assert "referencia atras repetida" in motivo


def test_alternativas_solapadas_en_un_grupo_repetido_se_detectan():
    """`(a|ab)+`: las alternativas comparten prefijo."""
    nivel, motivo = redos.analizar_redos("(a|ab)+")
    assert nivel == redos.NIVEL_EXPONENCIAL
    assert "alternativas solapadas" in motivo


def test_un_patron_sano_no_da_ningun_riesgo():
    """Un patron corriente no se marca: el analizador no ensucia el log."""
    assert redos.analizar_redos(r"https?://[a-z]+") is None
    assert redos.analizar_redos(r"\d{1,4}") is None
