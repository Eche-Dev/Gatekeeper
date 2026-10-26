"""Deteccion de estructuras de regex capaces de backtracking catastrofico.

Las reglas INTEGRADAS de Gatekeeper estan acotadas a proposito (sus
cuantificadores llevan cota). Las reglas PERSONALIZADAS las escribe el
usuario, y ahi no habia red: una regex como `(a+)+$` sobre 60 caracteres no
termina ni en 20 segundos. Es un DoS que el usuario se introduce en su
propio WAF, sin adversarial: basta con que su regla reciba una entrada
adversa.

Este modulo busca, de forma ESTATICA (sin ejecutar la regex), las estructuras
que ya se sabe que son problematicas, y las separa en dos niveles segun lo
que se ha MEDIDO:

- **Exponencial** (`NIVEL_EXPONENCIAL`): cuelga con una entrada corta.
  Medido: `(a+)+$` contra 60 caracteres no termina en 20 s. Se RECHAZA al
  arrancar.
  - Cuantificador anidado sin nada obligatorio despues: el motor prueba
    todas las formas de partir el texto y solo una vale. `(a+)+`, `(.*)*`,
    `(\\d+)*`.
  - Alternativas que se solapan dentro de un grupo repetido: `(a|a)+`,
    `(a|ab)+`, `(https|http)+`.
  - Referencia atras repetida: `(\\w+)\\1+`.

- **Cuadratico** (`NIVEL_CUADRATICO`): no cuelga con una entrada corta, pero
  se degrade con el tamano. Medido: `(?:\\w+\\.)+\\w+` tarda 0,29 s con 10.000
  caracteres y 7,4 s con 50.000 (es O(n^2)). Con el `max_body_size` de
  256 KiB, una entrada de ese tamano puede tardar minutos. Se AVISA al
  arrancar, pero no se rechaza: son patrones legitimos (una expresion
  regular de dominio, por ejemplo) y el usuario decide.

Por que ESTATICA y no "ejecutarla y medir": medirla exigiria un timeout, y
en Python no hay forma de interrumpir un regex que ya esta corriendo (no
existe `regex.cancel()`; solo un hilo aparte, que no se puede matar). Si
Gatekeeper tuviera que ejecutar la regex del usuario para medirla, la propia
medicion seria el DoS. Ademas, la estructura se ve sin ejecutar: un patron
que la tiene es peligroso por como esta escrito, no por lo que se le pase.
"""
from __future__ import annotations

# Longitud maxima de un patron de regla personalizada. Un patron enorme es
# senal de que algo va mal, y ademas compilarlo y escanearlo cuesta.
MAX_PATTERN_LENGTH = 1000

# Numero maximo de reglas personalizadas. Cada una se evalua en cada texto
# inspeccionado: 1.000 reglas serian 1.000 passes por peticion.
MAX_CUSTOM_RULES = 100

NIVEL_EXPONENCIAL = "exponencial"
NIVEL_CUADRATICO = "cuadratico"

_CUANTIFICADORES = "*+?"
_TODAS = "cualquiera"


def _salta_clase(patron: str, i: int) -> int:
    """Indice DESPUES de la clase de caracteres que empieza en `i`."""
    n = len(patron)
    i += 1
    if i < n and patron[i] == "^":
        i += 1
    if i < n and patron[i] == "]":  # un ']' inicial es literal
        i += 1
    while i < n and patron[i] != "]":
        if patron[i] == "\\":
            i += 1
        i += 1
    return i + 1


def _salta_grupo(patron: str, i: int) -> int:
    """Indice DESPUES del grupo que empieza en `i`."""
    n = len(patron)
    profundidad = 0
    while i < n:
        c = patron[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _salta_clase(patron, i)
            continue
        if c == "(":
            profundidad += 1
        elif c == ")":
            profundidad -= 1
            if profundidad == 0:
                return i + 1
        i += 1
    return n


def _sin_cota(cuantificador: str) -> bool:
    """True si el cuantificador repite sin limite (`*`, `+`, `{m,}`)."""
    if cuantificador in ("*", "+"):
        return True
    if cuantificador.startswith("{") and cuantificador.endswith("}"):
        cuerpo = cuantificador[1:-1]
        # `{m,n}` tiene cota; `{m,}` no.
        return "," in cuerpo and not cuerpo.split(",", 1)[1].strip()
    return False


def _lee_cuantificador(patron: str, i: int) -> tuple[str | None, int]:
    """(cuantificador, indice DESPUES) del cuantificador que empieza en `i`."""
    n = len(patron)
    if i >= n:
        return None, i
    if patron[i] in _CUANTIFICADORES:
        return patron[i], i + 1
    if patron[i] == "{":
        fin = patron.find("}", i)
        if fin != -1:
            return patron[i:fin + 1], fin + 1
    return None, i


def _grupos_cuantificados(patron: str) -> list[tuple[str, str]]:
    """(cuerpo, cuantificador) de cada grupo con cuantificador.

    Se ignoran escapes y clases de caracteres: un `)` dentro de `[()]` no
    cierra un grupo, y `\\)` tampoco.
    """
    grupos: list[tuple[str, str]] = []
    pila: list[int] = []
    i = 0
    n = len(patron)
    while i < n:
        c = patron[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _salta_clase(patron, i)
            continue
        if c == "(":
            pila.append(i)
            i += 1
            continue
        if c == ")" and pila:
            inicio = pila.pop()
            cuantificador, fin = _lee_cuantificador(patron, i + 1)
            if cuantificador is not None:
                grupos.append((patron[inicio + 1:i], cuantificador))
            i = fin
            continue
        i += 1
    return grupos


def _items(texto: str) -> list[tuple[str, str | None]]:
    """`(atomo, cuantificador)` de un texto, en orden.

    Un "atomo" es lo que puede casar: un caracter, una escape, una clase de
    caracteres o un grupo anidado. El cuantificador es `None` si no lo lleva.
    """
    items: list[tuple[str, str | None]] = []
    i = 0
    n = len(texto)
    while i < n:
        c = texto[i]
        if c == "\\":
            fin = min(i + 2, n)
            cuantificador, siguiente = _lee_cuantificador(texto, fin)
            items.append((texto[i:fin], cuantificador))
            i = siguiente
            continue
        if c == "[":
            fin = _salta_clase(texto, i)
            cuantificador, siguiente = _lee_cuantificador(texto, fin)
            items.append((texto[i:fin], cuantificador))
            i = siguiente
            continue
        if c == "(":
            fin = _salta_grupo(texto, i)
            cuantificador, siguiente = _lee_cuantificador(texto, fin)
            items.append((texto[i:fin], cuantificador))
            i = siguiente
            continue
        if c == "|":
            i += 1
            continue
        cuantificador, siguiente = _lee_cuantificador(texto, i + 1)
        items.append((c, cuantificador))
        i = siguiente
    return items


def _categorias(atomo: str) -> set[str] | None:
    """Categorias de caracteres que puede casar un atomo, o None si no se sabe.

    No hace falta ser exacto: basta con distinguir "esto se solapa con eso"
    de "esto no se solapa con aquello". Un `None` significa "no lo se", y se
    trata como solapamiento (conservador).
    """
    if len(atomo) == 1:
        return {f"lit:{atomo}"}
    if atomo.startswith("\\"):
        escape = atomo[1:]
        if escape == "d":
            return {"digito"}
        if escape == "w":
            return {"digito", "letra", "guion"}
        if escape == "s":
            return {"espacio"}
        if escape in ("D", "W", "S"):
            return {_TODAS}
        if len(escape) == 1 and escape.isalnum():
            return None  # \n, \t, \x41... no se sabe
        return {f"lit:{escape}"}
    if atomo.startswith("["):
        if "-" in atomo[1:-1]:  # rango: no se sabe con precision
            return {_TODAS}
        return {f"lit:{c}" for c in atomo[1:-1] if c != "^"}
    return None


def _se_solapan(a: set[str] | None, b: set[str] | None) -> bool:
    """True si dos categorias pueden casar el mismo caracter."""
    if a is None or b is None:
        return True  # no se sabe: se trata como solapamiento
    if _TODAS in a or _TODAS in b:
        return True
    return bool(a & b)


def _alternativas(cuerpo: str) -> list[str]:
    """Las alternativas de una alternacion de primer nivel."""
    partes: list[str] = []
    actual: list[str] = []
    profundidad = 0
    i = 0
    n = len(cuerpo)
    while i < n:
        c = cuerpo[i]
        if c == "\\":
            actual.append(cuerpo[i:i + 2])
            i += 2
            continue
        if c == "[":
            fin = _salta_clase(cuerpo, i)
            actual.append(cuerpo[i:fin])
            i = fin
            continue
        if c == "(":
            profundidad += 1
        elif c == ")":
            profundidad -= 1
        if c == "|" and profundidad == 0:
            partes.append("".join(actual))
            actual = []
            i += 1
            continue
        actual.append(c)
        i += 1
    partes.append("".join(actual))
    return partes


def _alternativas_solapadas(alternativas: list[str]) -> bool:
    """True si dos alternativas pueden empezar por lo mismo.

    `(foo|bar)` no se solapa; `(foo|foobar)` si (una es prefijo de la otra), y
    ahi el motor prueba las dos formas de partir el texto.
    """
    for i, a in enumerate(alternativas):
        if not a:
            # Una alternativa vacia puede casar sin consumir: el motor
            # tiene infinitas formas de seguir.
            return True
        for b in alternativas[i + 1:]:
            if a == b or a.startswith(b) or b.startswith(a):
                return True
    return False


def _tiene_referencia_atras(texto: str) -> bool:
    """True si el texto contiene una referencia atras (`\\1`, `\\g<1>`)."""
    i = 0
    n = len(texto)
    while i < n:
        if texto[i] == "\\" and i + 1 < n:
            siguiente = texto[i + 1]
            if siguiente.isdigit() or siguiente == "g":
                return True
            i += 2
            continue
        i += 1
    return False


def _riesgo_anidado(cuerpo: str) -> tuple[str, str] | None:
    """(nivel, motivo) del riesgo por cuantificador anidado, o None.

    La diferencia entre exponencial y cuadratico esta en lo que viene
    DESPUES del cuantificador interior:

    - si no viene nada obligatorio (`(a+)+`), el motor puede partir el texto
      de infinitas formas: exponencial;
    - si viene un separador que el interior no puede casar
      (`(?:\\w+\\.)+`), las repeticiones quedan delimitadas: solo cuadratico.
    """
    items = _items(cuerpo)
    for i, (atomo, cuantificador) in enumerate(items):
        if cuantificador is None or not _sin_cota(cuantificador):
            continue
        siguiente = items[i + 1] if i + 1 < len(items) else None
        if siguiente is None or siguiente[1] is not None:
            # Nada obligatorio despues (o algo opcional): la ambiguedad es
            # total.
            return (
                NIVEL_EXPONENCIAL,
                f"el grupo ({cuerpo}) se repite y su contenido ({atomo}"
                f"{cuantificador}) no va seguido de nada obligatorio",
            )
        if not _se_solapan(_categorias(atomo), _categorias(siguiente[0])):
            # Hay separador y no se solapa: el coste es cuadratico, no
            # exponencial.
            return (
                NIVEL_CUADRATICO,
                f"el grupo ({cuerpo}) se repite y su contenido ({atomo}"
                f"{cuantificador}) puede casar el mismo texto de varias formas "
                f"(coste cuadratico con entradas grandes)",
            )
        return (
            NIVEL_EXPONENCIAL,
            f"el grupo ({cuerpo}) se repite y su contenido ({atomo}"
            f"{cuantificador}) puede casar el mismo texto de varias formas",
        )
    return None


def analizar_redos(patron: str) -> tuple[str, str] | None:
    """`(nivel, motivo)` del riesgo de backtracking del patron, o None.

    `nivel` es `NIVEL_EXPONENCIAL` (cuelga con una entrada corta: se
    rechaza) o `NIVEL_CUADRATICO` (se degrada con el tamano: se avisa).
    """
    for cuerpo, cuantificador in _grupos_cuantificados(patron):
        if not _sin_cota(cuantificador):
            # El grupo repite un numero acotado de veces: no hay explosion.
            continue
        if "|" in cuerpo:
            alternativas = _alternativas(cuerpo)
            if len(alternativas) > 1 and _alternativas_solapadas(alternativas):
                return (
                    NIVEL_EXPONENCIAL,
                    f"alternativas solapadas: el grupo ({cuerpo}) se repite con "
                    f"'{cuantificador}' y sus alternativas se solapan",
                )
        if _tiene_referencia_atras(cuerpo):
            return (
                NIVEL_EXPONENCIAL,
                f"referencia atras: el grupo ({cuerpo}) se repite con "
                f"'{cuantificador}' y contiene una referencia atras",
            )
        anidado = _riesgo_anidado(cuerpo)
        if anidado is not None:
            return anidado

    # Una referencia atras repetida por fuera (`(\\w+)\\1+`) tambien es
    # catastrofica: el motor reintenta el grupo por cada forma de casarlo.
    for _i, (atomo, cuant_ref) in enumerate(_items(patron)):
        if atomo.startswith("\\") and len(atomo) > 1 and atomo[1].isdigit():
            if cuant_ref is not None and _sin_cota(cuant_ref):
                return (
                    NIVEL_EXPONENCIAL,
                    f"referencia atras repetida ({atomo}{cuant_ref}): el motor "
                    f"reintenta el grupo por cada forma de casarlo",
                )
    return None
