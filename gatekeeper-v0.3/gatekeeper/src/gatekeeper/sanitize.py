"""Saneado del texto no confiable que sale del proceso.

Dos salidas importan y las dos reciben texto que controla el atacante:

1. **El log de auditoria.** El `path`, el nombre del campo y el patron
   detectado vienen de la peticion. Un `\x1b[2J` en la URL llega al archivo
   de log tal cual, y de ahi a la terminal de quien lo mira.
2. **La salida del CLI** (`gatekeeper report`), que imprime lo que lee del
   log. El log puede venir de otra herramienta, con los controles sin
   escapar: en el formato JSON, `json.loads` decodifica `\\u001b` a un ESC
   real.

El saneado quita los caracteres de control (C0 y DEL) y el ESC. No se
limitan a lo que "puede" hacer una terminal: se quita todo lo que no es
texto imprimible, porque el texto imprimible es lo que el operador quiere
leer y lo que un SIEM puede indexar.

El ESC se marca como `\\e` (visible) en vez de borrarse: asi se ve que
habia algo ahi, que es informacion para quien lee el log.
"""
from __future__ import annotations

# Longitud maxima de un texto escrito en el log. El nombre de un campo lo
# elige el atacante: sin tope, un parametro de 100 KB metido en la URL
# produciria una linea de log de 100 KB.
MAX_LONGITUD_LOG = 256

# Caracteres de control: C0 (0x00-0x1F), DEL (0x7F) y los que dan color o
# mueven el cursor. Se quitan; el ESC se marca.
_TABLA_CONTROL: dict[int, str | None] = {
    codigo: None for codigo in range(0x20)
}
_TABLA_CONTROL[0x1B] = "\\e"  # ESC
_TABLA_CONTROL[0x7F] = None  # DEL
# Los tres "blancos" de control se convierten en espacio: si no, rompen la
# tabla del informe y la linea del log.
_TABLA_CONTROL[0x09] = " "  # tab
_TABLA_CONTROL[0x0A] = " "  # salto de linea
_TABLA_CONTROL[0x0D] = " "  # retorno de carro


def sanear(texto: str) -> str:
    """Quita los caracteres de control de un texto no confiable.

    No lanza nunca: si `texto` no es un `str`, se devuelve como estaba (la
    comprobacion de tipo la hace quien llama).
    """
    if not isinstance(texto, str):
        return texto
    return texto.translate(_TABLA_CONTROL)


def sanear_y_acotar(texto: str, maximo: int = MAX_LONGITUD_LOG) -> str:
    """Sanea el texto y lo acota, marcando el recorte.

    El recorte lleva `…` al final, para que se note que el texto estaba
    incompleto (y no que era asi).
    """
    limpio = sanear(texto)
    if maximo > 0 and len(limpio) > maximo:
        return limpio[:maximo - 1] + "…"
    return limpio
