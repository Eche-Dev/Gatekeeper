# Briefing para una revisión de seguridad hecha por una IA

Material para pedirle a **otra IA** (Claude, GPT, cualquier otra) una revisión
de seguridad del middleware `gatekeeper-asgi`, en el mismo formato que se le
pide a una persona.

> **Aviso, para que nadie se engañe:** una IA **no ejecuta** el código. Su
> informe, por muy bueno que sea, es una lista de hipótesis. Este briefing
> existe para que las hipótesis lleguen **con un PoC ejecutable** y para que
> ese PoC lo ejecute alguien (o algo) contra el código real. Sin ese paso, el
> informe no es evidencia: es una opinión. Con él, es un informe revisado.

---

## 1. Qué hay que mirar

Todo el contexto está en este mismo paquete:

| fichero | para qué |
|---|---|
| `ALCANCE.md` | el alcance, las fronteras de confianza por orden de prioridad, los datos medidos y los límites conocidos |
| `PLANTILLA-SECURITY-REVIEW.md` | el formato exacto que tiene que tener el informe |
| `ESTADO.md` | la línea base medida (tests, cobertura, detección, FP). Lo que la IA mida y no cuadre es un hallazgo |
| `ejecutar_pocs.py` | 15 comprobaciones ejecutables sobre el código real |

El código: `gatekeeper-v0.3/gatekeeper/src/gatekeeper/` (10 módulos, ~1.300
líneas). La documentación: `gatekeeper-v0.3/gatekeeper/docs/`.

> **Si no tienes acceso a un disco local** (casi todos los chats de IA), esta
> ruta no te sirve de nada: `D:\ADEV\...` no existe para ti. Usa el material
> **desde GitHub**, que es público:
>
> - briefing: <https://github.com/Eche-Dev/Gatekeeper/blob/fase7-cobertura/.audit/PACK-REVISOR/BRIEFING-IA.md>
> - alcance: <https://github.com/Eche-Dev/Gatekeeper/blob/fase7-cobertura/.audit/PACK-REVISOR/ALCANCE.md>
> - plantilla: <https://github.com/Eche-Dev/Gatekeeper/blob/fase7-cobertura/.audit/PACK-REVISOR/PLANTILLA-SECURITY-REVIEW.md>
> - estado medido: <https://github.com/Eche-Dev/Gatekeeper/blob/fase7-cobertura/.audit/PACK-REVISOR/ESTADO.md>
> - código: <https://github.com/Eche-Dev/Gatekeeper/tree/fase7-cobertura/gatekeeper-v0.3/gatekeeper/src/gatekeeper>
>
> El repositorio es publico y se puede leer entero. Lo que **no** puedes es
> ejecutar: eso lo hace el propietario del repo, con tus PoC.

---

## 2. Tres formas de usarlo

**A. Con el repo delante (lo mejor: Claude Code u otra IA con acceso a ficheros
y a una terminal).** Se le da el briefing y puede leer el código, ejecutar los
PoC y medir. Es una revisión de verdad: la IA verifica sus propias hipótesis
contra el código real.

**B. Solo con el texto pegado (Claude en la web, ChatGPT, etc.).** Se le pega
el bloque del punto 3 y los ficheros que se pidan. La IA escribe el informe y
los PoC; **los PoC los ejecuta luego el propietario del repo** contra el
código real, y los que no se confirmen no entran en el informe publicado.

**C. Con una persona (un colega con perfil de seguridad).** El briefing no
sirve: para una persona, el `ALCANCE.md` y la plantilla ya son suficientes.

---

## 3. El briefing, listo para pegar

```
Eres revisor/a de seguridad independiente del middleware ASGI `gatekeeper-asgi`
(un WAF para FastAPI y Starlette). NO has desarrollado este código y NO has
ajustado ninguna de sus reglas de deteccion: eso es lo que hace valida la
revision, y hay que declararlo explicitamente en el informe.

Contexto: es un middleware que se pone DELANTE de la aplicacion. Recibe la
peticion, la inspecciona con reglas (SQLi, XSS, traversal, SSRF, SSTI, NoSQL,
Log4Shell, CRLF...) y bloquea lo que detecta. Su trabajo es una promesa: "esto
que el atacante manda, y que la documentacion dice que frena, no pasa".

Como leerlo: por FRONTERAS DE CONFIDENCIA, no "leyendo el codigo". Las cuatro
fronteras no confiables son: (1) el body (bytes del cliente), (2) la ruta y la
query string, (3) las cabeceras, (4) la configuracion (que si es del operador,
es de confianza). El punto donde mas veces se ha encontrado algo es (1): la
diferencia entre lo que el middleware inspecciona y lo que la APLICACION usa
de verdad. Ya se encontró un bypass ahí: en una query string el `+` es un
espacio, pero en un body es un caracter literal, y el middleware lo traducía
igual en los dos casos, asi que `sleep(10+6)` (operador de MySQL) llegaba
intacto a la aplicacion. La pregunta que hay que volver a responder, con
OTROS ejemplos: ¿hay algun otro texto que el middleware normalice de una forma
y la aplicacion use de otra?

Que se considera un HALLAZGO: algo que un atacante puede hacer con el
middleware puesto y que el middleware (o su documentacion) dice que frena, y
no frena. Con esto: (a) el PoC ejecutable, (b) el impacto MEDIDO (tiempo,
memoria, o el payload exacto que pasa), (c) que se rompe. Sin PoC ejecutable
es una hipotesis, y asi hay que etiquetarla.

Que NO se considera un hallazgo: "esta regla es fea", "esto seria mas rapido",
"yo lo haria distinto", o un limite que el proyecto YA tiene documentado
(estan en `docs/amenazas.md` y en el informe anterior). Si discrepas de un
limite documentado, eso es una OBSERVACION: hay que decir por que el limite
no es aceptable, no presentarlo como fallo nuevo.

Reglas que no se pueden romper:
1. No inventar numeros. Si no lo has medido, no pongas cifras: di "no medido"
   y explica como medirlo.
2. No propongas cambiar el codigo sin un PoC que demuestre el problema.
3. No reescribas ni "mejores" las reglas de deteccion: no has ajustado ninguna,
   y ajustar una regla para que case es exactamente lo que invalida una
   revision.
4. Si no encuentras nada, ESO es un resultado valido, pero tienes que decir
   QUE has mirado y por que lo das por bueno (la parte "lo que la revision
   tambien comprobo, y estaba bien" es la que da la medida de una revision).
5. Si algo no lo puedes comprobar, dilo como tal ("no verificable sin
   ejecutar"), en vez de callarlo.

Formato del informe: usa la plantilla `PLANTILLA-SECURITY-REVIEW.md` tal cual
(fecha, autor, commit revisado, conflicto de intereses, alcance, metodo,
resumen, hallazgos con PoC, limites conocidos aceptados/discutidos, lo que
comprobo y estaba bien, y trazabilidad).

Ademas del informe, escribe tus comprobaciones ejecutables en un fichero
`pocs_<tu_nombre>.py` (por ejemplo `pocs_chatgpt.py`, `pocs_gemini.py`,
`pocs_claude.py`), en el directorio del paquete, con esta forma:

    from gatekeeper import Config
    from gatekeeper.middleware import GatekeeperMiddleware
    # ... tus imports

    def poc_mi_caso(resultados: list[tuple[str, str, str]]) -> None:
        """Una frase: que verifica esta comprobacion."""
        # PASA = "pasa", FALLA = "falla" (importalos de este paquete si hace
        # falta; mira como lo hacen las comprobaciones que ya estan aqui).
        # anade una tupla a `resultados`: (veredicto, titulo, detalle)
        ...

    COMPROBACIONES = [
        ("micaso", poc_mi_caso, "una frase: que verifica"),
    ]

Cada comprobacion tiene que devolver un veredicto y un motivo, y no puede
tirar una excepcion: si lo hace, el paquete la marca como FALLA y el resto
sigue. Con eso, tus PoC se ejecutan contra el codigo real con el mismo
comando que las 15 comprobaciones del proyecto, y sus resultados son
verificables por cualquiera.

Un nombre de fichero propio, y **no toques el de otro revisor**: si hay varias
revisiones a la vez, cada una con su fichero, el ejecutor carga todos y sus
comprobaciones se ejecutan juntas (y se distinguen por el prefijo del
nombre del fichero).

(El cargador ya esta probado: si dejas el fichero con esa forma, tus
comprobaciones aparecen en `ejecutar_pocs.py --listar` y se ejecutan con
`python .audit/PACK-REVISOR/ejecutar_pocs.py <nombre>`.)

Si no puedes ejecutar nada, tu PoC tiene que ser un comando concreto de
shell o de Python, con lo que tiene que imprimir, para que el propietario lo
pueda ejecutar y confirmar.
```

---

## 4. El paso que hace que esto valga: la verificación

El informe que devuelve la IA **no se publica tal cual**. El ciclo es:

1. La IA escribe el informe y los PoC.
2. Los PoC se ejecutan contra el código real (en el repo, con
   `python .audit/PACK-REVISOR/ejecutar_pocs.py`, que ya carga `pocs_ia.py`).
3. Cada hallazgo pasa a una de estas dos cajas:
   - **CONFIRMADO**: el PoC se ejecuta y reproduce. Pasa al informe con su
     impacto medido.
   - **REFUTADO**: el PoC no reproduce, o el comportamiento es el correcto. No
     es un fallo del código: es una hipótesis falsa. Se documenta igual, con
     la explicación, porque "lo que se miró y no aguantaba" es información.
4. Solo al informe publicado le faltan los dos campos de "conflicto de
   intereses" y "autoría" rellenados de verdad.

---

## 5. Por qué una IA sí sirve aquí (y por qué no es lo mismo que una persona)

**Sí sirve**, porque el conflicto de intereses que invalidate la revisión es
concreto: quien ajustó una regla para tapar un bypass no puede certificar que
no queda ninguno. Una IA que no ha tocado el proyecto no tiene ese conflicto.
Y el valor de este proyecto no está en la intuición, sino en la **medición**:
el informe con PoC ejecutable y verificado es exactamente el formato que este
proyecto ha usado en todas sus fases.

**No es lo mismo**, y conviene decirlo en el propio informe:

- Una IA no puede seguir una pregunta: si algo no lo entiende, no va a
  preguntar, va a suponer. Por eso el informe tiene que declarar **qué NO se
  ha revisado** y por qué.
- Una IA tiende a reportar como hallazgo lo que ya está documentado como
  límite, porque no conoce el contexto. El `ALCANCE.md` existe para eso.
- Una IA no ejecuta, así que su informe sin verificación es una hipótesis con
  ropa de informe.
- La revisión humana sigue siendo el listón más alto. Si hay alguien
  disponible, lo ideal es **las dos**: la IA de revisor de amplio alcance
  (muchos archivos, muchas hipótesis) y la persona que verifica y decide.
