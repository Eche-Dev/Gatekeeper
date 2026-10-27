# Revisión de seguridad — Gatekeeper [VERSIÓN]

> **Plantilla.** Cópiala a `gatekeeper-v0.3/gatekeeper/SECURITY_REVIEW.md` y
> llénala. Borra los corchetes `[...]` y las secciones que no apliquen.
>
> Si el informe anterior (el de la 0.3.1) quieres conservarlo, muévelo a
> `.audit/` y enlázalo desde aquí: es un registro histórico valioso.
>
> La plantilla sigue a mano el esquema del informe anterior
> (`SECURITY_REVIEW.md` de la 0.3.1), que ya está aceptado: fecha,
> alcance, método, resumen, hallazgos con PoC, límites y trazabilidad.

**Fecha:** [AAAA-MM-DD] · **Autor/a:** [nombre] · **Contacto:** [email o GitHub]
**Commit revisado:** [`<sha>`](https://github.com/Eche-Dev/Gatekeeper/commit/<sha>)
**Versión del paquete:** [gatekeeper-asgi X.Y.Z]

---

## Conflicto de intereses

[Declara cualquier relación con el proyecto. Si no has participado en su
desarrollo ni ajustado sus reglas, dilo explícitamente: eso es lo que hace
válida la revisión. Si has tenido alguna relación, dila también por qué no
invalida el informe.]

- [ ] No he participado en el desarrollo del código revisado.
- [ ] No he ajustado ni creado reglas de detección.
- [ ] [Si aplica: otra relación, y por qué no invalida la revisión.]

---

## Alcance

**Revisado:**

- `gatekeeper-v0.3/gatekeeper/src/gatekeeper/` — [módulos concretos]
- [Other: configuración, CLI, docs…]

**No revisado (y por qué):**

- [Ejemplo: el servidor ASGI, la red, el sistema operativo: no forman parte
  del paquete.]
- [Ejemplo: las reglas propias del usuario: son código del consumidor, no del
  paquete.]

**Superficie revisada** (las fronteras de confianza):

| Frontera | Entrada no confiable | Veredicto |
|---|---|---|
| Body | bytes del cliente | [OK / con hallazgos] |
| Ruta y query | del cliente | |
| Cabeceras | del cliente | |
| Configuración | el operador | |
| Log de auditoría | el propio middleware | |
| Rate limiter | el cliente (IP, XFF) | |
| CLI | ficheros de log | |

---

## Método

[Cómo se ha revisado. Lo que da valor a una revisión es el método, no la
voluntad. Opciones:]

- Lectura del código por **fronteras de confianza** (no "leyendo el código").
- [Pruebas de concepto ejecutables contra el código real: los PoC de
  `.audit/PACK-REVISOR/ejecutar_pocs.py` y los tuyos.]
- [Revisión de los regex: ReDoS, anclas, alcance.]
- [Comparación con el corpus y con CRS.]

**Herramientas:** [las que hayas usado, con versión]

**Qué NO se ha hecho:** [transparencia sobre los límites de tu propia revisión]

---

## Resumen

| | |
|---|---|
| Hallazgos **corregidos** | [n] |
| Hallazgos **pendientes** | [n] |
| Hallazgos **aceptados** (con documentación) | [n] |
| Limitaciones **conocidas** que confirmas | [n] |
| Limitaciones conocidas que **discutes** | [n] |
| Bypass **confirmado** (ejecutable) | [n] |

[Dos o tres frases: el veredicto en una línea. Ejemplo: "El middleware frena
los payloads que dice frenar; los dos límites que discuto son aceptables para
el uso declarado" o "He encontrado un bypass: ver H-2".]

---

## Hallazgos

> Un hallazgo es algo que un atacante puede hacer **con el middleware puesto**
> y que el middleware **dice** que frena (o que su documentación dice que
> frena), y no frena.
>
> Cada uno lleva: gravedad, PoC ejecutable, impacto y qué se rompe. Sin PoC,
> es una hipótesis.

### H-1 — [Título en una línea]

**Gravedad:** [alta / media / baja] · **Tipo:** [CWE-nnn] · **Vector:** [una frase]

**Qué pasa**

[La explicación técnica. Con el fragmento de código y el número de línea.]

**Impacto (medido)**

[Los números. Medidos, no estimados. Si es un DoS, la memoria y el tiempo;
si es un bypass, el payload y lo que consigue.]

**PoC**

```bash
[El comando exacto, ejecutable, y lo que tiene que imprimir]
```

**Qué se rompe**

[El efecto para el operador: qué deja de funcionar, qué se puede colar.]

**Corrección propuesta**

[Si la has escrito, el diff; si no, la dirección.]

**Estado:** [corregido en <sha> / pendiente / aceptado]

---

### [H-2, H-3…]

[Igual que el anterior. Si no hay hallazgos, borra la sección y pon:
"No se han encontrado hallazgos." — y eso es un resultado válido.]

---

## Limitaciones conocidas: ¿las aceptas?

Las del proyecto ya están documentadas (ver `docs/amenazas.md` y la revisión
anterior). Para cada una: **la aceptas**, **la discutes**, o **te parece
inaceptable**.

| límite | veredicto | por qué |
|---|---|---|
| `multipart/form-data` no se inspecciona | acepto / discuto / inaceptable | |
| Los cuerpos binarios no se inspeccionan | | |
| Las claves JSON no se unen en el modo combinado | | |
| El puntero JSON se recorta a 256 caracteres | | |
| Las reglas propias se validan al arrancar | | |
| NFKC expande hasta 4× | | |
| El rate limiter en memoria se multiplica por workers | | |
| `monitor_only` no es un plan de rollback | | |
| Una app que parsea el body de otra forma | | |
| [otra que hayas encontrado] | | |

---

## Lo que la revisión también comprobó (y estaba bien)

[Esto es lo que da la medida de una revisión: no solo lo que se rompió, sino
lo que se miró y aguantó. Escribe lo que verificaste de verdad.]

- [Ejemplo: "12 combinaciones de peer/XFF/proxy/CIDR dan el resultado
  correcto; un XFF malformado cae al peer."]
- [Ejemplo: "Las 4 reglas propias de semgrep no tienen falsos positivos: con
  el código bueno, 0 hallazgos."]
- [Ejemplo: "18 cuerpos adversarios (JSON anidado, UTF-8 inválido, bytes
  nulos, NaN/Infinity, JSON duplicado, BOM) producen respuestas normales,
  nunca un 500."]

---

## Trazabilidad

| Revisión | Fecha | Autor | Resultado |
|---|---|---|---|
| Original (PR #18) | 2026-10 | — | 4 bypasses del XFF, 3 reglas incompletas → corregidos en la 0.3.0 |
| Múltiples, durante la 0.3.x | 2026-10 | — | Redis < 6 en silencio, `Retry-After` +1, YAML inválido, FastAPI ausente, prefiltro en textos largos, falso positivo de blogs con fecha → corregidos |
| Revisión de la 0.3.1 | 2026-10-24 | [autor] | H-1 (DoS de punteros JSON), A-1 a A-4 aceptados |
| **[Esta revisión]** | **[fecha]** | **[autor]** | **[resultado]** |
