# Auditoría QA y seguridad de Gatekeeper

He empezado por el repositorio, la implementación del middleware, la configuración, las reglas de detección, la política de seguridad y los informes de pruebas. Voy a evaluarlo como lo haría en una revisión técnica de un proyecto open source de ciberseguridad: no basta con que la aplicación funcione o con que detecte los ejemplos que se han preparado; tiene que resistir entradas hostiles, evitar bloquear tráfico legítimo y explicar claramente qué protección ofrece.

| Recurso | Enlace |
| :--- | :--- |
| **Repositorio** | `Eche-Dev/Gatekeeper` |
| **Documentación** | Gatekeeper Docs |
| **Paquete** | `gatekeeper-asgi` en PyPI |

---

## 1. Mi primera valoración

**Puntuación provisional de la revisión técnica: `82/100`**

> 🏷️ *Proyecto open source en evolución*

### Mi veredicto

Una base de ingeniería prometedora, con buenas prácticas de evaluación y una limitación importante: todavía no hay evidencia suficiente para considerar demostrada su eficacia como defensa de seguridad en producción.

| Aspecto | Valoración |
| :--- | :--- |
| ✅ **Lo mejor** | La transparencia al publicar resultados, el corpus retenido, la atención al rendimiento, el rate limiting con Redis y la documentación de los límites de seguridad. |
| ⚠️ **Lo que más me preocupa** | La diferencia entre detectar patrones sospechosos y bloquear ataques reales, la validación independiente pendiente y la coherencia entre versiones, instalación y documentación publicada. |

> **Nota de alcance**
> Esta puntuación es una valoración preliminar basada en los archivos que he podido examinar, no el resultado de ejecutar una auditoría dinámica completa contra el paquete instalado. No he realizado pruebas de penetración contra una instalación desplegada. Más adelante te separo lo que he comprobado en el código de lo que todavía necesita verificación.

---

## 2. Qué has hecho bien: hay ingeniería detrás del proyecto

No voy a juzgar Gatekeeper únicamente por la cantidad de funcionalidades. En seguridad, lo importante es cómo se comporta cuando alguien intenta romperlo.

### Aciertos técnicos que he encontrado

**1. Has separado detección y prevención de forma razonable.**

La configuración permite activar `monitor_only=True`, que registra detecciones sin bloquear peticiones. Es útil para observar tráfico legítimo antes de aplicar reglas de bloqueo. Buen criterio operativo.

**2. Has previsto el rate limiting distribuido.**

El backend Redis utiliza un script Lua para actualizar el contador de forma atómica. Esto es importante cuando hay varios workers: un contador exclusivamente en memoria no proporciona un límite global. Buena decisión arquitectónica.

**3. Has tenido en cuenta el spoofing de IP.**

`trust_proxy` está desactivado por defecto. La configuración contempla redes de proxies de confianza y la extracción de la IP desde `X-Forwarded-For`. Es una decisión importante porque confiar ciegamente en esa cabecera permite manipular los límites por IP.

**4. Has investigado problemas reales de agotamiento de recursos.**

Tu informe de revisión de seguridad documenta un DoS de memoria causado por la construcción de punteros JSON profundos. El informe describe mediciones antes y después de corregirlo, además de pruebas de regresión.

**5. No escondes los resultados que salen mal.**

Tu informe del corpus de detección publica tanto los resultados propios como los de OWASP Core Rule Set. También documenta falsos positivos y falsos negativos. Esto es mucho más útil para evaluar una herramienta de seguridad que presentar solamente una cifra de éxito.

**6. La base del proyecto está organizada como un paquete Python real.**

He revisado el `pyproject.toml`: utiliza Hatchling, define las dependencias opcionales de YAML y Redis, incorpora herramientas de desarrollo y configura `mypy` en modo estricto. Son decisiones apropiadas para una biblioteca que otros desarrolladores van a instalar.

### Lo más destacable: tu corpus retenido

Según los informes que has publicado:

| Corpus | Resultado | Nota |
| :--- | :--- | :--- |
| **Corpus propio** | `159/159` | Ataques detectados |
| **Corpus retenido** | `103/109` | 94,5 % de detección |
| **OWASP CRS** | `465/1.135` | 41,0 % en el alcance evaluado |

> **Fuente:** los informes del repositorio. Son resultados declarados por el proyecto, no resultados que yo haya reproducido independientemente en esta revisión.

La separación entre corpus de desarrollo y corpus retenido es una de tus mejores decisiones. El primero ayuda a desarrollar las reglas; el segundo permite medir si funcionan con casos que no se usaron para escribirlas.

> **Importante**
> El 100 % del corpus propio no significa que Gatekeeper detecte todos los ataques reales. Y el 41 % del corpus externo no es directamente comparable con el rendimiento de un WAF completo: se ha evaluado un alcance específico de reglas y casos. Sin embargo, publicar ambos resultados hace que la evaluación sea más honesta.

---

## 3. Revisión de seguridad del código

He inspeccionado partes de `middleware.py`, `config.py`, `rules.py` y `SECURITY_REVIEW.md`. Estos son los aspectos que priorizaría como auditor.

> **Clasificación**
> Los problemas de documentación que he observado directamente están diferenciados de los riesgos técnicos que requieren pruebas adicionales.

### Hallazgo 1 — Las expresiones regulares no deben ser tu única defensa

**🔴 Prioridad alta**

La detección integrada de Gatekeeper se apoya en expresiones regulares aplicadas a texto normalizado y decodificado. Esto es útil para reconocer patrones conocidos, pero no equivale a interpretar de manera completa el contexto en el que una entrada se ejecutará.

Por ejemplo, una cadena sospechosa puede ser:

- Una inyección SQL dirigida a una consulta construida de forma insegura.
- Un ejemplo educativo en una página de documentación.
- Un valor que la aplicación almacena como texto y nunca ejecuta.

El middleware puede observar texto similar en los tres casos, pero el riesgo real es diferente.

**Qué mejoraría:**

- Mantener las reglas como capa adicional de detección, no como sustituto de consultas parametrizadas, validación, autorización o escape contextual.
- Evaluar los resultados en aplicaciones de prueba que reproduzcan diferentes comportamientos de backend.
- Incorporar reglas específicas por contexto cuando exista evidencia suficiente y sin generar complejidad innecesaria.
- Medir los falsos positivos sobre tráfico real anonimizado y autorizado, además de corpus sintéticos.

Tu propia documentación reconoce esta limitación. Mi recomendación es mantener esa honestidad y convertirla en una parte central de la propuesta del producto.

### Hallazgo 2 — Las reglas personalizadas pueden introducir ReDoS

**🟠 Riesgo documentado**

Tu informe de seguridad reconoce que `custom_rules` permite expresiones regulares arbitrarias, sin un límite de tiempo o de pasos de ejecución.

Una expresión mal diseñada puede consumir una cantidad desproporcionada de CPU cuando se aplica a una entrada cuidadosamente construida. Esto se conoce como *Regular Expression Denial of Service* (ReDoS).

Aunque la responsabilidad de una regla personalizada recaiga en el operador, una herramienta de seguridad profesional debería reducir el riesgo de una configuración peligrosa.

**Mejoras recomendadas, por orden:**

1. Documentar claramente que las reglas personalizadas se ejecutan sobre entradas no confiables.
2. Rechazar patrones con estructuras de alto riesgo cuando sea posible hacerlo de forma fiable.
3. Evaluar una biblioteca de regex con garantías de tiempo de ejecución acotado, comprobando su compatibilidad con los patrones existentes.
4. Si se necesita compatibilidad completa con el motor `re`, considerar la ejecución aislada y límites de recursos; un simple timeout alrededor de una operación síncrona no garantiza que se pueda interrumpir con seguridad.

No eliminaría la funcionalidad de reglas propias, porque aporta valor. La protegería mejor.

### Hallazgo 3 — El tamaño del cuerpo HTTP no es suficiente para limitar el coste

**🔴 Prioridad alta**

`Config` establece un límite predeterminado de `max_body_size=1_048_576`, y el middleware inspecciona cuerpos de solicitudes. Esto es una buena primera barrera, pero un límite de bytes no limita por sí solo el coste de procesar una estructura compleja.

El informe de seguridad documenta precisamente un caso de agotamiento de memoria por JSON profundamente anidado, corregido mediante límites en los punteros JSON.

Eso demuestra algo importante: **un cuerpo pequeño puede tener un coste de procesamiento grande.**

Yo añadiría pruebas de límites independientes para:

- Profundidad de anidamiento JSON.
- Número total de nodos y campos.
- Longitud máxima de claves y valores.
- Tiempo máximo de inspección por solicitud.
- Varias solicitudes complejas en paralelo.
- Cuerpos incompletos, desconexiones del cliente y cancelación de tareas.

> No doy por hecho que estos límites falten todos en la versión actual; son los puntos que verificaría en la implementación y en sus pruebas antes de recomendar un despliegue de producción.

### Hallazgo 4 — El rate limiting debe comprobarse en toda la cadena de confianza

El tratamiento de `X-Forwarded-For` tiene comentarios y decisiones de diseño razonables. Sin embargo, el comportamiento correcto depende de cómo estén configurados realmente el proxy inverso, los CIDR de confianza y el número de saltos.

**Las pruebas que exigiría son:**

- Petición directa sin proxy.
- Cabecera falsificada enviada por un cliente.
- Uno y varios proxies de confianza.
- Cadena incompleta o malformada.
- Direcciones IPv4 e IPv6, incluidas direcciones IPv4 mapeadas en IPv6.
- Distintos clientes que intentan evadir el límite.
- Redis inaccesible, lento o reiniciado.

También probaría expresamente `rate_fail_open=True` y `False`. Permitir el tráfico cuando Redis falla favorece la disponibilidad, pero implica que el rate limit puede dejar de proteger durante una incidencia. Rechazar con `503` ofrece una política más estricta, a costa de la disponibilidad.

La decisión debe depender del riesgo de la aplicación y quedar clara en la configuración y en la documentación.

### Hallazgo 5 — El procesamiento del body y las exclusiones requieren pruebas de frontera

El código inspeccionado contempla query string, ruta, cabeceras y body, además de exclusiones por campo y un modo de inspección cruzada.

Es una cobertura funcional interesante, pero las exclusiones de seguridad son una zona especialmente delicada: una excepción demasiado amplia puede dejar fuera contenido que el operador creía protegido.

**Verificaría de forma sistemática:**

- Que `allow_paths` no permita eludir la inspección mediante rutas codificadas o normalizaciones diferentes.
- Que `exclude_fields` excluya exactamente el campo previsto, sin ocultar ataques presentes en otros campos.
- Que la reconstrucción de query strings conserve el comportamiento esperado con valores repetidos, caracteres especiales y parámetros vacíos.
- Que los encabezados duplicados o malformados no generen interpretaciones distintas entre el proxy y la aplicación.
- Que los formatos no inspeccionados, como `multipart/form-data`, estén identificados de forma visible como límites de cobertura.

La documentación ya declara algunas de estas limitaciones; el siguiente paso es asegurarse de que las pruebas las mantienen controladas.

---

## 4. Auditoría de la documentación: aquí sí he encontrado incoherencias importantes

He comparado el README principal, el README de la versión 0.3, `pyproject.toml`, `SECURITY.md`, la documentación de compatibilidad y la página de inicio de MkDocs.

Hay una cuestión que considero más urgente que corregir una frase o mejorar el diseño de la web: **la información sobre las versiones y la publicación no está completamente sincronizada.**

### Hallazgo 6 — El estado de publicación y las versiones se contradicen

**🔴 Prioridad crítica de publicación**

En los archivos que he consultado aparecen estas diferencias:

| Documento o archivo | Lo que indica |
| :--- | :--- |
| `README` principal | La versión activa es v0.3 y el paquete todavía no está publicado en PyPI. |
| `gatekeeper-v0.3/gatekeeper/pyproject.toml` | El nombre del paquete es `gatekeeper-asgi` y la versión declarada es `0.4.0`. |
| `gatekeeper-v0.3/gatekeeper/SECURITY.md` | Indica que todavía no hay publicación en PyPI. |
| `docs/compatibilidad.md` | Identifica la rama `0.4.x` como activa. |
| `docs/index.md` | Todavía menciona Python 3.10–3.13 y Starlette ≥ 0.37 en la sección de requisitos, mientras que `pyproject.toml` declara Starlette ≥ 0.23. |

Esto no demuestra por sí solo que el paquete publicado sea incorrecto. Sí demuestra que hace falta revisar qué versión corresponde a cada documento.

Además, la ruta `gatekeeper-v0.3/gatekeeper/` sigue siendo la ubicación física del código, aunque sus metadatos declaren la versión `0.4.0`. Eso puede ser válido durante una migración, pero dificulta entender qué código corresponde a cada release.

**Qué haría primero:**

1. Confirmar la versión publicada realmente en PyPI y compararla con la versión del repositorio.
2. Decidir cuál es la versión estable y cuál es la versión de desarrollo.
3. Actualizar el README principal, `SECURITY.md`, el sitio de documentación y las instrucciones de instalación.
4. Añadir una comprobación automática que impida publicar si las versiones y los enlaces de instalación no coinciden.
5. Comprobar que los ejemplos de instalación funcionan desde un entorno virtual limpio.

> No puedo confirmar en esta revisión la versión que actualmente sirve PyPI porque no he conseguido recuperar sus metadatos directamente. Por tanto, no voy a afirmar que exista una publicación defectuosa: la contradicción documental sí está identificada y merece resolverse.

### Hallazgo 7 — La documentación técnica está bien planteada, pero puede ser más útil para quien instala la biblioteca

Tu documentación tiene una fortaleza: explica los límites y las decisiones de diseño. No se limita a vender características.

Sin embargo, la información debería organizarse alrededor de lo que necesita hacer un desarrollador que llega por primera vez.

#### Mi valoración por área

| Documento | Nota | Comentario |
| :--- | :---: | :--- |
| **README principal** | `8/10` | Buena síntesis del propósito, las características y las limitaciones. El problema es la información de versiones y publicación. |
| **Documentación de seguridad** | `9/10` | Específica, honesta y con decisiones justificadas. La revisión propia está correctamente identificada como no independiente. |
| **Instalación y compatibilidad** | `6/10` | Tiene información útil sobre versiones y topologías, pero las discrepancias entre páginas pueden provocar instalaciones equivocadas. |
| **Informes de detección** | `8,5/10` | Los resultados negativos y los límites conocidos están documentados. Mejoraría la presentación de la metodología y los criterios de comparación. |

> Estas notas son valoraciones editoriales de los archivos examinados, no puntuaciones calculadas mediante una herramienta automática.

### Cómo mejoraría la redacción

El mensaje principal podría quedar más claro y uniforme en todo el proyecto. Por ejemplo, esta sería una propuesta para la introducción del README, sin cambiar las capacidades que afirmas tener:

```markdown
# Gatekeeper

Gatekeeper es un middleware ASGI de seguridad para aplicaciones FastAPI y Starlette.

Añade una capa de defensa en profundidad que combina limitación de solicitudes por IP,
cabeceras de seguridad HTTP, detección de patrones de ataque en las entradas y registro
de eventos de auditoría.

Incluye backends de rate limiting en memoria y Redis, reglas personalizadas y un modo de
monitorización que permite evaluar las detecciones antes de activar el bloqueo.

> **Alcance y limitaciones:** Gatekeeper no sustituye a un WAF completo, la validación de
> entradas, las consultas SQL parametrizadas ni los controles de autenticación y
> autorización. Su eficacia depende de la configuración, el tráfico y los patrones de
> ataque evaluados.

Consulta la guía de instalación, la matriz de compatibilidad y el modelo de amenazas antes
de desplegarlo en un entorno de producción.
```

La mejora principal no consiste en usar palabras más sofisticadas, sino en mantener la misma descripción del producto en GitHub, PyPI y la documentación.

---

## 5. Qué echo en falta para considerarlo un producto de seguridad profesional

Estas son las áreas que priorizaría para pasar de una biblioteca prometedora a una herramienta que otros desarrolladores puedan evaluar y desplegar con mayor confianza.

### A. Una revisión de seguridad independiente

Tu informe reconoce que el autor realizó la revisión. Eso es útil, pero no sustituye a una segunda revisión por alguien que no haya escrito el código ni ajustado las reglas.

El objetivo sería revisar los límites de confianza, los bypasses, los falsos positivos, la disponibilidad y las decisiones de configuración. No hace falta una certificación para empezar: una revisión reproducible y documentada ya aportaría mucho valor.

### B. Pruebas diferenciales contra aplicaciones reales de prueba

No basta con comprobar que una entrada maliciosa devuelve `403`. También hay que comprobar que una petición legítima sigue funcionando y que la aplicación no interpreta una entrada de forma diferente al middleware.

Crearía aplicaciones de prueba con distintas versiones de FastAPI y Starlette, configuraciones de proxy y comportamientos de parsing. Todas las pruebas serían locales y controladas.

### C. Benchmarks de rendimiento reproducibles

Publicaría latencia `p50`, `p95` y `p99`, solicitudes por segundo, uso de CPU y memoria, tanto con la inspección activada como desactivada.

Mediría también cargas grandes, reglas personalizadas, alta concurrencia y fallos de Redis. Un middleware de seguridad no debería convertirse en el principal vector de agotamiento de recursos de la aplicación.

### D. CI orientada a releases de seguridad

Además de los tests, incluiría verificaciones de dependencias vulnerables, builds reproducibles, comprobación de artefactos, compatibilidad del paquete instalado y validación de la documentación.

Los escáneres automáticos ayudan, pero sus resultados deben revisarse y no equivalen a una auditoría de seguridad.

### E. Un modelo de evaluación más amplio

Mantendría el corpus retenido congelado y añadiría nuevas evaluaciones versionadas. Para cada cambio de reglas, registraría qué detecciones se ganan, qué falsos positivos aparecen y cuánto aumenta el coste de ejecución.

Las métricas deben poder compararse entre releases sin cambiar silenciosamente el conjunto de pruebas.

---

## 6. Puntuación desglosada

Para que el `82/100` no sea una impresión sin fundamento, esta es la rúbrica que usaría para la siguiente fase de evaluación.

| Área | Nota provisional | Motivo principal |
| :--- | :---: | :--- |
| Arquitectura y diseño | `17/20` | Middleware modular, configuración y backend Redis |
| Pruebas y evaluación | `17/20` | Corpus propio y retenido, regresiones documentadas |
| Seguridad y resistencia | `15/25` | Buenas medidas, pero faltan validación independiente y más pruebas dinámicas |
| Documentación | `13/15` | Buen nivel técnico, con inconsistencias de versión |
| Mantenibilidad y calidad | `12/15` | Tipado estricto y herramientas de desarrollo |
| Distribución y releases | `8/5` | — |

La última fila revela que una rúbrica mal diseñada puede producir resultados incoherentes. Por eso no usaría esa tabla como puntuación definitiva.

Una ponderación corregida, con categorías que suman 100 puntos, sería:

| Área | Máximo | Evaluación |
| :--- | ---: | ---: |
| Arquitectura y diseño | 20 | 17 |
| Pruebas y evaluación | 20 | 17 |
| Seguridad y resistencia | 25 | 15 |
| Documentación | 15 | 13 |
| Mantenibilidad y calidad | 10 | 8 |
| Distribución y releases | 10 | 5 |
| **Total** | **100** | **75** |

Esta rúbrica sitúa la valoración en **75/100** si se aplican los criterios estrictamente. Mi estimación inicial de `82/100` fue más favorable; después de revisar las inconsistencias de publicación y la ausencia de una revisión independiente, considero más defendible utilizar `75/100` como nota provisional actual.

No significa que el código haya empeorado: significa que una evaluación más rigurosa debe penalizar la incertidumbre en un producto cuyo propósito es la seguridad.

---

## 7. Hoja de ruta recomendada para trabajar con OpenCode

No intentaría implementar todas las mejoras de golpe. Dividiría el trabajo en fases pequeñas, cada una con criterios de aceptación.

### Fase 1 — Coherencia del proyecto · *Primero*

Sin tocar las reglas de detección: verificar versiones, instalación, enlaces, requisitos de Python y Starlette, y documentación publicada.

> **Aceptación:** README, PyPI y documentación describen la misma versión y los mismos requisitos.

### Fase 2 — Auditoría del middleware

Revisar body parsing, normalización, exclusiones, cabeceras, límites de recursos, cancelaciones y errores.

> **Aceptación:** cada riesgo identificado tiene una prueba reproducible o una limitación explícitamente documentada.

### Fase 3 — Pruebas de resistencia y falsos positivos

Pruebas de carga, concurrencia, regresión, límites de parsing y comportamiento con tráfico legítimo.

> **Aceptación:** resultados medidos, umbrales definidos y regresiones bloqueadas por CI.

### Fase 4 — Release verificable

Construcción del paquete, instalación desde un entorno limpio, auditoría de dependencias, comprobación de versiones y publicación documentada.

> **Aceptación:** un usuario externo puede instalar la release, ejecutar el ejemplo y reproducir los tests indicados.

### Fase 5 — Revisión independiente

Una persona externa revisa el código y los resultados sin haber participado en el desarrollo de las reglas.

> **Aceptación:** informe de hallazgos, correcciones y riesgos residuales.

---

## 8. Mi conclusión

Gatekeeper tiene elementos que me parecen especialmente valiosos para un proyecto personal: un modelo de amenazas explícito, decisiones técnicas justificadas, un corpus retenido y voluntad de publicar resultados desfavorables. Eso demuestra una mentalidad de ingeniería de seguridad, no simplemente de desarrollo de funcionalidades.

Pero hay una diferencia entre un proyecto técnicamente prometedor y una herramienta cuya seguridad y eficacia están demostradas para producción. Para dar ese salto, necesitas coherencia en los releases, pruebas reproducibles más amplias, mediciones de rendimiento y una revisión independiente.

> **Mi recomendación:** no añadas más familias de detección todavía. Primero consolidaría lo que ya existe y haría que cada release fuese verificable por terceros.

El siguiente paso más útil sería revisar los archivos restantes del núcleo —especialmente `body.py`, `ratelimit.py`, `paths.py`, el resto de `middleware.py` y las pruebas correspondientes— línea por línea, para convertir esta evaluación preliminar en una auditoría de código más concluyente.
