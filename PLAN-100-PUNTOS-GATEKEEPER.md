# Hoja de ruta: llevar Gatekeeper a 100/100 de preparación

## Propósito y alcance

Esta hoja convierte la auditoría de preparación en tareas verificables para llevar
Gatekeeper a **20/20 en cada dimensión evaluada**. La puntuación mide calidad del
producto, facilidad de uso y evidencia disponible; **no significa protección
perfecta ni garantiza que una aplicación sea segura**.

Gatekeeper debe presentarse como una capa adicional para FastAPI/Starlette. No se
debe anunciar como sustituto de validación de entradas, consultas parametrizadas,
un WAF de borde ni un motor compatible con OWASP CRS.

La evaluación inicial se hizo sobre el merge del PR #18, commit
`e14bbd11e74ba0fdea6e1d49832b9a45e06f2748`. Antes de iniciar cada fase, actualizar
el checkout y confirmar el commit efectivo de `main`.

## Estado de continuación — 2026-10-23

**Hito integrado:** PR #20, [detección opt-in entre query y body](https://github.com/Eche-Dev/Gatekeeper/pull/20),
se integró en `main`. La opción `inspect_cross_carrier=True` está desactivada
por defecto, combina ruta/query con valores textuales inspeccionables del body,
respeta `exclude_fields` y mantiene las claves JSON y cabeceras fuera de la
combinación. CRS permanece integrado como corpus de benchmark; sus datos no se
eliminaron ni se usan como motor o dependencia de ejecución.

**Evidencia local de esa entrega:** 2066 tests pasaron con 96% de cobertura;
Ruff, mypy, Bandit, evaluación de corpus, validación de importación CRS y
`mkdocs build --strict` pasaron. El benchmark ahora entrega el body real al
middleware, pero sus latencias son medidas locales directas sobre ASGI, no un
SLA ni una medición de producción.

**Métricas regeneradas:** corpus propio 159/159 ataques y 0 falsos positivos no
documentados; corpus CRS 459/1135 (40,4%) y 11/232 negativos marcados (4,7%).
Estas cifras corresponden a escaneos individuales: todavía no miden el modo
cruzado. No describir 40,4% como porcentaje general de protección.

**Para retomar con OpenCode:** actualizar el checkout principal antes de tocar
código. El checkout donde se creó esta hoja estaba en `e14bbd1`, antes de la
integración de la PR #20; confirmar el nuevo `origin/main` y trabajar desde esa
base. No hay que volver a implementar el hito ya integrado.

## Prioridad inmediata

Las tareas inmediatas de la auditoría original ya se completaron en la PR #20:

- [x] **Conectar y probar el cruce entre query y body.** Integrado en el
  middleware como opción opt-in; pruebas verifican bloqueo, exclusiones, modo
  monitor y ausencia del payload en logs.
- [x] **Regenerar las métricas desde el evaluador** y sincronizar README,
  documentación e informe. La evaluación sigue siendo solo del modo individual.
- [x] **Corregir la documentación del límite del body.** 413 cuando el tamaño
  declarado o el stream leído exceden `max_body_size`; la falta de
  `Content-Length` por sí sola no causa rechazo.
- [x] **Registrar evidencia reproducible de validación.** Los comandos y
  resultados locales están en la descripción de la PR #20, que quedó integrada.

**Siguiente tarea recomendada:** crear una evaluación separada para
`inspect_cross_carrier=True`, con ataques divididos entre query/body y casos
benignos representativos. Publicar detecciones y falsos positivos con
denominadores explícitos; mantenerlos separados de las métricas actuales y no
cambiar el valor por defecto sin evidencia. Después, continuar con la guía rápida
copiable, configuración segura para proxy/Redis y ejecución de ejemplos en CI.
No subir las puntuaciones de auditoría hasta cumplir los criterios de evidencia
de cada dimensión.

## 1. Pruebas y calidad del código — 18/20 → 20/20

### Qué significa obtener 20/20

- La suite requerida por CI pasa en todas las versiones de Python soportadas.
- Los comportamientos de seguridad y los fallos operativos están cubiertos por
  pruebas de integración, no solo por pruebas unitarias de regex.
- Los cambios de reglas se evalúan contra casos de ataque y tráfico benigno, con
  umbrales explícitos para falsos positivos y regresiones.
- La instalación construida desde el paquete funciona en un entorno limpio.
- Hay una revisión de seguridad enfocada en límites de confianza, parsing,
  almacenamiento distribuido y manejo del body antes de una versión estable.

### Trabajo

- [ ] Mantener Ruff, mypy, Bandit, cobertura y tests de corpus como checks
  obligatorios en CI.
- [ ] Añadir pruebas ASGI de extremo a extremo para query, path, headers, body,
  respuestas 403/413/429/503, `monitor_only` y cabeceras de seguridad.
- [ ] Probar body por streaming sin `Content-Length`, límite exacto, límite
  excedido, desconexión del cliente y tipos de contenido no inspeccionados.
- [ ] Probar rate limiting con concurrencia, múltiples workers usando Redis,
  caída/timeout de Redis y los modos fail-open y fail-closed.
- [ ] Añadir regresiones para IP directa, `X-Forwarded-For` confiable y no
  confiable, CIDR de proxies y cabeceras manipuladas desde clientes externos.
- [ ] Ejecutar pruebas de fuzzing y límites de tiempo/memoria para entradas
  grandes y patrones configurables. Documentar que las regex del usuario pueden
  tener riesgos distintos de las reglas integradas.
- [ ] Probar el artefacto wheel/sdist en un entorno virtual limpio y verificar
  instalación, importación, extras opcionales y metadatos.
- [ ] Añadir una revisión de seguridad independiente antes de declarar una
  versión estable; resolver o aceptar de forma explícita cada hallazgo.

### Evidencia de cierre

- CI verde para todos los runtimes soportados y publicación de artefactos
  verificada.
- Pruebas nuevas que cubren las rutas de integración y fallos enumerados arriba.
- Cobertura mínima del proyecto mantenida; no usar cobertura como único indicador
  de seguridad.
- Informe de revisión de seguridad con hallazgos resueltos o aceptados.

## 2. Facilidad de integración ASGI — 14/20 → 20/20

### Qué significa obtener 20/20

Un desarrollador puede instalar Gatekeeper, añadirlo a una aplicación, escoger
una configuración adecuada para su despliegue y verificar que está funcionando
sin tener que adivinar cómo confiar en proxies, configurar Redis o depurar
bloqueos.

### Trabajo

- [ ] Publicar e instalar la versión desde PyPI, una vez comprobados nombre,
  disponibilidad, metadatos, wheel y sdist.
- [ ] Mantener ejemplos mínimos y probados para FastAPI y Starlette, incluyendo
  instalación, middleware, reglas propias, modo monitor y Redis.
- [ ] Añadir una guía rápida copiable que valide una petición permitida y una
  bloqueada localmente.
- [ ] Documentar ejemplos de despliegue de un proceso, varios workers, Docker y
  proxy inverso; explicar qué valores cambian según el entorno.
- [ ] Explicar con claridad cómo configurar IP del cliente y proxies confiables.
  No recomendar confiar en `X-Forwarded-For` sin limitar quién puede enviarlo.
- [ ] Proporcionar configuraciones de ejemplo conservadora y distribuida, sin
  ocultar las diferencias entre rate limit en memoria y Redis.
- [ ] Documentar códigos de respuesta, eventos de log, límites de inspección y
  cómo diagnosticar falsos positivos.
- [ ] Mantener compatibilidad comprobada con versiones soportadas de Python,
  FastAPI y Starlette; documentar la matriz probada.
- [ ] Definir política de compatibilidad de API y versionado semántico.

### Evidencia de cierre

- Todos los ejemplos de documentación se ejecutan en CI.
- Una persona nueva puede seguir la guía rápida desde un entorno limpio.
- Matriz de versiones publicada y validada por pruebas.
- Sin parámetros críticos de proxy o Redis cuyo riesgo quede implícito.

## 3. Cobertura de detección demostrada — 7/20 → 20/20

### Qué significa obtener 20/20

No significa detectar el 100% de ataques posibles ni alcanzar un porcentaje
arbitrario de OWASP CRS. Significa que el alcance está definido, las métricas son
reproducibles, los límites se reconocen y hay evidencia de comportamiento en los
tipos de entrada realmente inspeccionados.

### Trabajo

- [x] Mantener corpus propio con procedencia, etiquetas, ejemplos benignos y
  explicación de falsos positivos y negativos aceptados.
- [ ] Separar corpus de desarrollo y corpus de evaluación retenido para reducir
  el riesgo de ajustar reglas solo a los mismos ejemplos que luego se publican
  como evidencia.
- [ ] Publicar métricas por familia: precisión/recall o, cuando los datos no
  permitan estimarlos con rigor, conteos, denominadores y límites claros.
- [x] Publicar el alcance exacto CRS: familias incluidas, exclusiones, negativos,
  falsos positivos y commit de origen. No comparar ese porcentaje con la
  cobertura de un WAF completo.
- [x] Asegurar que las métricas publicadas del modo individual se regeneran
  desde el evaluador y coinciden en README, documentación e informe. El modo
  cruzado aún no tiene evaluación propia y no se incluye en esas cifras.
- [ ] Añadir casos reales anonimizados, recopilados con autorización, para
  observar falsos positivos en modo monitor antes de activar bloqueos.
- [ ] Probar entradas de query, path, headers y body; incluir codificación,
  normalización, tipos de contenido y combinaciones entre campos cuando se
  anuncie detección combinada.
- [ ] Mantener el criterio de cero falsos positivos **no documentados** en el
  corpus propio. Informar por separado todos los falsos positivos documentados.
- [ ] Establecer umbrales de regresión por corpus, con justificación y proceso
  para actualizar el corpus sin ocultar deterioros.

### Evidencia de cierre

- Un comando genera el informe completo y produce resultados deterministas.
- Las cifras de todos los documentos coinciden con el informe generado.
- La detección combinada anunciada tiene una prueba que pasa a través del
  middleware real.
- Se informa de limitaciones y casos no detectados; no se formula una promesa de
  protección total ni se usa un único porcentaje como resumen de seguridad.

## 4. Operación y compatibilidad con despliegues — 8/20 → 20/20

### Qué significa obtener 20/20

El operador entiende qué sucede ante cada fallo, cómo se calcula la IP, qué
datos se procesan y registran, y cómo desplegar el middleware en una topología
real sin confiar accidentalmente en el cliente.

### Trabajo

- [ ] Documentar y probar el comportamiento de cada backend de rate limit,
  incluyendo reinicios, concurrencia, workers y indisponibilidad de Redis.
- [ ] Elegir y explicar el comportamiento recomendado ante fallo del backend:
  fail-open o fail-closed, según el riesgo de la aplicación.
- [ ] Aclarar la cadena de confianza de proxies, CIDR permitidos y comportamiento
  cuando el peer no es confiable.
- [ ] Verificar límites de memoria y consumo con cuerpos grandes, cuerpos
  fragmentados y entradas de gran volumen.
- [ ] Documentar qué tipos de body no se inspeccionan, incluidos multipart y
  contenido binario, y cuáles son las consecuencias.
- [ ] Confirmar que los logs nunca incluyen payloads sensibles y documentar qué
  metadatos sí se registran, retención y recomendaciones de acceso.
- [ ] Definir métricas/observabilidad de bloqueos, límites, errores de Redis,
  respuestas 413 y modo monitor, sin exponer datos sensibles.
- [ ] Probar la interacción con aplicaciones ASGI comunes y servidores de
  producción soportados; documentar topologías comprobadas.
- [ ] Proporcionar un procedimiento de despliegue gradual: monitor, revisión de
  alertas, ajuste y activación de bloqueo, con instrucciones de reversión.

### Evidencia de cierre

- Pruebas de integración y carga reproducibles para las topologías documentadas.
- Guía operativa con decisiones ante fallo, proxy, logs, límites y rollback.
- Sin afirmaciones de soporte para configuraciones que no se hayan probado.

## 5. Documentación y preparación de publicación — 8/20 → 20/20

### Qué significa obtener 20/20

El paquete tiene un canal oficial de instalación y actualización, documentación
consistente, un historial de cambios y una política clara de soporte y reporte
responsable de vulnerabilidades.

### Trabajo

- [ ] Sincronizar README, docs, informe del corpus, changelog, metadatos del
  paquete y notas de release.
- [ ] Verificar el nombre del proyecto, número de versión, licencia, URL,
  clasificadores de Python y extras publicados.
- [ ] Publicar en PyPI con un proceso de release reproducible y revisar el
  artefacto instalado desde PyPI en un entorno limpio.
- [ ] Etiquetar versiones y mantener notas de migración para cambios de API,
  configuración, reglas y defaults.
- [ ] Publicar una matriz explícita de compatibilidad y una lista de limitaciones
  conocidas.
- [ ] Revisar la guía de instalación y quickstart desde cero; comprobar comandos
  y enlaces.
- [ ] Mantener SECURITY.md con canal privado de reporte, alcance, tiempos de
  respuesta razonables y proceso de divulgación.
- [ ] Definir política de soporte: versiones mantenidas, compatibilidad y cómo
  reportar errores o falsos positivos.
- [ ] Retirar o identificar claramente scripts temporales, reportes de análisis
  puntuales y artefactos que puedan confundirse con una interfaz estable.

### Evidencia de cierre

- Release etiquetada e instalable desde el canal anunciado.
- Documentación coherente, enlaces revisados y ejemplos ejecutables.
- Proceso de seguridad y soporte visible para usuarios.

## Secuencia recomendada

1. **Confiabilidad inmediata — completada en PR #20:** conectar la detección
   query/body como opt-in, corregir el 413 documentado, regenerar las métricas y
   sincronizar la documentación. Falta medir el modo cruzado por separado.
2. **Medición del cruce:** crear un conjunto de evaluación separado para el modo
   opt-in, con ataques divididos y peticiones benignas; informar resultados sin
   mezclarlos con las métricas de escaneo individual.
3. **Producto utilizable:** publicar una guía rápida y configuración segura para
   proxy, Redis, modo monitor y producción.
4. **Confianza operacional:** agregar pruebas de integración, streaming, proxy,
   concurrencia y fallos de Redis.
5. **Evidencia de detección y release:** crear evaluación retenida, validar
   tráfico benigno autorizado y reportar límites; completar revisión de
   seguridad, paquete limpio, versión etiquetada, publicación y política de
   soporte.

## Regla para asignar la puntuación final

No subir una dimensión a 20/20 solo porque hay más tests, más reglas o más
documentación. Cada puntuación requiere cumplir sus criterios de cierre con
evidencia reproducible. Si una capacidad no existe o no se ha validado, se debe
marcar como pendiente y no presentarla como completa.
