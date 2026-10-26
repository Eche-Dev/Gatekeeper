# Gatekeeper --- Auditoría consolidada y plan para alcanzar la máxima madurez

**Proyecto:** Gatekeeper, middleware/WAF para aplicaciones ASGI\
**Repositorio:** https://github.com/Eche-Dev/Gatekeeper\
**Paquete:** https://pypi.org/project/gatekeeper-asgi/\
**Documentación:** https://eche-dev.github.io/Gatekeeper/\
**Objetivo de planificación:** corregir los hallazgos de Claude, ChatGPT
y Gemini, verificar cada cambio y preparar una versión robusta y
mantenible.

> **Importante sobre el alcance:** este documento consolida los
> hallazgos comunicados por las tres evaluaciones. No significa que
> todos hayan sido reproducidos independientemente. Antes de afirmar que
> un defecto existe o que está corregido, hay que comprobarlo contra el
> código y el artefacto exactos afectados. "100 %" es un objetivo de
> madurez y cobertura definido por criterios verificables; no puede
> garantizarse seguridad absoluta ni la detección de todos los ataques.

------------------------------------------------------------------------

## 1. Resumen ejecutivo de las tres evaluaciones

  ------------------------------------------------------------------------------------------
  Evaluación           Puntuación Enfoque         Hallazgos principales Limitación
                        informada descrito                              
  ------------- ----------------- --------------- --------------------- --------------------
  Claude                   74/100 Revisión de     Posible DoS en la     Los resultados y
                                  repositorio y   normalización SQL;    tiempos reportados
                                  pruebas de caja cobertura de          deben reproducirse
                                  negra, según su WebSockets y MIME;    con la versión
                                  informe         recursos del rate     exacta.
                                                  limiter; JSON         
                                                  duplicado/profundo;   
                                                  logs y CLI;           
                                                  documentación y       
                                                  empaquetado           

  ChatGPT                  75/100 Revisión de     Riesgos de recursos,  No ejecutó
                                  arquitectura,   reglas regex,         independientemente
                                  código          proxies/rate          todas las pruebas
                                  disponible,     limiting, versiones y dinámicas descritas
                                  corpus y        requisitos            por Claude.
                                  documentación   documentales          
                                                  inconsistentes        

  Gemini                   94/100 Valoración de   Riesgos de            La puntuación alta
                                  arquitectura,   CPU/memoria al leer   no demuestra por sí
                                  normalización y cuerpos, ReDoS y      misma preparación
                                  diseño          cabeceras de          para producción;
                                  defensivo       seguridad duplicadas  hacen falta pruebas
                                                                        reproducibles.
  ------------------------------------------------------------------------------------------

### Interpretación

-   Claude aporta los hallazgos de mayor urgencia, especialmente el
    posible DoS por normalización.
-   ChatGPT destaca la necesidad de comprobar los límites de seguridad y
    la coherencia del proyecto.
-   Gemini reconoce fortalezas arquitectónicas, pero también menciona
    riesgos de recursos y cabeceras.
-   Las puntuaciones no son directamente comparables porque no consta
    que las tres evaluaciones hayan usado la misma versión, metodología,
    entorno y criterios.

## 2. Fortalezas que conviene preservar

Según el material del proyecto revisado anteriormente, estas decisiones
parecen valiosas y deben volver a verificarse en la versión actual antes
de modificarlas:

-   Middleware ASGI orientado a Starlette/FastAPI.
-   Modo de observación (`monitor_only`) para desplegar sin bloquear
    tráfico inicialmente.
-   `trust_proxy` desactivado por defecto.
-   Rate limiting con Redis y operación Lua atómica, si sigue
    implementado así.
-   Reglas de detección y normalización para varias familias de ataques.
-   Corpus propio, conjunto retenido (*held-out*) y evaluación con OWASP
    CRS.
-   Documentación de amenazas, compatibilidad y despliegue.
-   Uso de CI, tipado estático y herramientas de calidad.

Las cifras de corpus citadas en evaluaciones anteriores ---159/159 en
corpus propio, 103/109 en held-out y 465/1135 en OWASP CRS--- son cifras
comunicadas por el proyecto o por la revisión, no una garantía general
de detección. Hay que volver a ejecutar los comandos y registrar
versión, entorno, falsos positivos y falsos negativos.

------------------------------------------------------------------------

## 3. Inventario consolidado de hallazgos

**Prioridades**

-   **P0 --- Crítica:** posible bloqueo del servicio, DoS o fallo que
    requiere investigación inmediata.
-   **P1 --- Alta:** límites de recursos, rutas sin protección o
    diferencias de interpretación que pueden afectar a la seguridad.
-   **P2 --- Media:** robustez operativa, falsos positivos/negativos y
    observabilidad.
-   **P3 --- Mantenimiento:** documentación, empaquetado, experiencia de
    desarrollo y publicación.

Estados iniciales sugeridos: `Pendiente de verificar`, `Reproducido`,
`Corregido`, `Regresión probada`, `Cerrado`. No marcar como corregido
sin evidencia.

### 3.1 Seguridad y disponibilidad

  --------------------------------------------------------------------------------------------------------------------------------
  ID             Prioridad      Hallazgo reportado                             Riesgo              Solución y criterio de cierre
  -------------- -------------- ---------------------------------------------- ------------------- -------------------------------
  SEC-01         P0             Posible complejidad cuadrática en la           CPU elevada y       Inspeccionar la versión
                                eliminación de comentarios SQL, atribuida a    bloqueo del bucle   afectada. Si se confirma,
                                `re.sub(r"/\*.*?\*/", ..., flags=re.DOTALL)`   de eventos ASGI     sustituir por escaneo lineal de
                                con comentarios sin cerrar                                         una pasada con `str.find()` o
                                                                                                   un parser acotado. Añadir
                                                                                                   pruebas de escalado con tamaños
                                                                                                   crecientes y límites de tiempo.
                                                                                                   Comparar resultados del corpus
                                                                                                   antes/después.

  SEC-02         P1             Los `scope` de WebSocket podrían pasar sin     WebSockets sin      Definir expresamente el
                                inspección si el middleware solo procesa HTTP  reglas o rate       alcance: implementar protección
                                                                               limiting            de
                                                                                                   handshake/conexiones/mensajes
                                                                                                   si está soportada o declarar y
                                                                                                   aplicar una exclusión segura.
                                                                                                   Añadir pruebas ASGI de HTTP y
                                                                                                   WebSocket. No afirmar que
                                                                                                   WebSockets están protegidos si
                                                                                                   no lo están.

  SEC-03         P1             `application/octet-stream` podría quedar       Diferencias entre   Definir política para tipos
                                excluido aunque la aplicación interprete el    la inspección del   conocidos, desconocidos y
                                cuerpo                                         middleware y el     binarios. No intentar
                                                                               parser de la        interpretar todo contenido
                                                                               aplicación          binario como JSON sin criterio.
                                                                                                   Añadir límites y pruebas de
                                                                                                   parser diferencial.

  SEC-04         P1             Lectura/acumulación de cuerpos grandes o       Agotamiento de      Aplicar el límite durante la
                                fragmentados; confianza excesiva en            memoria o CPU,      lectura de cada fragmento,
                                `Content-Length`                               especialmente con   incluso si no hay
                                                                               concurrencia        `Content-Length` o es falso.
                                                                                                   Limitar tamaño, tiempo,
                                                                                                   concurrencia y coste de
                                                                                                   inspección. Verificar
                                                                                                   cancelación y liberación de
                                                                                                   recursos.

  SEC-05         P1             `max_body_size` citado como 1 MiB puede ser    Latencia alta y     Hacer configurable el límite;
                                costoso para ciertos cuerpos y cargas          presión de          establecer un valor
                                concurrentes                                   memoria/CPU         predeterminado prudente según
                                                                                                   mediciones. Permitir límites
                                                                                                   por endpoint/tipo cuando sea
                                                                                                   viable. Documentar el cálculo
                                                                                                   aproximado de memoria por
                                                                                                   petición concurrente.

  SEC-06         P1             Rate limiter en memoria sin límite de claves,  Agotamiento de      Limitar entradas, añadir
                                con crecimiento de memoria reportado ante      memoria por         expiración/limpieza eficiente y
                                muchas IP distintas                            cardinalidad        definir comportamiento al
                                                                               elevada             llegar al máximo. Evaluar
                                                                                                   agrupación IPv6 por prefijo con
                                                                                                   cuidado, documentando
                                                                                                   implicaciones de equidad.

  SEC-07         P1             Claves JSON duplicadas pueden interpretarse de Bypass o detección  Detectar duplicados durante el
                                forma distinta por middleware y aplicación     incorrecta por      parseo y aplicar una política
                                                                               discrepancia de     documentada; preferiblemente
                                                                               parsers             rechazar cuando la aplicación
                                                                                                   pueda interpretar el mismo
                                                                                                   documento de forma ambigua.
                                                                                                   Probar la integración con
                                                                                                   parsers reales.

  SEC-08         P1             JSON muy profundo; se informó de atribución    Exclusiones         Corregir construcción del JSON
                                incorrecta de campos a partir de más de 64     incorrectas,        Pointer y escape de segmentos.
                                niveles                                        diagnósticos        Definir profundidad máxima y
                                                                               engañosos y falsos  comportamiento al excederla.
                                                                               positivos           Añadir pruebas para
                                                                                                   profundidad, `~`, `/`, arrays y
                                                                                                   exclusiones.

  SEC-09         P1/P2          `multipart/form-data` podría no                Carga de contenido  Si se soporta, inspeccionar
                                inspeccionarse; nombres de archivo/campos      no inspeccionado y  partes con límites de
                                pueden ser maliciosos                          rutas de archivo    tamaño/cantidad y validar
                                                                               inseguras en la     nombres. Si no se soporta,
                                                                               aplicación          documentar el alcance y aplicar
                                                                                                   una política explícita de
                                                                                                   exclusión/rechazo. El
                                                                                                   middleware no sustituye la
                                                                                                   validación del almacenamiento
                                                                                                   de archivos.

  SEC-10         P1             Configuración de proxy y cabeceras de IP de    Falsificación de IP Mantener `trust_proxy`
                                cliente                                        y evasión del rate  desactivado por defecto.
                                                                               limit si se confía  Aceptar cabeceras solo desde
                                                                               en cualquier        proxies confiables
                                                                               `X-Forwarded-For`   configurados; validar cadenas y
                                                                                                   documentar el despliegue.
                                                                                                   Añadir pruebas con proxy
                                                                                                   confiable y no confiable.

  SEC-11         P2             Posibles cabeceras de seguridad duplicadas     Comportamiento      Definir política por cabecera:
                                                                               distinto entre      conservar, sustituir o combinar
                                                                               servidores,         según corresponda. Añadir
                                                                               navegadores y       pruebas cuando la aplicación ya
                                                                               aplicación          emite las cabeceras.

  SEC-12         P2             Las regex de reglas personalizadas podrían     ReDoS si se aceptan Documentar que las reglas
                                tener coste no acotado                         patrones            personalizadas son confiables o
                                                                               arbitrarios         limitar longitud/estructura y
                                                                                                   usar un motor con garantías de
                                                                                                   complejidad si procede. No
                                                                                                   confiar en que todas las regex
                                                                                                   sean seguras por ser cortas.
                                                                                                   Añadir pruebas de rendimiento y
                                                                                                   advertencias en configuración.
  --------------------------------------------------------------------------------------------------------------------------------

### 3.2 Detección, normalización y calidad de las reglas

  ----------------------------------------------------------------------------------------
  ID             Prioridad      Hallazgo reportado  Solución         Pruebas requeridas
  -------------- -------------- ------------------- ---------------- ---------------------
  DET-01         P1             Falsos negativos en Revisar          Casos positivos por
                                variantes de SQL    normalización y  familia,
                                injection, como     reglas con       codificaciones,
                                ciertos             ejemplos reales, comentarios y
                                booleanos/cadenas   sin convertir el variaciones
                                vacías              WAF en una lista sintácticas;
                                                    ilimitada de     confirmar que la
                                                    firmas           aplicación interpreta
                                                                     igual el dato.

  DET-02         P1             Posibles evasiones  Usar parsers     IPv4/IPv6, formatos
                                de SSRF con         estándar de      admitidos,
                                representaciones    direcciones y    direcciones
                                alternativas de IP  validación       privadas/reservadas y
                                                    consistente; no  variantes del parser
                                                    comparar solo    objetivo.
                                                    cadenas          

  DET-03         P1             Variantes de        Normalizar de    Separadores, saltos
                                command injection   forma segura y   de línea,
                                con saltos de       ampliar reglas   codificaciones y
                                línea/separadores   basadas en       casos benignos
                                                    contexto         similares.

  DET-04         P2             Falsos positivos en Mejorar          Corpus benigno
                                prosa o ejemplos,   contexto,        etiquetado; tasa de
                                como `<script>`,    umbrales y       falsos positivos por
                                `1=1` o             exclusiones;     regla y tipo de
                                `sleep(8 hours)`    permitir         tráfico.
                                                    monitorización y 
                                                    ajuste por       
                                                    aplicación       

  DET-05         P2             Corpus con          Mantener corpus  Resultados
                                resultados          propio, held-out reproducibles,
                                elevados, pero      y OWASP CRS;     versión/hash del
                                cobertura no        añadir casos de  corpus, métricas de
                                universal           regresión y      precisión, recall,
                                                    publicar         FPR/FNR y límites
                                                    metodología      conocidos.

  DET-06         P2             Normalización de    Centralizar      Pruebas de doble
                                rutas,              normalización y  codificación,
                                codificaciones y    evitar           escapes, Unicode,
                                evasiones debe      normalizar de    comentarios y rutas;
                                mantenerse          forma distinta   asegurar que no se
                                consistente         en cada regla    produzcan
                                                                     discrepancias con la
                                                                     aplicación.
  ----------------------------------------------------------------------------------------

### 3.3 Logs, CLI y privacidad

  -------------------------------------------------------------------------------
  ID             Prioridad      Hallazgo       Solución            Criterio de
                                reportado                          cierre
  -------------- -------------- -------------- ------------------- --------------
  OPS-01         P1/P2          Campos         Escapar caracteres  Pruebas con
                                controlados    de control, truncar CR/LF, ANSI,
                                por el         campos, usar        BEL, Unicode
                                atacante       logging             de control,
                                ---ruta o      estructurado y      campos enormes
                                claves JSON--- evitar guardar      y secretos
                                podrían        payloads/secretos   ficticios.
                                aparecer sin                       
                                sanear en logs                     

  OPS-02         P2             La CLI de      Sanitizar salida de Una entrada
                                informes       terminal antes de   maliciosa no
                                podría         imprimir texto no   cambia
                                imprimir       confiable           colores, no
                                secuencias                         mueve el
                                ANSI/BEL                           cursor ni
                                presentes en                       genera pitidos
                                los logs                           inesperados.

  OPS-03         P2             Promesa        Definir lista       Verificar que
                                documental de  permitida de campos no se
                                no registrar   y política de       registran
                                payloads       privacidad          cuerpos,
                                podría no                          cookies,
                                cubrir todos                       tokens ni
                                los campos                         datos
                                                                   sensibles;
                                                                   documentar
                                                                   retención y
                                                                   redacción.
  -------------------------------------------------------------------------------

### 3.4 Documentación, versiones y distribución

  ------------------------------------------------------------------------------
  ID                Prioridad         Hallazgo reportado       Solución
  ----------------- ----------------- ------------------------ -----------------
  DOC-01            P2                README, `SECURITY.md`,   Definir fuente
                                      documentación y          única de versión
                                      metadatos podrían        y actualizar
                                      discrepar sobre versión  todas las
                                      activa/publicación en    referencias en el
                                      PyPI                     mismo cambio.

  DOC-02            P2                Requisitos de            Alinear
                                      Python/Starlette         requisitos con
                                      inconsistentes entre     matriz de CI y
                                      documentos y             dependencias
                                      `pyproject.toml`         realmente
                                                               soportadas.

  DOC-03            P2                Enlaces de               Comprobar los
                                      corpus/documentación en  enlaces
                                      el README de PyPI        renderizados
                                      podrían ser incorrectos  desde PyPI y
                                                               añadir
                                                               comprobación
                                                               automática de
                                                               enlaces.

  DOC-04            P3                Carpetas de versiones    Usar una
                                      antiguas en la raíz y    estructura
                                      estructura confusa       estable (`src/`,
                                                               `tests/`,
                                                               `docs/`,
                                                               `examples/`) y
                                                               etiquetas Git
                                                               para versiones
                                                               históricas.
                                                               Hacerlo en un
                                                               cambio separado
                                                               de las
                                                               correcciones de
                                                               seguridad.

  DOC-05            P3                Archivos                 Revisar contenido
                                      auxiliares/demo/corpus   de sdist y wheel;
                                      posiblemente incluidos   excluir
                                      en sdist sin necesidad   herramientas
                                                               privadas, demos y
                                                               archivos de
                                                               planificación
                                                               cuando no formen
                                                               parte del
                                                               paquete.

  DOC-06            P3                README largo y solo en   Mantener inicio
                                      español                  rápido conciso;
                                                               mover detalles a
                                                               documentación y
                                                               considerar
                                                               versión inglesa.

  DOC-07            P2                Cobertura desigual en    Añadir pruebas de
                                      módulos como             importación, API
                                      `__init__.py`, según el  pública,
                                      informe de Claude        configuración y
                                                               rutas poco
                                                               cubiertas. No
                                                               perseguir
                                                               porcentaje sin
                                                               valor de prueba.

  DOC-08            P2                Falta de una matriz de   Probar versiones
                                      compatibilidad probada   de Python y
                                                               frameworks
                                                               declaradas;
                                                               retirar soporte
                                                               que no se pueda
                                                               mantener.
  ------------------------------------------------------------------------------

------------------------------------------------------------------------

## 4. Plan de trabajo por fases

Las duraciones son estimaciones de planificación, no garantías. Se deben
ajustar al tamaño real del código, al entorno de pruebas y a la
reproducción de los hallazgos.

### Fase 0 --- Preparación y reproducción (1--3 días)

**Objetivo:** establecer una línea base fiable antes de modificar
código.

1.  Identificar exactamente qué commit corresponde a la versión
    publicada `0.4.0`.
2.  Descargar/inspeccionar el sdist y la wheel publicados; comparar con
    el repositorio.
3.  Crear una rama de trabajo y conservar el commit base.
4.  Ejecutar CI, pruebas, linter, tipado y corpus existentes; guardar
    resultados.
5.  Reproducir SEC-01 en un proceso aislado con timeout externo y
    tamaños de entrada crecientes.
6.  Convertir cada hallazgo de Claude en un caso mínimo reproducible.
7.  Registrar por hallazgo: versión, comando, entorno, resultado
    esperado/real y evidencia.
8.  No ejecutar pruebas de carga destructivas en sistemas de producción.

**Entregables:** inventario de hallazgos, versión exacta afectada, línea
base de pruebas y reproducciones mínimas.

**Criterio de salida:** los hallazgos críticos están reproducidos o
explícitamente clasificados como no reproducidos con evidencia.

### Fase 1 --- Corregir el posible DoS y los límites de recursos (prioridad P0/P1)

1.  Corregir `normalize()` si se confirma el algoritmo problemático.
2.  Asegurar complejidad lineal o acotada en la eliminación de
    comentarios SQL.
3.  Añadir pruebas de complejidad y límites de tiempo para entradas
    maliciosas.
4.  Aplicar límites al leer cuerpos fragmentados; no confiar
    exclusivamente en `Content-Length`.
5.  Definir el tratamiento de timeout, cancelación y errores de
    análisis.
6.  Revisar regex personalizadas y cuantificadores con riesgo de
    backtracking.
7.  Revisar concurrencia: un cuerpo limitado por petición puede seguir
    siendo costoso si hay muchas peticiones simultáneas.

**Criterio de salida:** el caso de DoS no se reproduce en la versión
corregida; los límites son efectivos; el corpus y la funcionalidad
normal siguen pasando.

### Fase 2 --- Cobertura de protocolos y formatos (P1)

1.  Decidir y documentar la cobertura real de HTTP y WebSocket.
2.  Añadir pruebas ASGI que comprueben el comportamiento de cada
    `scope`.
3.  Definir política para MIME conocido, desconocido y binario.
4.  Revisar multipart y límites de partes, campos y nombres de archivo.
5.  Detectar JSON con claves duplicadas.
6.  Corregir JSON Pointer y profundidad máxima.
7.  Verificar que la normalización del middleware coincide con la
    interpretación esperada de la aplicación.

**Criterio de salida:** no quedan formatos/protocolos con comportamiento
ambiguo; cada exclusión está documentada y cubierta por pruebas.

### Fase 3 --- Rate limiting, proxy y resistencia a abuso (P1)

1.  Limitar la cardinalidad del rate limiter en memoria.
2.  Implementar expiración y limpieza sin pausas prolongadas.
3.  Definir comportamiento cuando se alcanza la capacidad máxima.
4.  Revisar claves IPv4/IPv6 y posible agrupación por prefijo.
5.  Validar el uso de cabeceras de proxy solo desde proxies confiables.
6.  Probar Redis: atomicidad, expiración, errores de conexión y
    comportamiento de fallback.
7.  Definir si el fallo de Redis debe ser fail-open o fail-closed según
    el caso de uso; documentarlo como decisión de seguridad.

**Criterio de salida:** memoria acotada, política de fallo explícita y
pruebas con proxies confiables/no confiables y alta cardinalidad.

### Fase 4 --- Reglas, evasiones y falsos positivos (P1/P2)

1.  Crear una matriz de ataques por familia: SQLi, XSS, traversal, SSRF,
    command injection y otras familias soportadas.
2.  Añadir variantes de codificación, Unicode, comentarios, separadores
    y normalización.
3.  Añadir corpus benigno que represente tráfico real y documentación.
4.  Medir por regla falsos positivos y falsos negativos.
5.  Separar detección de política de bloqueo; usar modo monitor para
    despliegues iniciales.
6.  No anunciar "detección del 100 % de ataques" a partir de un corpus
    finito.
7.  Revisar las exclusiones para evitar que se conviertan en bypasses
    generales.

**Criterio de salida:** métricas publicadas y reproducibles, sin
regresiones críticas, con límites conocidos documentados.

### Fase 5 --- Logs, privacidad y cabeceras (P2)

1.  Sanitizar caracteres de control en logs y CLI.
2.  Truncar y normalizar campos controlados por el atacante.
3.  Evitar registrar cuerpos, cookies, tokens y secretos.
4.  Definir una política por cabecera de seguridad para evitar
    duplicados.
5.  Añadir pruebas de logs con entradas maliciosas.
6.  Documentar retención, datos recogidos y configuración segura.

**Criterio de salida:** entradas maliciosas no pueden manipular la
terminal; los logs respetan la política de privacidad y las cabeceras
tienen un comportamiento determinista.

### Fase 6 --- Documentación, empaquetado y release (P2/P3)

1.  Unificar versiones y requisitos de compatibilidad.
2.  Corregir enlaces de README, PyPI y documentación.
3.  Revisar `SECURITY.md`, política de reporte responsable y versiones
    soportadas.
4.  Limpiar estructura y archivos del paquete.
5.  Inspeccionar el contenido real de sdist y wheel.
6.  Añadir comprobación automática de enlaces y metadatos.
7.  Mantener README conciso y mover guías extensas a la documentación.
8.  Considerar traducción al inglés.
9.  Preparar changelog con cambios de seguridad y migración.

**Criterio de salida:** documentación consistente con el artefacto
publicado y paquete reproducible con solo los archivos previstos.

### Fase 7 --- Validación independiente y publicación

1.  Ejecutar CI en todas las versiones de Python/framework declaradas.
2.  Ejecutar pruebas unitarias, integración ASGI, Redis y corpus.
3.  Ejecutar análisis estático y de dependencias.
4.  Ejecutar pruebas de rendimiento y límites en un entorno controlado.
5.  Revisar el diff de seguridad por otra persona o IA que no haya
    escrito el parche.
6.  Generar sdist y wheel desde un tag limpio.
7.  Instalar el artefacto en un entorno virtual limpio y repetir las
    pruebas.
8.  Publicar una versión correctiva solo tras completar los criterios de
    salida.
9.  Si se confirma una vulnerabilidad explotable en una versión
    publicada, valorar un aviso de seguridad coordinado y las
    instrucciones de actualización.
10. Mantener una lista de limitaciones conocidas.

**Criterio de salida:** artefacto exacto probado, resultados guardados,
revisión independiente y documentación de seguridad actualizada.

------------------------------------------------------------------------

## 5. Qué significa realmente llegar al "100 %"

No existe un 100 % universal de seguridad. Para que la meta sea útil,
define un **100 % de cumplimiento de una lista verificable de
criterios**, sin confundirlo con inmunidad frente a ataques
desconocidos.

### Matriz de aceptación propuesta

  -----------------------------------------------------------------------
  Área                                Meta verificable
  ----------------------------------- -----------------------------------
  Vulnerabilidades críticas           0 hallazgos P0 abiertos; todos los
                                      P1 corregidos o con riesgo residual
                                      formalmente aceptado.

  Complejidad/DoS                     No se reproducen casos de
                                      crecimiento desproporcionado;
                                      límites de CPU, tamaño y
                                      concurrencia documentados y
                                      probados.

  Recursos                            Lectura de cuerpos y rate limiter
                                      con límites efectivos; errores y
                                      cancelaciones liberan recursos.

  Protocolos                          HTTP y WebSocket cubiertos según
                                      alcance explícito; ningún protocolo
                                      se presenta como protegido sin
                                      pruebas.

  Formatos                            Política definida para JSON,
                                      formularios, multipart, binarios y
                                      tipos desconocidos.

  Parser diferencial                  Pruebas de JSON duplicado,
                                      profundidad, codificación y
                                      discrepancias relevantes con
                                      frameworks soportados.

  Detección                           Corpus versionado; resultados
                                      repetibles; falsos
                                      positivos/negativos medidos por
                                      familia.

  Pruebas                             100 % de los hallazgos conocidos
                                      tienen una prueba de regresión.
                                      Objetivo orientativo de cobertura
                                      de líneas ≥95 %, sin usarlo como
                                      sustituto de calidad.

  Compatibilidad                      Matriz CI completa para todas las
                                      versiones declaradas.

  Calidad                             Tipado, lint, dependencias y
                                      análisis estático pasan;
                                      excepciones justificadas y
                                      documentadas.

  Privacidad/logs                     Sin payloads ni secretos por
                                      defecto; caracteres de control
                                      sanitizados.

  Documentación                       Versiones, requisitos, alcance,
                                      limitaciones y política de
                                      seguridad consistentes.

  Empaquetado                         sdist/wheel instalados y probados
                                      desde un entorno limpio; contenido
                                      revisado.

  Seguridad independiente             Revisión final independiente de los
                                      cambios críticos; registro de
                                      riesgos residuales.

  Mantenimiento                       Política de versiones, avisos,
                                      respuesta a vulnerabilidades y
                                      proceso de release documentados.
  -----------------------------------------------------------------------

### Métricas que conviene publicar

-   Versión del código y hash del commit.
-   Versiones de Python, sistema operativo y dependencias.
-   Comandos exactos para repetir las pruebas.
-   Tiempo y memoria máximos medidos.
-   Tamaños y patrones de entrada usados en pruebas de rendimiento.
-   True positives, false positives, false negatives y corpus de
    referencia.
-   Casos excluidos y limitaciones conocidas.
-   Resultados de CI y análisis de dependencias.

No publiques un porcentaje de detección como si representara todos los
ataques de producción. Especifica siempre el conjunto de pruebas sobre
el que se calculó.

------------------------------------------------------------------------

## 6. Organización sugerida para trabajar con OpenCode

Trabaja **una fase por vez**. No le pidas a un agente que modifique todo
el repositorio en una sola operación.

Para cada fase, pídele que:

1.  Lea el código y la documentación antes de editar.
2.  Enumere los archivos que pretende cambiar y explique por qué.
3.  Reproduzca primero el fallo con una prueba que falle en la versión
    base.
4.  Implemente el cambio mínimo y justifique cualquier alternativa.
5.  Añada una prueba de regresión automatizada.
6.  Ejecute las pruebas relacionadas, el conjunto completo y el corpus.
7.  Muestre los comandos ejecutados y sus resultados reales; no invente
    resultados.
8.  Revise posibles regresiones, compatibilidad, rendimiento y
    seguridad.
9.  Actualice documentación y changelog cuando corresponda.
10. Se detenga al finalizar la fase y espere revisión antes de
    continuar.

### Plantilla de instrucción para cada fase

``` text
Trabaja exclusivamente en la Fase [N] de la auditoría de Gatekeeper.

Antes de editar:
- Identifica el commit y la versión del proyecto.
- Lee los archivos afectados y las pruebas existentes.
- Explica el fallo, el impacto y cómo reproducirlo.
- Enumera los archivos que propones modificar.

Durante el trabajo:
- Crea primero una prueba de regresión que falle en la versión base.
- Implementa el cambio mínimo, seguro y mantenible.
- No desactives pruebas ni rebajes aserciones para conseguir que pasen.
- No cambies métricas del corpus ni elimines casos difíciles para mejorar resultados.
- Conserva compatibilidad salvo que exista una razón documentada para romperla.
- No declares protegidos protocolos o formatos que no estén realmente cubiertos.

Al terminar:
- Ejecuta las pruebas específicas y la suite completa.
- Ejecuta lint, tipado y corpus cuando estén disponibles.
- Informa de los comandos exactos, resultados, tiempos y fallos.
- Muestra un resumen del diff y los riesgos residuales.
- Comprueba documentación y changelog.
- No empieces la siguiente fase sin mi aprobación.

Si no puedes ejecutar una prueba, indícalo claramente. Nunca afirmes que una prueba pasó si no se ejecutó.
```

------------------------------------------------------------------------

## 7. Orden final de prioridades

1.  **P0:** reproducir y resolver el posible DoS de la normalización
    SQL.
2.  **P1:** límites de lectura y concurrencia; cobertura HTTP/WebSocket;
    MIME/multipart; rate limiter; JSON duplicado y profundo; proxy.
3.  **P2:** calidad de detección, falsos positivos/negativos, logs, CLI
    y cabeceras.
4.  **P2/P3:** documentación, compatibilidad, empaquetado y estructura.
5.  **Validación final:** CI completa, pruebas de regresión,
    rendimiento, revisión independiente y publicación controlada.

### Resultado esperado

El objetivo realista es llevar Gatekeeper a un estado en el que sus
riesgos conocidos estén corregidos o explícitamente aceptados, sus
límites de recursos sean verificables, sus detecciones se evalúen con
corpus reproducibles y sus publicaciones sean auditables. Eso permite
aspirar a una evaluación excelente y una herramienta más fiable;
**ninguna puntuación, porcentaje de cobertura ni conjunto finito de
pruebas puede certificar seguridad absoluta**.
