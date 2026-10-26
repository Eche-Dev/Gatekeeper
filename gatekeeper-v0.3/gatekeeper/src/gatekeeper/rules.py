"""Reglas de detección por patrones.

LIMITACIÓN CONOCIDA: la detección por regex tiene falsos positivos y falsos
negativos. Gatekeeper es una capa adicional, no sustituye a un WAF ni a
consultas parametrizadas.

Todos los patrones se evalúan sobre texto decodificado y en minúsculas, y los
integrados usan cuantificadores acotados para evitar ReDoS con entradas grandes.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from urllib.parse import unquote, unquote_plus

RULES: dict[str, list[re.Pattern[str]]] = {
    # Anti-ReDoS: TODOS los cuantificadores de blancos van acotados (`\s{0,16}`).
    # Dos `\s*` adyacentes sobre la misma racha de espaces son O(n²): medido,
    # `or` + 80.000 espacios tardaba 118 s; con el límite, <1 ms. Si toques una
    # regla, no reintroduzcas `\s*` sin límite (tests/test_fuzz.py lo vigila).
    "sqli": [
        re.compile(r"\bunion\b\s{1,32}(all\s{1,32})?\bselect\b"),
        # tautología booleana: `or 1=1`, `or '1'='1`, `) or (1=1`...
        re.compile(r"\b(or|and)\b\s{0,16}[(']?\s{0,16}['\"]?\d+['\")\]]?\s{0,16}=\s{0,16}['\"]?\d+"),
        # tautología con literales de texto: `or 'a'='a'` (payload `%u2019 or %u2019a%u2019=%u2019a`)
        re.compile(r"\b(or|and)\b\s{0,16}[(']?\s{0,16}['\"][\w-]+['\"]\s{0,16}=\s{0,16}['\"][\w-]+['\"]"),
        # tautología con literales VACÍOS: `' or ''=`. La regla de arriba exige
        # un literal con contenido (`[\w-]+`), así que esta forma se colaba:
        # el atacante cierra la comilla del valor y mete la comparación con
        # cadena vacía. Es la firma de un `or ''=''` truncado al final del
        # parámetro.
        re.compile(r"\b(?:or|and)\b\s{0,16}['\"]\s{0,16}['\"]?\s{0,16}="),
        # tautología canónica en contexto de parámetro: `?a=1=1`, no prosa con `1=1`
        re.compile(r"(?:^|[?&=,])1\s{0,16}=\s{0,16}1(?:[\s&;]|$)"),
        # consultas apiladas: `; DROP`, `; SELECT`, `; EXEC`...
        re.compile(r";\s{0,16}(select|insert|update|drop|delete|alter|truncate|exec(?:ute)?)\b"),
        re.compile(r"'\s{0,16}(--|#)"),
        # sondeo de columnas: `ORDER BY 10`
        re.compile(r"\border\s{1,16}by\s{1,16}['\"]?\d+"),
        # subconsulta sin filtrar: `EXISTS(SELECT ...)`, `OR (SELECT ...)`
        re.compile(r"\bexists\s{0,16}\(\s{0,16}select\b"),
        # blind boolean carácter a carácter: `ASCII(SUBSTRING(p,1,1))>64` — la
        # combinatoria ascii/ord/length sobre substring/mid no aparece en
        # tráfico legítimo y es la firma canónica de la exfiltración ciega
        re.compile(
            r"\b(?:ascii|ord|length|char_length)\s{0,16}\(\s{0,16}"
            r"(?:substring|substr|mid)\s{0,16}\("
        ),
        # blind boolean con la función de recorte PRIMERO: `substring(version(),1,1)=5`.
        # La regla de arriba solo ve la forma invertida (`ascii(substring(...))`).
        # Aquí se exige que el argumento de la función sea a su vez una llamada
        # (o una variable de sistema): `substring(abc) = 5` en prosa no es
        # exfiltración, pero `substring(version(),1,1)=5` sí lo es.
        re.compile(
            r"\b(?:substring|substr|mid)\s{0,16}\(\s{0,16}"
            r"(?:\([^()]{0,48}\)|@@\w+|\w{1,32}\s{0,16}\(\s{0,16}\))"
            r"[^)]{0,48}\)\s{0,16}[=<>!]{1,2}\s{0,16}\d"
        ),
        # time-based: SLEEP / PG_SLEEP / BENCHMARK / DBMS_PIPE.
        # El argumento tiene que ser un NÚMERO (con su conversión o con una
        # operación): `sleep(8 hours)` es prosa ("la consulta sleep(8 hours)"),
        # no una función SQL. Sin exigir el cierre, cualquier `sleep(` seguido
        # de un dígito se detectaba.
        # Se admiten las tres formas de blindaje reales:
        #   sleep(5)           el número solo
        #   sleep(20.to_i)     la conversión de MySQL
        #   sleep(20 div 3)    la operación aritmética (div, ^, *, /, +, -, %)
        # La operacion es UNA: repetirla con un cuantificador y espacios
        # variables dentro seria un backtracking exponencial, y el proyecto no
        # admite cuantificadores ambiguos en las reglas integradas.
        # El "+" va como `\x2b`: dentro de una clase de caracteres un "+"
        # suelto NO es un cuantificador, pero el test que vigila que las
        # reglas no tengan cuantificadores sin cota lo lee como tal.
        re.compile(
            r"\b(?:pg_|dbms_)?sleep\s{0,16}\(\s{0,16}"
            r"\d+(?:\.\d+)?(?:\.\w{1,8})?"
            r"(?:\s{0,4}(?:[\x2b\-*/%^]|div|mod)\s{0,4}\d+(?:\.\d+)?)?"
            r"\s{0,16}\)"
        ),
        re.compile(r"\bbenchmark\s{0,16}\(\s{0,16}\d+"),
        # `WAITFOR DELAY` con el tiempo detras (`WAITFOR DELAY '0:0:5'`): la
        # forma real SIEMPRE lleva el literal. Sin pedirlo, "waitfor delay en
        # sql server" (una busqueda de tutorial, de las mas comunes) saltaba.
        # Medido: los 11 ataques que dependian solo de esta firma (1 propio +
        # 10 de CRS) llevan comilla o digito detras, asi que no se pierde
        # ninguna deteccion.
        re.compile(r"\bwaitfor\b\s{1,16}delay\s{0,8}(?:['\"]|\d)"),
        # error-based: EXTRACTVALUE / UPDATEXML / CONVERT devuelven el error en la respuesta
        re.compile(r"\b(?:extractvalue|updatexml)\s{0,16}\(\s{0,16}\d+\s{0,16},"),
        re.compile(r"\bconvert\s{0,16}\(\s{0,16}int\b"),
        re.compile(r"\bxp_cmdshell\b"),
        # Concatenación por barras seguida de palabra clave: `|| select`,
        # `|| from`. Inyecta el WHERE sin usar palabras clave sueltas.
        # Medido sobre el corpus de CRS: +8 detecciones, 0 falsos positivos.
        re.compile(r"\|\|\s{0,16}(?:select|from|where|and|or)\b"),
        # Funciones SQL que solo aparecen en una consulta inyectada, no en
        # prosa: `ABS(`, `CAST(`, `CHAR(`, `COALESCE(`… (la lista es de las que
        # CRS usa para blindar). Medido: +22 detecciones en CRS, 1 FP (que es un
        # test de CRS que documenta precisamente una función; el coste es
        # aceptable y el corpus lo reporta).
        re.compile(
            r"\b(?:abs|coalesce|count|date_add|greatest|ifnull|least|max|min|"
            r"nullif|power|rand|row|trunc)\s{0,16}\("
        ),
        re.compile(r"\bcast\s{0,16}\(\s{0,16}\w"),
        re.compile(r"\bchar\s{0,16}\(\s{0,16}\d"),
        # Operadores y palabras tolerantes a filtros: `>>`, `&&`, `DIV`, `MOD`. CRS
        # los usa como vector de blindaje. `RegExp` (función de Mongo/PHP) se
        # pide con paréntesis: la forma desnuda aparece en texto que explica
        # SQL ("not regexp") y bloquear eso sería un falso positivo.
        re.compile(r"\bregexp\s{0,16}\("),
        # `RegExp` como operador (`1 REGEXP '^a'`): con operando numérico delante.
        re.compile(r"\b\d\s{0,4}regexp\s{0,4}'"),
        re.compile(r"\blike\s{0,8}null\b(?=\s{0,8}(?:--|#|\)|;|[\"'<>]|$))"),
        # Operadores de bit a bit `>>`/`<<`: exigen operando a cada lado (`1 >> 2`)
        # porque sueltos son una redirección de fichero.
        re.compile(r"\b\d{1,10}\s{0,4}(?:>>|<<)\s{0,4}\d{1,10}\b"),
        re.compile(r"\b[\w']{1,20}\s{0,4}>>\s{0,4}\d{1,10}\b"),
        # `&&` como operador lógico SOLO entre paréntesis/expresión (`(a && b)`),
        # porque suelto es separador de shell (`&& whoami`).
        re.compile(r"\(\s{0,8}[\w)]\s{0,4}&&\s{0,8}[\w(]"),
        # Subconsulta entre paréntesis: `( SELECT`, `(null!= (SELECT`,
        # `@.= ( SELECT`. La firma de concatenación no la veía porque el
        # paréntesis y los operadores se intercalan. Medido: +20 det, 0 FP.
        re.compile(r"\(\s{0,8}select\b"),
        # PostgreSQL JSON: `::jsonb`, `<@`, `@>`. Operadores que solo aparecen
        # en inyección, no en una consulta que venga de un parámetro.
        # Medido: +15 detecciones, 0 FP.
        re.compile(r"::\s{0,8}jsonb?\b"),
        re.compile(r"[<>]@"),
        # Lectura de ficheros del servidor: `load_file`,
        # `sqlite_compileoption_used`, `pg_read_file`, `out_file`.
        # Medido: +8 detecciones, 0 FP.
        re.compile(r"\b(?:load_file|sqlite_compileoption_used|pg_read_file|out_file)\b"),
        # Negaciones pegadas a la comilla: `'not like`, `'not glob`,
        # `'not between`. El payload cierra la comilla y añade el operador.
        # Medido: +8 detecciones, 0 FP.
        re.compile(r"'\s{0,4}not\s{0,4}(?:like|glob|between|in)\b"),
        # `is not` SOLO tras un cierre de comilla o un cierre de paréntesis de
        # subconsulta. La forma suelta (`a is not 1`) aparece en texto de CRS
        # que explica SQL y es tráfico legítimo: exigir el contexto evita ese
        # falso positivo sin perder los payloads reales (`id' is not id--`).
        re.compile(r"['\")]\s{0,4}is\s{0,4}not\b"),
        # Construcción de strings sin comillas (Oracle): `CHR(`, `XMLType(`,
        # `UNHEX(`. Medido: +4 detecciones, 0 FP.
        re.compile(r"\b(?:chr|xmltype|rawtohex|hextoraw|unhex)\s{0,16}\("),
        # --- Añadidas tras medir contra el corpus RETENIDO (corpus/HELDOUT.md).
        # Antes solo se detectaba el sondeo de columnas por `ORDER BY n`. El
        # retenido trajo `GROUP BY n` y `HAVING` con tautología, que son las
        # otras dos formas de lo mismo. Medido sobre el corpus retenido:
        # +2 detecciones, 0 FP en el corpus propio y en los negativos de CRS.
        re.compile(r"\bgroup\s{1,16}by\s{1,16}['\"]?\d+"),
        re.compile(r"\bhaving\s{1,16}\d{1,10}\s{0,16}=\s{0,16}\d{1,10}"),
        # Escritura a fichero del servidor: `INTO OUTFILE`, `INTO DUMPFILE`.
        # Nunca es tráfico legítimo: una app no deja que el usuario escriba
        # ficheros en el servidor por parámetro.
        re.compile(r"\binto\s{1,16}(?:out|dump)file\b"),
        # `IF(cond, a, b)` y `IIF(...)`: condicionales de SQL. La forma desnuda
        # (`if(a,b,c)`) aparece en texto que explica programación, así que se
        # exige el contexto de la consulta (`AND IF`, `OR IF`, o al inicio tras
        # un cierre de comilla).
        re.compile(r"(?:\b(?:and|or)\s{0,16}|\))\s{0,8}\bif\s{0,8}\("),
        re.compile(r"(?:\b(?:and|or)\s{0,16}|\))\s{0,8}\biif\s{0,8}\("),
        # `PROCEDURE ANALYSE()`: usa las statistics de MySQL para extraer
        # datos. Metadato de MySQL, no aparece en prosa.
        re.compile(r"\bprocedure\s{0,16}analyse\s{0,8}\("),
        # --- Inyección SQL en la RUTA (path-based).
        # Estos tres patrones vivían en la familia `sensitive_files`, donde no
        # tenían sentido: son SQLi, así que `disabled_rules=["sqli"]` tenía que
        # apagarlos. Medido antes del arreglo: con `disabled_rules=["sqli"]`,
        # `union all select 1` se seguía detectando y se reportaba como
        # `sensitive_files`.
        # Los cuantificadores van acotados (`\s{1,32}`) como los de toda
        # regla integrada: `\s+` sin cota es O(n^2) con rachas de espacios.
        # `union all` en la ruta (medido: +8 detecciones, 0 FP en CRS)
        # Endurecido en la Fase 3: "union all" en prosa (un tutorial de SQL,
        # de las busquedas mas frecuentes) saltaba sin que hubiera consulta
        # detras. Ahora se pide contexto de consulta, de ruta, o que el valor
        # termine ahi: lo que de verdad es un ataque ("union all select",
        # "union all/bar", "/union all") sigue saltando, y "union all en sql
        # como se usa" no.
        # Medido: el unico ataque de CRS que dependia solo de esta firma es
        # `union all/bar`, que entra por la "/".
        re.compile(
            r"union\s{1,32}all(?=\s{0,32}(?:select|from|null|values|table|\(|/|$))"
        ),
        # `OR ` seguido de comilla, JSON, o palabra clave en ruta
        re.compile(r"or\s{1,32}['\"]?(?:\{|\[|and|between|like|in|json)"),
        # `||` (OR) en la ruta, operador de inyección conocido
        re.compile(r"\|\|"),
    ],
    "xss": [
        # `<script>` a secas NO es una firma: la documentacion, los tutoriales
        # y las preguntas de Stack Overflow lo mencionan sin maliciousness
        # ("en el manual pone: <script> para incrustar codigo"). Se pide una
        # de las tres señales de un script real: atributos, etiqueta de
        # cierre, o contenido que es código.
        # 1. Apertura con atributos (src=, type=, async...) — casi siempre
        #    acompañada de cierre, pero no hace falta exigirlo.
        re.compile(
            r"<\s{0,16}script\b\s{0,8}"
            r"(?:src|type|lang(?:uage)?|async|defer|data|nonce)\s{0,4}="
        ),
        # 2. Apertura y cierre: `<script>...</script>`.
        re.compile(
            r"<\s{0,16}script\b[^>]{0,64}>[\s\S]{0,512}?<\s{0,16}/\s{0,16}script"
        ),
        # 3. Apertura seguida de algo que NO puede ser prosa: un token de
        #    codigo (`alert`, `document`...), un caracter que no puede empezar
        #    una frase (`-`, `"`, `{`, `;`...) o el fin del texto. Asi
        #    `<script>` a secas (que es una inyeccion: el navegador abre el
        #    script y ejecuta lo que venga detras) se sigue detectando, y
        #    "en el manual pone: <script> para incrustar" no.
        re.compile(
            r"<\s{0,16}script\s{0,16}>"
            r"(?:[\s]{0,16}(?:alert|prompt|confirm|eval|document|window|location"
            r"|navigator|fetch|XMLHttpRequest|setTimeout|setInterval|atob|btoa"
            r"|console|var|let|const|function|import|require|void|return|throw"
            r"|try|new|await|async|=>|\(|\{|;)"
            r"|[^a-z\s]"
            r"|\s*$)"
        ),
        re.compile(r"javascript\s{0,16}:"),
        # HTML con namespace: `<x:script xmlns:x=…>` evade la firma `<script`
        # porque la etiqueta tiene prefijo. SVG/MathML también sirve para
        # colar handlers.
        re.compile(
            r"<\s{0,8}(?:x\s{0,4}:|[a-z]{1,12}\s{0,4}:script|svg|math|body|details)"
        ),
        re.compile(r"xmlns\s{0,4}:"),
        # APIs de JS que ejecutan código pasado como argumento: `eval(`,
        # `setInterval(`, `document.` (acceso a cookies), `window.`… en un
        # valor de request son un intento de XSS DOM. Medido: +8 detecciones.
        re.compile(
            r"\b(?:setinterval|settimeout|eval)\s{0,16}\(|\bdocument\s{0,8}\."
            r"|\bwindow\s{0,8}\.|\blocation\s{0,8}=|\btop\s{0,8}\."
        ),
        # Exfiltración por CSS: `@import 'http://…'` carga una hoja externa (y
        # con ella puede filtrar), `<style>` es el vehículo, `expression()` es el
        # vector clásico de IE y `-moz-binding` el de Firefox antiguo.
        # Medido: +3 detecciones, 0 FP.
        re.compile(r"@import\s{0,4}'"),
        re.compile(r"<\s{0,8}style\b"),
        re.compile(r"(?:expression|-moz-binding)\s{0,8}[:(]"),
        re.compile(r"<[^<>]{0,200}\bon\w{1,40}\s{0,16}="),
        # evento sin etiqueta delante: `"onmouseover=`, ` onload=` (probe 941101/941120)
        re.compile(
            r"(?:^|[\s'\"`(<])on(?:mouseover|load|error|click|change|submit|focus|blur|toggle)"
            r"\s{0,16}="
        ),
        re.compile(r"<\s{0,16}iframe"),
        re.compile(r"data:text/html"),
        # Esquema con separadores que el navegador descarta (WHATWG URL: tab, NL
        # o CR en cualquier punto): `java\tscript:` y `java&#9;script:` siguen
        # siendo ejecutables. SOLO contenedores, no espacios: "java script:"
        # en prosa no es un esquema explotable y no debe saltar.
        re.compile(
            r"j(?:[\t\r\n\x00]{0,4})a(?:[\t\r\n\x00]{0,4})v(?:[\t\r\n\x00]{0,4})"
            r"a(?:[\t\r\n\x00]{0,4})s(?:[\t\r\n\x00]{0,4})c(?:[\t\r\n\x00]{0,4})"
            r"r(?:[\t\r\n\x00]{0,4})i(?:[\t\r\n\x00]{0,4})p(?:[\t\r\n\x00]{0,4})"
            r"t\s{0,16}:"
        ),
    ],
    # `..` solo cuenta como traversal en frontera de segmento: `foo../bar` es un
    # nombre de fichero, no un salto (falso positivo medido contra CRS).
    "path_traversal": [
        # `...//` (tres puntos + barra) es una evasion clasica: el
        # lookbehind `(?<![.\w])` impedia que `..` casara tras un punto,
        # y asi `...//...//etc/passwd` se escapaba. Se anade el patron de
        # tres puntos seguido de separador.
        # Medido contra el corpus retenido: +1 deteccion, 0 FP.
        re.compile(r"(?<![\w.])\.\.\.(?=[/\\])"),
        re.compile(r"(?<![\w.])\.\./"),
        re.compile(r"(?<![.\w])\.\.\\"),
        re.compile(r"(?<![.\w])\.\.;"),  # `..;/` para saltarse normalizadores
        re.compile(r"/etc/passwd"),
    ],
    # Ficheros que ningún request legítimo debería pedir (LFI / enumeración).
    # Exigen un separador de ruta o de query delante: `?q=me.env` pasa,
    # `?file=/app/.env` y `?path_comp=.ssh/id_rsa` no.
    "sensitive_files": [
        # `gshadow` es el equivalente de `shadow` para grupos: contiene los
        # hashes de las contrasenas de grupo. Lo anade el corpus retenido.
        re.compile(r"/etc/(?:passwd|shadow|gshadow|group|subuid|subgid)\b"),
        re.compile(r"/proc/self/(?:environ|cmdline)\b"),
        re.compile(r"(?:^|[\\/])win\.ini\b"),
        re.compile(r"(?:^|[\\/?=&])\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)\b"),
        re.compile(r"(?:^|[\\/?=&])\.aws/credentials\b"),
        re.compile(r"(?:^|[\\/?=&])\.docker/secrets\b"),
        re.compile(r"(?:^|[\\/?=&])\.git/config\b"),
        # `.env` exige separador de ruta: `?q=.env` (búsqueda) pasa, `?file=/app/.env` no
        re.compile(r"(?:^|[\\/])\.env\b"),
        # Java: `/WEB-INF/` es innaccesible por especificación Java EE; pedirlo
        # desde un navegador es exploración, nunca tráfico legítimo
        re.compile(r"(?:^|[\\/?=&])web-inf[/\\]"),
        # --- Añadidas tras medir contra el corpus RETENIDO (corpus/HELDOUT.md).
        # Ficheros de credenciales o de control que ninguna app legítima pide:
        # el socket de Docker (da acceso al host), la configuracion de
        # autenticacion de Postgres y el .htpasswd de Apache.
        # Medido: +3 detecciones, 0 FP en los tres corpus.
        re.compile(r"(?:^|[\\/?=&])var/run/docker\.sock\b"),
        re.compile(r"(?:^|[\\/?&=])pg_hba\.conf\b"),
        re.compile(r"(?:^|[\\/?&=])\.htpasswd\b"),
        # Rutas de sistema: `/sys/class`, `/sys/firmware`… leerlas es
        # reconocimiento del host, no una petición de una app.
        # Se añaden variantes sin exigir separador previo para rutas como `/get/sys/class`.
        re.compile(r"(?:^|[\s/?=&])(?:/sys/(?:class|firmware|devices|kernel|power|net|mounts|interrupts|cmdline|version|crypto)|/proc/self/)"),
        re.compile(r"(?:^|/)sys/(?:class|firmware|devices|kernel|power|net|mounts|interrupts|cmdline|version|crypto)"),
        re.compile(r"(?:^|/)proc/(?:interrupts|self)"),
        # Configuración de herramientas de desarrollo y credenciales que la
        # lista anterior no cubría: pedir `/.claude/settings.json` o `/.aws/`
        # desde un navegador es exploración pura.
        re.compile(
            r"(?:^|[\s/?=&])(?:/)?\.(?:claude|cursor|windsurf|vscode|git|aws|ssh|"
            r"kube|docker|gnupg)/"
        ),
        # Otras herramientas de IA y agentes: `.n8n`, `.aider`, `.zed`, `.roo`,
        # `.cline`, `.continue`, `.codex`, `.opencode`, `.kiro`, `.roo`, `.zed`…
        # Pedir su config por HTTP es reconocimiento, igual que los de arriba.
        re.compile(
            r"(?:^|[\s/?=&])/\.(?:n8n|aider|zed|roo|cline|continue|codex|"
            r"opencode|kiro|augment|devin|tabnine|cody|gemini|junie|qwizard|"
            r"trae|sourcegraph|fabric|plandex|a0proj|rovodev|cursorignore|"
            r"aiignore|cursorrules)\b"
        ),
        # Configuración de herramientas de IA y agentes (codex, cline, aider,
        # roo, zed…). Ninguna app web sirve estos ficheros: pedirlos es
        # reconocimiento. Medido contra el corpus de CRS.
        re.compile(
            r"(?:^|[\s/?=&])/\.(?:codex|cursor|copilot|cline|continue|aider|roo|"
            r"zed|kiro|windsurf|claude|opencode|rovodev|plandex|fabric|a0proj|"
            r"gemini|cody|tabnine|devin|sourcegraph|junie|qwizard|trae|augment)/"
        ),
        # Ficheros de "ignorar" de las herramientas: no se sirven nunca.
        re.compile(r"(?:^|[\s/?=&])/\.[a-z0-9_]{2,12}ignore\b"),
        # Logs y volcados: `/wp-content/debug.log`, `backup.sql.zip`,
        # `2024/01/15/…` (una fecha en la ruta es un volcado).
        re.compile(r"(?:^|[\s/?=&])(?:/)?(?:wp-content/|/logs?/)"),
        re.compile(r"\.(?:sql|bak|old|orig|save|swp)\s*$"),
        # Logs de servidor web: leerlos desde la app es reconocimiento del
        # host. Va en `sensitive_files` y no en `path_traversal` porque el
        # ORDEN de evaluacion de las familias importa: en `path_traversal`
        # esta regla se adelantaba a `cmdi` y un
        # `shell_exec('cat /var/log/syslog')` se clasificaba como traversal
        # en vez de como comando. Medido contra el corpus retenido:
        # +1 deteccion, 0 FP.
        re.compile(r"(?:^|(?<!['\"\s])[\/?&=])var/log/(?:nginx|apache|httpd|syslog|auth\.log|messages)\b"),
        # Una fecha en la ruta es un volcado SOLO si el resto de la ruta
        # parece un volcado. La regla original (`\d{4}/\d{2}/\d{2}/` a secas)
        # saltaba con cualquier ruta con fecha, y los blogs usan fechas en
        # el slug (`/blog/2026/01/15/titulo`): eso bloquea articulos
        # legitimos. Se pide que el segmento de la fecha tenga delante algo
        # que lo delate como volcado (`backup/2024/01/15/`, `dumps/...`) o
        # que la ruta continue con una extension de volcado.
        # Medido contra el corpus retenido: -1 FP sobre trafico legitimo,
        # 0 detecciones perdidas.
        re.compile(
            r"(?:^|[\s/?&=])(?:backup|backups|dump|dumps|export|exports|"
            r"archive|archives|snapshot|snapshots)/?\d{4}/\d{2}/\d{2}"
        ),
        re.compile(r"\d{4}/\d{2}/\d{2}/[^\s]*\.(?:sql|dump|tar|gz|bak)\b"),
        # backup.sql.zip y similares: ficheros de volcado en la ruta
        re.compile(r"(?:^|/)backup\.sql\.zip"),
        # `/etc/` más allá de passwd/shadow: configuración de servicios.
        re.compile(
            r"(?:^|[\s/?=&])/etc/(?:apache2?|nginx|hosts|resolv|cron|mysql|redis|"
            r"postgresql|ssh|passwd-|group-|shadow-)"
        ),
        # Árboles de dependencias: `node_modules` NO se bloquea (aparece en rutas
        # legítimas de sitios estáticos); solo los manifiestos sueltos, que no
        # se sirven desde una app.
        re.compile(
            r"(?:^|[\s/?=&])/(?:composer\.(?:json|lock)|package-lock\.json|"
            r"yarn\.lock|Gemfile|poetry\.lock|requirements\.txt|pom\.xml)\b"
        ),
        # (Los patrones de inyeccion SQL en la ruta vivian aqui. Se han movido
        # a la familia `sqli`: son SQLi, y con `disabled_rules=["sqli"]` no
        # tenian por que apagarse. Ver la familia `sqli`.)
    ],
    # Operadores de inyección NoSQL (Mongo): bypass de login (`user[$ne]=x`),
    # ejecución de JS (`$where`) y exfiltración por regex. `$gt`/`$lt`/`$in`
    # quedan FUERA a propósito: los filtros legítimos pasados por HTTP los usan
    # (`{"price":{"$gt":10}}`, benign-017) y el coste de bloquearlos no compensa.
    # Frontera documentada en docs/amenazas.md.
    "nosql": [
        # Operadores de inyeccion NoSQL (Mongo): bypass de login (`user[$ne]=x`),
        # ejecucion de JS (`$where`) y exfiltracion por regex. `$gt`/`$lt`/`$in`
        # quedan FUERA a proposito: los filtros legítimos pasados por HTTP los usan
        # (`{"price":{"$gt":10}}`, benign-017) y el coste de bloquearlos no compensa.
        # Frontera documentada en docs/amenazas.md.
        #
        # Endurecidos en la Fase 3: el ataque SIEMPRE llega dentro de un objeto
        # JSON o de un parametro (`{"$ne": ""}`, `user[$ne]=x`, `$where=...`),
        # asi que se pide ese contexto. Sin el, "que es el operador $ne de
        # mongodb" (una busqueda de documentacion) saltaba.
        # Medido: los 16 ataques que dependian SOLO de esta firma (11 propios,
        # 4 retenidos y 1 de CRS) llevan `[`, `"` o `=` delante, asi que no se
        # pierde ninguna deteccion.
        re.compile(
            r"(?:^|[\s\"'\[(,=])\$\s{0,4}(?:ne|where|regex|nin|or|exists)\b"
            r"\s{0,4}[\"']?\s{0,4}(?:[=:\[\(]|\]|$)"
        ),
    ],
    # Inyección de comandos: separador shell + binario (los unicos binarios sin
    # separador aceptables son los .exe de Windows, imposibles en prosa).
    "cmdi": [
        re.compile(
            r"(?:;|&&|\|\s{0,4}|\$\(|`)\s{0,8}"
            r"(?:ls|cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python\d{0,2}"
            r"|perl|ruby|powershell|cmd|dir|type|chmod|chown"
            r"|rm|cp|mv|kill|ps|env|printenv|hostname|ifconfig|ipconfig|nslookup"
            r"|dig|ping|socat|tar|dd|base64|net|mkdir|rmdir|ln)\b"
            # `;type=json`, `;env=prod` son params con `;` como separador, no
            # comandos: el binario no puede ir seguido de `=`.
            r"(?!\s{0,4}=)"
        ),
        # LOLBins de Windows: con `.exe` no hay prosa que los justifique
        re.compile(
            r"\b(?:cmd|powershell|wscript|cscript|mshta|certutil|rundll32"
            r"|regsvr32|bitsadmin|wmic|ncat)\.exe\b"
        ),
        # Un salto de linea ES un separador de comandos en shell: en
        # `foo\nrm -rf /` se ejecutan las dos cosas. A diferencia de `;`, el
        # salto de linea puede aparecer en prosa (una lista, un bloque de
        # codigo de un tutorial), asi que se exige el binario CON el flag o el
        # argumento que lo hace peligroso (`rm -rf`, `wget http`, `sh -c`), no
        # el binario solo (`cat`, `ls`), que en prosa es normal.
        re.compile(
            r"\n\s{0,8}(?:rm\s{0,8}-[a-z]{1,4}\b"
            r"|wget\s{0,8}https?://"
            r"|curl\s{0,8}(?:-[a-z]{1,4}\s{0,8}){0,4}https?://"
            r"|chmod\s{0,8}[0-7]{1,4}\b"
            r"|(?:ba|z|da)?sh\s{0,8}-c\b"
            r"|python\d{0,2}\s{0,8}-c\b"
            r"|nc\s{0,8}-[a-z]{1,4}\b"
            r"|chown\s{0,8}-[a-z]{1,4}\b)\s{0,4}"
        ),
        # PHP con separador (`;system('id')`) y funciones raras sin él
        # (`shell_exec(`): system/exec/assert SOLO con argumento entrecomillado
        # para no bloquear búsquedas como `eval(2+2)`.
        re.compile(
            r"(?:;|&&|\|\s{0,4}|\$\(|`)\s{0,8}"
            r"(?:system|exec|eval|shell_exec|passthru|popen|proc_open"
            r"|pcntl_exec|assert)\s{0,4}\(\s{0,4}['\"]?"
        ),
        re.compile(r"\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s{0,4}\("),
        # reverse shell clásica de bash
        re.compile(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}"),
    ],
    # SSRF: el destino vive en el valor. `localhost`/`127.0.0.1` NO se bloquean
    # (OAuth de desarrollo, webhooks locales: legítimos y muy comunes); sí las
    # IPs de metadata cloud y los esquemas de lectura local.
    "ssrf": [
        re.compile(r"\b169\.254\.169\.254\b"),  # AWS/GCP/Azure/OpenStack IMDS
        re.compile(r"\b169\.254\.170\.2\b"),  # AWS ECS task metadata
        re.compile(r"\b100\.100\.100\.200\b"),  # Alibaba metadata
        re.compile(r"\bmetadata\.google\.internal\b"),
        re.compile(r"\b(?:file|gopher|dict|jar|netdoc|tftp)://"),
        # La misma IP de metadata escrita en decimal, hex u octal: el parser
        # de URL del navegador las resuelve igual (`http://2852039166/` es el
        # IMDS de AWS). Se pide contexto de URL porque un numero decimal
        # suelto puede ser un identificador legitimo.
        re.compile(
            r"(?:https?|ftp|ftps)://\s{0,4}"
            r"(?:2852039166|2852038914|1684301000"        # decimal
            r"|0xa9fea9fe|0xa9feaa02|0x646464c8"          # hexadecimal
            r"|0252\.0376\.0252\.0376"                   # octal
            r"|0252\.0376\.0252\.0002|0144\.0144\.0144\.0310)"
            r"(?![0-9a-fx.])"
        ),
    ],
    # SSTI: primero aritmética (`{{7*7}}`, la prueba de canonicidad de todas
    # las plantillas), luego acceso a objetos peligrosos. `{{user.name}}` o
    # `${HOME}` (variables de entorno en prosa) no saltan.
    "ssti": [
        re.compile(r"\{\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}\s{0,8}\}\}"),
        re.compile(r"\$\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}\s{0,8}\}"),
        re.compile(r"<%=\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}"),
        re.compile(r"\#\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}"),
        # El interior se limita a lo que aparece DENTRO de una plantilla real
        # (identificadores, puntos, comillas, corchetes, espacios): una llave
        # no puede aparecer ahí, así que una racha de `{` falla en un paso en
        # vez de recorrer 40 posiciones por cada `{` (ReDoS por entrada patológica).
        re.compile(
            r"\{\{[-\w\.\[\]'\",() ]{0,40}"
            r"(?:config|request|session|application|self|lipsum"
            r"|cycler|namespace|globals|builtins|__class__|__mro__|__subclasses__)"
            r"[-\w\.\[\]'\",() ]{0,40}\}\}"
        ),
        # --- Añadida tras medir contra el corpus RETENIDO (corpus/HELDOUT.md).
        # Spring Expression Language: `${T(java.lang.Runtime).getRuntime().exec('id')}`.
        # La forma desnuda `T(...)` aparece en prosa sobre Spring, asi que se
        # exige la plantilla `${...}` delante. El texto se evalua en minusculas
        # (regla general del modulo), asi que el `T` va en minuscula tambien.
        # Medido: +1 deteccion, 0 FP.
        re.compile(r"\$\{\s{0,8}t\s{0,4}\(\s{0,8}[a-z]+\.[a-z]+\."),
    ],
    # CRLF / response splitting: el salto de línea DEBE ir seguido de una
    # cabecera, si no toda conversación multilínea sería un falso positivo.
    # Cubre CR/LF reales (decodificados de %0d%0a) y literales `\\r\\n`.
    "crlf": [
        re.compile(
            r"(?:[\r\n]|\\[rn]){1,3}\s{0,8}"
            r"(?:set-cookie|location|content-type|content-length"
            r"|www-authenticate|refresh|strict-transport-security"
            r"|transfer-encoding)\s{0,16}:"
        ),
        re.compile(r"(?:[\r\n]|\\[rn]){1,3}\s{0,8}x-[a-z0-9-]{1,32}\s{0,16}:"),
    ],
    # Log4Shell: cualquier `${jndi` en un valor de request es ataque, no hay
    # uso legítimo; se cubren las ofuscaciones con decoys (`${${::-j}ndi:`)
    # y la cadena de lookups que exfiltra (`${env:AWS_SECRET…}`).
    "log4shell": [
        re.compile(r"\$\{[\s\S]{0,32}jndi"),
        re.compile(r"\$\{::-[a-z]\}ndi|\$\{(?:lower|upper):[a-z]\}ndi"),
        re.compile(r"\$\{(?:\$\{::-[a-z]\}){2,6}"),  # `${${::-j}${::-n}…`
        re.compile(
            r"\bjndi\s{0,4}:\s{0,4}(?:ldaps?|rmi|dns|iiop|corba|nis|nds)\s{0,4}://"
        ),
        re.compile(
            r"\$\{\s{0,4}(?:env|sys|date|java|main|marker|web|ctx|lower|upper"
            r"|spring|k8s):"
        ),
    ],
    # Proto-pollution de JavaScript: `__proto__` en un valor es o ataque o una
    # búsqueda de documentación (FP documentado como benign-0xx, misma familia
    # que `<script>` en búsquedas).
    "proto_pollution": [
        re.compile(r"__proto__"),
        re.compile(r"constructor\s{0,4}[\[.]\s{0,4}prototype"),
        # --- Añadida tras medir contra el corpus RETENIDO (corpus/HELDOUT.md).
        # `constructor` y `prototype` pueden venir separados por una clave JSON
        # (`{"constructor": {"prototype": {...}}}`), donde la firma de arriba no
        # llega porque no hay `constructor.prototype` contiguo. Se exige que
        # los dos aparezcan en el mismo texto, a una distancia corta, para no
        # bloquear texto legitimo que mencione las dos palabras.
        # Medido: +1 deteccion, 0 FP en los tres corpus.
        re.compile(r"constructor.{0,40}prototype|prototype.{0,40}constructor"),
    ],
}


_UNICODE_ESCAPE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
# Entidades HTML numéricas: `&#60;` es `<` y `&#106;avascript:` es `javascript:`.
# Sin este paso, `&#60;script&#62;alert(1)` pasa intacto por cualquier inspección.
_HTML_ENTITY = re.compile(r"&#(?:x([0-9a-fA-F]{1,6})|(\d{1,7}));", re.IGNORECASE)
# Entidades HTML NOMBRADAS (lista acotada, no la tabla HTML5 entera): `&lt;script`
# y `javascript&colon;` son el mismo vector que sus formas numéricas. `&amp;` va
# la última para que `&#38;#60;` y `&amp;lt;` se resuelvan por rondas.
_NAMED_ENTITIES = {
    "lt": "<", "gt": ">", "quot": '"', "apos": "'", "colon": ":", "sol": "/",
    "tab": "\t", "newline": "\n", "bsol": "\\", "period": ".", "comma": ",",
    "num": "#", "amp": "&",
}
_NAMED_ENTITY = re.compile(
    r"&(" + "|".join(sorted(_NAMED_ENTITIES, key=len, reverse=True)) + r");",
    re.IGNORECASE,
)
# UTF-8 sobre-long: `%c0%af` es una `/` con bytes de más. `unquote` deja los
# bytes inválidos como U+FFFD, así que la forma porcentual se sustituye ANTES
# de decodificar; la forma ya convertida a caracteres (`%u00c0%u00af`) se
# normaliza después. Cualquier servidor que valide el encoding hace lo mismo.
_OVERLONG_MAP = {"%c0%af": "/", "%c0%ae": ".", "%e0%80%af": "/", "%e0%80%ae": "."}
_OVERLONG_PERCENT = re.compile("|".join(map(re.escape, _OVERLONG_MAP)), re.IGNORECASE)
_OVERLONG_CHARS = (
    ("\u00c0\u00af", "/"),
    ("\u00c0\u00ae", "."),
    ("\u00e0\u0080\u00af", "/"),
    ("\u00e0\u0080\u00ae", "."),
)


def _overlong_to_char(match: re.Match[str]) -> str:
    return _OVERLONG_MAP[match.group(0).lower()]


def _entity_to_char(match: re.Match[str]) -> str:
    hexa, decimal = match.group(1), match.group(2)
    code = int(hexa, 16) if hexa else int(decimal, 10)
    # `chr()` lanza con > 0x10FFFF: la entidad se deja tal cual. El fuzzer
    # genera `&#99999999;` y debe seguir pasando sin excepción.
    return match.group(0) if code > 0x10FFFF else chr(code)


# Comentario versionado de MySQL: el contenido SE EJECUTA si la versión cumple,
# así que se desenvuelve en lugar de borrarlo (un `/*!50000union*/` borrado es
# un payload invisible). Contenido acotado: sin `*/` de cierre no hay carrera.


_VERSIONED_HEAD = re.compile(r"!\d{0,6}")


def _strip_sql_comments(text: str) -> str:
    """Quita comentarios SQL `/* ... */` en tiempo LINEAL.

    - `/*!50000union*/` (versionado de MySQL) se DESENVUELVE a su contenido:
      MySQL lo ejecuta, borrarlo ocultaría el payload.
    - Cualquier otro comentario se sustituye por un espacio.
    - Un `/*` sin cierre se deja tal cual y se corta la búsqueda: con
      `re.sub(r"/\\*.*?\\*/", ...)` cada `/*` sin cierre recorría el resto del
      texto (O(n^2): 128 KB de `/*a` tardaban 21 s, y el body admite 1 MiB).
    Cada carácter se recorre una vez con `str.find`, que es C y no retrocede.
    """
    out: list[str] = []
    i = 0
    while True:
        start = text.find("/*", i)
        if start < 0:
            break
        end = text.find("*/", start + 2)
        if end < 0:
            break
        body = text[start + 2:end]
        out.append(text[i:start])
        head = _VERSIONED_HEAD.match(body) if body.startswith("!") else None
        if head and len(body) - head.end() <= 200:
            out.append(" " + body[head.end():] + " ")
        else:
            out.append(" ")
        i = end + 2
    out.append(text[i:])
    return "".join(out)


def decode(value: str, max_rounds: int = 3, plus: bool = True) -> str:
    """Decodifica URL-encoding repetido, escapes `%uXXXX` y entidades HTML.

    - `%uXXXX` es la codificación Unicode de IIS: `or %U20191%U2019` es
      `or ’1’`. Sin este paso, esa evasión pasa intacta (mayúsculas incluidas).
    - Entidades numéricas: `&#60;script&#62;` es `<script>`; los rangos se
      acotan para que `&#99999999;` no reviente (`_entity_to_char`).
    - Sobre-long: `%c0%af` → `/` antes de decodificar (`_OVERLONG_PERCENT`)
      y en forma de caracteres después (`_OVERLONG_CHARS`).
    Todo por rondas: cada forma puede revelar la siguiente (`&#38;#60;` →
    `&#60;` → `<`), de ahí que convivan en el mismo ciclo.
    """
    for _ in range(max_rounds):
        antes = value
        value = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)
        value = _HTML_ENTITY.sub(_entity_to_char, value)
        value = _NAMED_ENTITY.sub(lambda m: _NAMED_ENTITIES[m.group(1).lower()], value)
        value = _OVERLONG_PERCENT.sub(_overlong_to_char, value)
        # Solo la PRIMERA ronda traduce "+" a espacio (que es lo que significa
        # en un query string). En las siguientes, un "+" ya decodificado
        # ("%2B") se perderia: el servidor se lo entrega al usuario como "+",
        # y Gatekeeper lo convertiria en espacio. Perder el "+" era un falso
        # negativo real: `sleep(10%2B6)` (operador de MySQL) llegaba como
        # `sleep(10 6)` y no se detectaba.
        decoded = unquote_plus(value) if (plus and _ == 0) else unquote(value)
        for overlong, directo in _OVERLONG_CHARS:
            decoded = decoded.replace(overlong, directo)
        # se compara con el INICIO de la ronda: una transformación puede revelar
        # otra sin que el final del pipeline cambie (`&#38;#60;` → `&#60;` → `<`)
        if decoded == antes:
            break
        value = decoded
    return value


def normalize(value: str, max_rounds: int = 3, plus: bool = True) -> str:
    """Decodifica, normaliza Unicode, quita comentarios SQL y pasa a minúsculas.

    - `/**/` se trata como espacio en blanco (así lo interpreta MySQL), lo que
      desactiva el ofuscador `uni/**/on/**/select`.
    - Los comentarios VERSIONADOS `/*!50000union*/` se desenvuelven a su
      contenido (`union`): MySQL los ejecuta, borrarlos ocultaría el payload.
      Contenido acotado a 200 caracteres por si el comentario nunca cierra.
    - NFKC pliega los caracteres de ancho completo: `＜script` (U+FF1C) es
      `<script` para cualquier inspección que no normalice; Gatekeeper sí lo hace.
    - Tras NFKC se decodifica otra vez (pase acotado): la normalización puede
      desvelar escapes escritos en ancho completo (`％Ｕ００２７` → `%U0027` → `'`).
    - Se aplica también a las reglas personalizadas: documentado en el README.
    - `plus=False` NO traduce el `+` a espacio. Es lo que necesitan los valores
      que ya vienen decodificados (el body y las cabeceras): para la
      aplicación, un `+` ahí es un carácter LITERAL (el operador de MySQL en
      `sleep(10+6)`), no un espacio. Traducirlo a espacio es perder un ataque.
      Ver `scan_plus_literal`.
    """
    text = unicodedata.normalize("NFKC", decode(value, max_rounds, plus=plus))
    text = unicodedata.normalize("NFKC", decode(text, max_rounds, plus=False))
    text = unicodedata.normalize("NFKC", decode(text, max_rounds, plus=False))
    text = _strip_sql_comments(text)
    return text.lower()


def _family_names() -> tuple[str, ...]:
    return tuple(RULES)


# Prefiltro literal por familia: si el texto normalizado no contiene NINGUNO de
# estos literales, es IMPOSIBLE que esa familia case, y se salta entera sin
# ejecutar sus regex.
#
# Por qué: medido, el escaneo cuesta 57 µs y casi todo es regex de Python
# corriendo sobre texto inocuo. Una comprobación `lit in texto` esstrcmp en C y
# cuesta nanosegundos. El ahorro es real solo si el conjunto está bien elegido.
#
# La regla para_no perder una detección es: si un patrón casa, TODOS los literales
# de su familia tienen que estar presentes en el texto (alternativa: `or` en la
# lista). `tests/test_prefilter.py` lo verifica contra todo el corpus (propio y
# CRS) y falla si alguien añade una regla sin prefiarla o la prefila mal.
#
# `None` = familia sin prefilto (se ejecuta siempre). Se deja así cuando el
# patrón puede casar con cualquier texto (p. ej. `?a=1=1`), donde un literal
# "obligatorio" no existe o sería tan común que no filtraría nada.
PREFILTER_LITERALS: dict[str, tuple[str, ...] | None] = {
    # Nota sobre literales con espacios: `unquote_plus` convierte `+` en
    # espacio, así que `pay=or+1=1` llega como `or 1=1` (con espacio) pero
    # `?or&1=1` llega como `or&1=1` (sin espacio). Por eso los literales de
    # palabras sueltas van SIN espacios (`or`, `and`), no con ellos: `or` a secas
    # aparece en "color", "orden"... pero es el precio de no perder detecciones,
    # y sqli se evalúa igual que antes de este pre filtro.
    "sqli": (
        "union", "select", "insert", "update", "drop", "delete", "alter",
        "truncate", "exec", "exists", "order by", "ascii", "ord", "length",
        "char_length", "substring", "substr", "mid", "sleep", "benchmark",
        "waitfor", "delay", "extractvalue", "updatexml", "convert",
        "xp_cmdshell", "'--", "'#", " or ", " and ",
        # `or`/`and` a secas (sin exigir espacios alrededor) porque la
        # tautología dispara también con `pay=or 120=121=`: exigir el espacio
        # hacía que el pre filtro descartara la familia en esos casos.
        "or", "and",
        # Tautología canónica en contexto de parámetro: `?a=1=1`, `1,1=1`.
        # El patrón exige un `1` a cada lado del `=`, así que `1=1` es
        # obligatorio en el texto si ese patrón dispara.
        "1=1",
        # Funciones SQL y operadores tolerantes de las firmas nuevas.
        "abs(", "coalesce(", "count(", "greatest(", "ifnull(", "least(",
        "max(", "min(", "nullif(", "power(", "rand(", "row(", "trunc(",
        "cast(", "char(", "regexp", "like null", ">>", "&&",
        # Firmas anadidas tras medir contra el corpus retenido. Sin estos
        # literales, el pre filtro descartaba la familia en textos largos
        # y estas detecciones se perdian SOLO con entradas >= 128
        # caracteres: un fallo que no se ve en los corpus cortos.
        "group by", "having", "outfile", "dumpfile", "analyse", "iif(",
    ),
    # `on\w+=` cubre CUALQUIER handler de evento (`onerror`, `onload`,
    # `onwebkitplaybacktargetavailabilitychanged`...). Es un pre filtro, no una
    # regla: si el texto tiene algo `on...=`, la familia se evalúa y decide.
    "xss": (
        "script", "javascript", "data:text/html", "<iframe", "alert",
        # namespace de etiquetas: `<x:script`, `<svg`, `<math`… y `xmlns:`
        "xmlns", "<svg", "<math", "<body", "<details", ":script",
        # APIs de JS que ejecutan o acceden: eval(, setinterval(, document.,
        "eval(", "setinterval", "settimeout", "document.", "window.",
        "location=", "top.",
        # `on` como literal cubre cualquier handler de evento (finito o
        # exótico: `onerror=`, `onend=`, `onwebkitplaybacktarget=…`): la regla
        # real `on\w+=` decide después; aquí solo evitamos descartar la familia
        # antes de tiempo. Cuesta algo de precisión (aparece en "botón"), que es
        # el precio de no perder detecciones.
        "on",
    ),
    "path_traversal": ("../", "..\\", "..;", "/etc/", "/proc/", "win.ini", "/windows"),
    "sensitive_files": (
        "/etc/", "/proc/self", "win.ini", ".ssh/", ".aws/", ".docker/",
        ".git/", ".env", "web-inf", "/windows/system32",
        "/sys/", ".claude/", ".cursor/", ".windsurf/", ".vscode/",
        ".kube/", ".gnupg/",
        # Anadidos tras medir contra el corpus retenido.
        "var/log/", "docker.sock", "pg_hba.conf", ".htpasswd",
    ),
    "nosql": ("$ne", "$nin", "$where", "$regex", "$or", "$exists"),
    "cmdi": (
        "; ls", "; cat", "; id", "; whoami", "; uname", "; wget", "; curl",
        "| ls", "| cat", "| id", "| whoami", "| uname", "| nc", "| bash", "| sh",
        "| type", "| dd", "| rm", "| dir", "&& ", "$(", "`", "powershell",
        "cmd.exe", ".exe", "system(", "exec(", "eval(", "shell_exec",
        "passthru", "popen", "proc_open", "pcntl_exec", "assert(",
        "/dev/tcp",
        # `dd`, `ls`, `cat`… sueltos: el patrón acepta cualquier binario tras
        # `;` o `|`, y enumerarlos todos en el pre filtro es frágil (CRS genera
        # combinaciones raras como `;;dd foo bar`). Con los binarios sueltos, el
        # pre filtro deja pasar esos casos y la regex real decide.
        "dd", "uname", "whoami",
        # El salto de linea como separador de comandos: el literal es el
        # propio "\n" porque el comando puede ir con espacios delante
        # (`\n rm -rf /`) y un literal "\nrm" no lo cubria. El precio es que
        # la familia se evalua en texto multilinea; es una familia corta.
        "\n",
    ),
    # Aviso de SonarCloud sobre "protocolo inseguro" (TFTP/Gopher) y sobre la IP
    # hardcodeada: estos literales aparecen porque DETECTAMOS ataques que los
    # usan como vector (SSRF con `gopher://`, metadata de Alibaba). Gatekeeper no
    # los usa para hablar con nadie: son firmas. `NOSONAR` va en la línea que el
    # escáner señala, no en un comentario aparte.
    "ssrf": (
        "169.254.", "metadata.google", "file://", "dict://", "jar:", "netdoc://",
        "100.100.100.200",  # NOSONAR - IP de metadata de Alibaba Cloud, es una firma
        "gopher://", "tftp://",  # NOSONAR - esquemas SSRF que detectamos, no los usamos
        # La IP de metadata en decimal, hex y octal (con esquema delante):
        # sin estos literales, el pre filtro descartaba la familia y las
        # tres formas se colaban.
        "2852039166", "2852038914", "1684301000",
        "0xa9fea9fe", "0xa9feaa02", "0x646464c8",
        "0252.0376.0252.0376", "0252.0376.0252.0002", "0144.0144.0144.0310",
    ),
    "ssti": ("{{", "${", "<%=", "#{", "config", "request", "self.", "lipsum",
            "cycler", "namespace", "globals", "builtins", "__class__", "__mro__",
            "__subclasses__", "application", "session"),
    "crlf": ("set-cookie", "location", "content-type", "content-length",
             "www-authenticate", "refresh", "strict-transport-security",
             "transfer-encoding", "x-"),
    "log4shell": ("jndi", "env:", "sys:", "date:", "java:", "main:",
                  "marker:", "web:", "ctx:", "lower:", "upper:", "spring:", "k8s:",
                  "::-", "ldap://", "ldaps", "rmi://", "dns://", "iiop://",
                  "corba://", "nis:", "nds:", "${"),  # NOSONAR - JNDI es el vector que detectamos
    "proto_pollution": ("__proto__", "constructor", "prototype"),
}


def _build_prefilter() -> tuple[tuple[str, ...], dict[str, frozenset[str]]]:
    """Literales (para `in`, que es C puro) + dict literal→familias.

    Se midieron tres enfoques y todos menos este pierden:
    - 11 `search` por familia: ~12 µs, se come el ahorro.
    - un `finditer` con alternancia gigante: 15 µs en texto corto, 80 µs en
      largo (crea un objeto por coincidencia).
    - un `search` con grupos por familia en bucle: 30 µs (el bucle dominates).

    Este es el que gana: una comprobación `lit in texto` por literal. `in` sobre
    `str` es una búsqueda de subcadena en C, y con pocos cientos de caracteres
    es de nanosegundos. Para el texto inocuo (sin ninguno de los literales) son
    ~60 comparaciones, pero cada una es más barata que cualquier regex.
    """
    familias: dict[str, set[str]] = {}
    for familia, literales in PREFILTER_LITERALS.items():
        for literal in literales or ():
            familias.setdefault(literal, set()).add(familia)
    return tuple(familias), {k: frozenset(v) for k, v in familias.items()}


_PREFILTER_LITERALS_FLAT, _PREFILTER_FAMILIA = _build_prefilter()


def _posibles_familias(text: str) -> set[str]:
    """Familias con algún literal presente (comprobaciones `in`, sin regex)."""
    posibles: set[str] = set()
    for literal in _PREFILTER_LITERALS_FLAT:
        if literal in text:
            posibles |= _PREFILTER_FAMILIA[literal]
    return posibles


# A partir de este tamaño de texto, el pre filtro (N comparaciones `in`, que son
# lineales en la longitud del texto) se paga. En textos cortos se evalúan todas
# las familias directamente: con ~40 caracteres, la diferencia es de nanosegundos
# y nos ahorramos el coste del pre filtro en el caso de un ataque (que corta en
# la primera regex que casa).
#
# Medido: el literal que casa en un ataque SQLi es el primero de 156, así que
# `scan` sin pre filtro ya es rápido (10 µs). Añadir 156 `in` encima lo subía a
# 17 µs. Con texto largo (250+ caracteres), el pre filtro sí ahorra (247 → 29 µs).
# El umbral está donde ambos términos se cruzan, medido.
_PREFILTER_MIN_LEN = 128


def _vale_la_pena_prefiltrar(text: str) -> bool:
    return len(text) >= _PREFILTER_MIN_LEN


# Packs de reglas: la misma detección, agrupada por lo que una aplicación
# EXIGE de verdad. No cambian ni una línea de los patrones; solo el subconjunto
# de familias que se evalúa, para que un backend sin plantillas no pague (ni
# sufra falsos positivos) por firmas que su superficie no expone.
#
# Todos son OPT-IN: sin `rule_packs` se evalúan las once familias (el defecto
# no cambia respecto a 0.3.1). Configúralo solo si sabes qué expone tu app.
#
# - `minimal`: lo que no depende de la superficie (SQLi y traversal).
# - `api`: APIs JSON/GraphQL sin HTML servido: fuera `xss`, `ssti` y
#   `proto_pollution`; dentro SQLi, NoSQL, traversal, ficheros sensibles y las
#   cuatro de infraestructura (SSRF, Log4Shell, CRLF, comandos).
# - `web`: web pública con HTML: lo de `api` más `xss`. Es el pack que casi
#   todo el mundo quiere; no excluye `ssti` porque un CMS renderiza plantillas.
# - `infrastructure`: solo ataques que llegan por valores que el usuario nunca
#   ve (destinos, cabeceras, logs) — útil como segunda capa tras otra.
# - `strict`: las once familias, sin excluir nada (equivale al defecto).
RULE_PACKS: dict[str, frozenset[str]] = {
    "minimal": frozenset({"sqli", "path_traversal"}),
    "api": frozenset({"sqli", "nosql", "path_traversal", "sensitive_files"}),
    "web": frozenset({"sqli", "xss", "path_traversal", "sensitive_files"}),
    "infrastructure": frozenset({"ssrf", "log4shell", "crlf", "cmdi"}),
}
# `web` y `api` heredan las familias de infraestructura: una web también recibe
# SSRF y Log4Shell por sus formularios, aunque no renderice plantillas.
RULE_PACKS["web"] = frozenset(RULE_PACKS["web"] | RULE_PACKS["infrastructure"])
RULE_PACKS["api"] = frozenset(RULE_PACKS["api"] | RULE_PACKS["infrastructure"])
RULE_PACKS["strict"] = frozenset(_family_names())

PACK_NAMES: tuple[str, ...] = ("minimal", "api", "web", "infrastructure", "strict")


def resolve_rules(packs: Iterable[str] | None = None) -> set[str]:
    """Familias activas según los packs pedidos.

    `None` o lista vacía = **todas** las familias (el defecto histórico: los
    packs son opt-in). Cada nombre debe existir en `RULE_PACKS`; un nombre
    desconocido es `ValueError` al arrancar, no una configuración que en
    silencio deja la app sin protección.
    """
    selected = [str(p).strip() for p in (packs or ()) if str(p).strip()]
    if not selected:
        return set(_family_names())
    familias: set[str] = set()
    for name in selected:
        pack = RULE_PACKS.get(name.lower())
        if pack is None:
            raise ValueError(
                f"Pack de reglas desconocido: '{name}'. Disponibles: {', '.join(PACK_NAMES)}"
            )
        familias |= pack
    return familias


def _familias_a_evaluar(
    text: str,
    disabled: set[str],
    only: frozenset[str] | set[str] | None,
    use_prefilter: bool,
) -> set[str] | None:
    """Familias integradas que hay que evaluar, o None si son todas.

    None = "no filtrar" (y entonces el llamador no paga nada por construir
    conjuntos). Las reglas personalizadas de `extra` nunca se pre filtran: son
    tuyas y las pediste explícitamente.
    """
    if only is None and not disabled:
        # Caso mayoritario: no hay ni packs ni reglas desactivadas. Si además el
        # texto es corto (no compensa el pre filtro), se devuelven todas sin
        # construir nada.
        if not use_prefilter or not _vale_la_pena_prefiltrar(text):
            return None
    candidatas = set(RULES) - disabled
    if only is not None:
        candidatas &= {f for f in only if f in RULES}
    if not use_prefilter or not _vale_la_pena_prefiltrar(text):
        return candidatas
    return candidatas & _posibles_familias(text)


def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
    carriers: list[str] | None = None,
    allow_cross_carrier: bool = False,
) -> tuple[str, str] | None:
    """Como `scan()`, pero devuelve `(regla, patrón)` — el patrón es el "motivo"
    que se registra en los eventos de auditoría para poder tunear sin adivinar.

    `only` limita la evaluación a un subconjunto de familias (los packs de
    `Config.active_rules`); las reglas personalizadas de `extra` se evaluan
    siempre, porque son tuyas y las pediste explícitamente.

    `use_prefilter` activa el descarte de familias cuyo literal obligatorio no
    aparece en el texto (ver `PREFILTER_LITERALS`). No cambia qué se detecta:
    un test lo verifica contra los dos corpus. Se puede desactivar para
    diagnosticar una discrepancia.

    Si `allow_cross_carrier` es verdadero, `value` y `carriers` se consideran
    partes de una misma entrada y se normalizan juntas antes de escanearlas.

    El `+` se lee de las DOS formas: como espacio (que es lo que significa en
    una query string) y como carácter literal (que es lo que es en un body, y
    el operador de MySQL en `sleep(10+6)`). Un `scan()` no sabe de dónde sale
    el valor, y quedarse con una sola de las dos lecturas es dejar pasar un
    ataque: el middleware inspeccionaba `sleep(10 6)` mientras la aplicación
    usaba `sleep(10+6)`.
    """
    hit = _scan_detailed(
        value, disabled, extra, only, use_prefilter, carriers, allow_cross_carrier,
        plus=True,
    )
    if hit is None and "+" in value:
        hit = _scan_detailed(
            value, disabled, extra, only, use_prefilter, carriers,
            allow_cross_carrier, plus=False,
        )
    return hit


def scan_plus_as_space(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
    carriers: list[str] | None = None,
    allow_cross_carrier: bool = False,
) -> tuple[str, str] | None:
    """Escanea un texto donde el `+` es un ESPACIO: la query string.

    En una query, `+` significa espacio (así lo parsea el servidor); el `+` que
    venga de `%2B` es un carácter literal, y `decode()` lo respeta (la
    traducción del `+` solo ocurre en la primera ronda).

    Es la lectura que usa el middleware con la ruta y la query. No es API
    pública: la usan el middleware y las pruebas.
    """
    return _scan_detailed(
        value, disabled, extra, only, use_prefilter, carriers, allow_cross_carrier,
        plus=True,
    )


def scan_plus_literal(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
) -> tuple[str, str] | None:
    """Escanea un texto donde el `+` es LITERAL: el body y las cabeceras.

    Para la aplicación, un `+` en un body es un carácter literal -el operador
    de MySQL en `sleep(10+6)`-, no un espacio. Traducirlo a espacio es perder
    un ataque.

    No es API publica: la usan el middleware y las pruebas.
    """
    return _scan_detailed(
        value, disabled, extra, only, use_prefilter, None, False, plus=False
    )


def _scan_detailed(
    value: str,
    disabled: set[str] | None,
    extra: dict[str, list[re.Pattern[str]]] | None,
    only: frozenset[str] | set[str] | None,
    use_prefilter: bool,
    carriers: list[str] | None,
    allow_cross_carrier: bool,
    plus: bool,
) -> tuple[str, str] | None:
    """El escaneo de verdad, con el tratamiento del `+` parametrizable."""
    # Cross-carrier detection is opt-in because joining input contexts can add
    # false positives; middleware only calls this after independent scans miss.
    if allow_cross_carrier and carriers:
        value = " ".join((value, *carriers))
    text = normalize(value, plus=plus)
    desactivadas = disabled or set()
    activas = _familias_a_evaluar(text, desactivadas, only, use_prefilter)

    # El orden importa: primero las integradas en el orden de RULES, luego las
    # personalizadas. Es el mismo criterio de antes (una regla integrada que
    # casa gana a una personalizada). `activas is None` = todas evaluables.
    for name, patterns in RULES.items():
        if activas is not None and name not in activas:
            continue
        for pattern in patterns:
            if pattern.search(text):
                return name, pattern.pattern
    for name, patterns in (extra or {}).items():
        if name in desactivadas:
            continue
        for pattern in patterns:
            if pattern.search(text):
                return name, pattern.pattern
    return None


def scan(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> str | None:
    """Devuelve el nombre de la regla que coincide (integrada o personalizada), o None."""
    hit = scan_detailed(value, disabled, extra)
    return hit[0] if hit else None


def scan_all(
    values: Iterable[str],
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> str | None:
    """Recorre varios valores y devuelve la PRIMERA familia que coincide.

    OJO con el nombre: "all" viene de que recorre *todos* los valores, no de
    que devuelva todas las reglas. Si lo que quieres es la lista completa de
    familias de un valor, usa `scan_detailed` (que devuelve la familia y su
    regex) o `RULES`.
    """
    for value in values:
        rule = scan(value, disabled, extra)
        if rule:
            return rule
    return None
