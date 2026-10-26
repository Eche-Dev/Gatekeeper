# Hoja de ruta

Lo que está hecho, lo que está en curso y lo que queda. Cada versión publicada
tiene su entrada en el [CHANGELOG](CHANGELOG.md) y sus notas de versión.

## v0.1 — núcleo
- [x] Rate limiting en memoria (ventana deslizante)
- [x] Cabeceras de seguridad por defecto
- [x] Reglas sqli / xss / path traversal sobre ruta + query string
- [x] Modo `monitor_only` y lista de IPs bloqueadas
- [x] Auditoría en JSON (logger `gatekeeper`)

## v0.2 — body, YAML, exclusiones
- [x] Inspección del body JSON y form-urlencoded con límite de tamaño (413)
- [x] Reglas personalizadas y configuración por YAML (`Config.from_yaml`)
- [x] `allow_paths` resistente a traversal
- [x] Regex acotadas (anti-ReDoS) y limpieza de IPs inactivas en el rate limiter

## v0.3 — medida, Redis y honestidad
- [x] Corpus público con procedencia y límites documentados (`corpus/`)
- [x] Evaluador `tools/evaluate.py`: tasa de detección, falsos positivos y
      umbral de CI (`--check`)
- [x] Reglas nuevas midiendo antes y después: sondeo de columnas, EXISTS,
      error-based, time-based de SQL Server/PostgreSQL, ficheros sensibles
- [x] Rate limiting en Redis con script Lua atómico y cliente `redis.asyncio`
      (no bloquea el event loop), política `rate_fail_open`
- [x] Benchmark de latencia por petición (`benchmarks/latency.py`)
- [x] mypy estricto + `py.typed` (PEP 561), `CHANGELOG.md`, `SECURITY.md`,
      build + `twine check` y prueba de instalación limpia en CI
- [x] Corpus **externo** de OWASP CRS (1379 tests, Apache-2.0 con atribución y
      commit de procedencia) como segunda batería de medida, con guarda de
      regresión en CI
- [x] Fuzzing con hypothesis (`tests/test_fuzz.py`): propiedades sobre
      `scan`, `normalize`, `extract_strings`, `Config` y `allow_paths`
- [x] ReDoS cuadrático de los cuantificadores de blancos medido y corregido
      (`or` + 80k espacios: 118 s → <1 s) con test de regresión
- [x] Documentación con MkDocs Material (`docs/`), CONTRIBUTING, código de
      conducta y plantillas de issues/PR; workflows en la raíz del repo para
      que GitHub los ejecute
- [x] Demo desplegable (`demo/`: playground con payloads, Vercel/Docker) con
      el GIF de una sesión real (`docs/assets/demo.gif`)
- [x] Artículo de publicación (`ARTICLE.md`)
- [x] GitHub Pages publicando la docs en cada push a main
      (https://eche-dev.github.io/Gatekeeper/)

## v0.4 — superficie
- [x] WebSocket: se inspecciona el **handshake** (ruta, query y cabeceras), los
      frames no
- [x] `multipart/form-data`: se inspeccionan los **nombres** de campo y de
      fichero, no el contenido
- [x] `application/octet-stream`: se **sniffea** el cuerpo (si es JSON, se
      inspecciona como JSON)
- [x] DoS cuadrático en la normalización corregido (advisory
      `GHSA-p5w5-hwqh-78hc`, publicado)

## v0.5 — superficie y honestidad del log
- [x] Cabeceras de seguridad también en los rechazos (403/413/429/503)
- [x] El log lleva la regla, la ruta y el tamaño, **nunca** los valores
- [x] `Config` valida al arrancar y los valores unknown son un error

## v0.6 — recursos, logs y operación
- [x] Presupuestos: `max_fields` y `max_inspection_ms` (fail-closed, nunca
      fail-open: agotar el presupuesto a propósito sería un bypass)
- [x] Rate limiter acotado (LRU), IPv6 `/64` e IPv4-mapped
- [x] Salida saneada (el atacante no puede escribir en la terminal de quien
      lee el log) y punteros JSON acotados
- [x] Reglas propias validadas contra ReDoS al arrancar (`redos.py`)
- [x] Límite de body a 256 KiB (documentado como cambio de comportamiento)

## v0.7 — detección
- [x] 4 falsos negativos reales cerrados (tautología con literales vacíos,
      booleano ciego, SSRF con la IP de metadata en decimal/hex/octal, y
      comandos separados por salto de línea)
- [x] El `+` de un query string ya no se pierde al decodificar
- [x] 6 falsos positivos de prosa cerrados (`<script>`, `sleep(8 hours)`,
      `union all`, `waitfor delay`, `like null`, operadores NoSQL citados)
- [x] **Corpus de falsos positivos en español e inglés**: 100 peticiones
      legítimas nuevas (50 de desarrollo + 50 retenidas), publicadas

## v0.9 — validación externa (en curso)
- [x] Job `sast` en CI: `semgrep` (reglas propias bloqueantes + `p/default`
      informativo) y `zizmor` para los workflows, con `persist-credentials`
      desactivado en los siete `actions/checkout` (7 hallazgos de zizmor -> 0)
- [x] Job `bench` en CI: el PR y `main` medidos **en el mismo runner**, con la
      mediana de tres repeticiones (el ruido típico es del 0,3 %; los picos
      sueltos del 41 % hacen inviable un umbral absoluto)
- [x] `Config.redis_timeout`: con Redis caído, el coste por petición estaba
      escrito a pelo (2,0 s) y no se podía ajustar
- [x] El log de auditoría sanea **también** los avisos de `config.py` (el
      nombre de una regla propia llegaba sin sanear ni acotar)
- [x] Tests diferenciales del body (`tools/diferencial_body.py`): el middleware
      y la aplicación tienen que interpretar el body igual, medido en las 10
      combinaciones de la matriz de compatibilidad
- [x] El `+` de un body es **literal** para la aplicación (el operador de MySQL
      en `sleep(10+6)`): el middleware lo traducía a espacio y el payload
      llegaba intacto (bypass corregido)
- [x] Paquete para la revisión de seguridad independiente
      (`.audit/PACK-REVISOR/`): alcance, PoC ejecutables, estado medido y
      plantilla del informe
- [ ] Revisión de seguridad **independiente**, publicada

## v0.8 — coherencia documental (cerrada)
- [x] Verificador propio de coherencia (`tools/check_docs.py`): la versión,
      los enlaces internos, las anclas y la higiene editorial, en CI
- [x] API pública exportada de forma explícita (`scan`, `scan_all`,
      `scan_detailed`, `RULES`, `PACK_NAMES`) y testeada
- [x] Umbral de CI del corpus de CRS subido a la línea base real (0,40)
- [x] Sin email personal en los metadatos: el canal es GitHub Advisories
- [x] README en inglés (`README.en.md`) con enlace desde el español
- [x] Empaquetado: el sdist baja de **514 KiB a 95 KiB** (sin corpus, web,
      demos ni tests) y el CI lo vigila
- [x] `AGENTS.md` con las reglas de trabajo del proyecto
- [x] `tools/metrics.py` con tests y `tools/compat_matrix.py` como job de CI
- [ ] Aplanar el repo (`src/`, `tests/`, `docs/` a la raíz) y mover las
      versiones viejas a tags
- [ ] Métricas Prometheus (contadores de bloqueos y de rate limit)

## Publicación
- [x] Publicado en PyPI como `gatekeeper-asgi` con *Trusted Publishing* y
      provenance verificado (0.4.0, 0.4.1, 0.5.0, 0.6.0, 0.7.0, 0.8.0,
      0.9.0)
- [ ] Nombre y versión definitivos del paquete (hoy `gatekeeper-asgi`, con la
      carpeta del repo en `v0.3` por razones históricas)
- [ ] Demo en Vercel (`vercel --prod` desde `demo/`) — credenciales del
      propietario
- [ ] Publicación del artículo (`ARTICLE.md` listo, sin placeholders)
