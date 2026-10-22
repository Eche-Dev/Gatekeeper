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
