import json
import logging

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


async def echo(request: Request):
    return PlainTextResponse((await request.body()).decode("utf-8", "replace"))


def make_client(**cfg):
    app = Starlette(
        routes=[
            Route("/echo", echo, methods=["POST"]),
            Route("/docs", echo, methods=["POST"]),
        ]
    )
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0, **cfg))
    return TestClient(app)


def test_clean_json_reaches_app_intact():
    payload = {"name": "Ángel", "tags": ["a", "b"], "n": 3}
    r = make_client().post("/echo", json=payload)
    assert r.status_code == 200
    assert json.loads(r.text) == payload


def test_json_attack_in_nested_value_is_blocked():
    body = {"user": {"bio": ["ok", "1 UNION SELECT password FROM users"]}}
    assert make_client().post("/echo", json=body).status_code == 403


def test_json_attack_in_key_is_blocked():
    assert make_client().post("/echo", json={"<script>alert(1)</script>": 1}).status_code == 403


def test_form_attack_is_blocked():
    r = make_client().post("/echo", data={"comment": "<script>alert(1)</script>"})
    assert r.status_code == 403


def test_clean_form_passes_and_is_replayed():
    r = make_client().post("/echo", data={"a": "hello"})
    assert r.status_code == 200
    assert r.text == "a=hello"


def test_monitor_only_allows_body_and_replays_it():
    r = make_client(monitor_only=True).post("/echo", json={"q": "<script>x</script>"})
    assert r.status_code == 200
    assert "<script>" in r.text


def test_oversize_declared_content_length_is_413():
    c = make_client(max_body_size=1024)
    r = c.post("/echo", content=b"x" * 2048, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_oversize_streamed_without_content_length_is_413():
    def gen():
        for _ in range(4):
            yield b"x" * 512

    c = make_client(max_body_size=1024)
    r = c.post("/echo", content=gen(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_text_plain_attack_is_blocked():
    # Regresión del bypass por content-type: request.json() parsea un text/plain
    # igual que el atacante sabe, así que el middleware también lo inspecciona.
    r = make_client().post("/echo", content="<script>x</script>",
                           headers={"content-type": "text/plain"})
    assert r.status_code == 403


def test_multipart_is_passed_through():
    r = make_client().post("/echo", files={"f": ("a.txt", b"<script>x</script>")})
    assert r.status_code == 200


def test_malformed_json_with_attack_is_blocked_by_raw_scan():
    r = make_client().post("/echo", content=b'{"a": "<script>"',
                           headers={"content-type": "application/json"})
    assert r.status_code == 403


def test_malformed_benign_json_reaches_app():
    r = make_client().post("/echo", content=b'{"a": ',
                           headers={"content-type": "application/json"})
    assert r.status_code == 200


def test_extract_strings_can_omit_json_keys_for_cross_carrier_scanning():
    from gatekeeper.body import extract_strings

    body = b'{"select": "password from users"}'
    assert extract_strings("application/json", body, include_keys=False) == [
        ("/select", "password from users")
    ]


def test_extract_strings_and_values_reuses_parsed_body_fields():
    from gatekeeper.body import extract_strings_and_values

    body = b'{"select": "password from users"}'
    assert extract_strings_and_values("application/json", body) == (
        [("/select", "select"), ("/select", "password from users")],
        [("/select", "password from users")],
    )


def test_deeply_nested_json_does_not_crash():
    body = b"[" * 5000 + b"]" * 5000
    r = make_client().post("/echo", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200


def test_allow_path_skips_all_inspection():
    c = make_client(allow_paths=["/docs"])
    assert c.post("/docs", json={"q": "<script>x</script>"}).status_code == 200
    assert c.post("/echo", json={"q": "<script>x</script>"}).status_code == 403


def test_body_inspection_can_be_disabled():
    r = make_client(inspect_body=False).post("/echo", json={"q": "<script>x</script>"})
    assert r.status_code == 200


def test_audit_log_never_contains_payload(caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        make_client().post("/echo", json={"q": "1 UNION SELECT secret_column FROM users"})
    assert "attack_detected" in caplog.text
    assert '"source": "body"' in caplog.text
    assert "secret_column" not in caplog.text
