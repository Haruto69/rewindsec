"""Final productization checks for the normal RewindSec 2.0 web surface.

The historical suite deliberately mounts the preserved v1 application and the
``/prototype`` prefix.  These checks start a clean process with those switches
absent, so they exercise the routes and copy a real deployment receives.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

from tests.conftest import csrf_for


REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOTYPE_TEMPLATES = REPO_ROOT / "templates" / "prototype"
PROTOTYPE_STATIC = REPO_ROOT / "static" / "prototype"

CANONICAL_PAGES = {
    "/start", "/workstation", "/results", "/trainer", "/trainer/login",
    "/trainer/students", "/trainer/groups", "/trainer/assessments",
}
CANONICAL_APIS = {
    "/api/me", "/api/enroll", "/api/assessments", "/api/session/start",
    "/api/session", "/api/actions", "/api/session/end",
    "/api/session/debrief", "/api/events", "/api/trainer/students",
    "/api/trainer/groups", "/api/trainer/assessments",
    "/api/trainer/assignments",
}


@pytest.fixture(scope="module")
def production_probe(tmp_path_factory):
    root = tmp_path_factory.mktemp("product-web")
    probe = textwrap.dedent(r"""
        import html
        import json
        import re

        import app as app_module
        from security import INSTRUCTOR_SESSION_KEY

        app = app_module.app
        app.config["TESTING"] = True
        client = app.test_client()

        def visible_text(body):
            body = re.sub(r"<!--.*?-->", " ", body, flags=re.I | re.S)
            body = re.sub(r"<(script|style)\b.*?</\1>", " ", body,
                          flags=re.I | re.S)
            body = re.sub(r"<[^>]+>", " ", body)
            return " ".join(html.unescape(body).split()).lower()

        result = {"routes": sorted(rule.rule for rule in app.url_map.iter_rules())}
        root_response = client.get("/")
        result["root"] = [root_response.status_code,
                          root_response.headers.get("Location")]
        legacy = client.get("/prototype/start?mode=simulation")
        result["legacy_browser"] = [legacy.status_code,
                                    legacy.headers.get("Location")]

        canonical_me = client.get("/api/me")
        legacy_me = client.get("/prototype/api/me")
        result["api_alias"] = [canonical_me.status_code,
                               legacy_me.status_code,
                               canonical_me.get_json() == legacy_me.get_json()]

        start = client.get("/start")
        token = re.search(
            rb'name="csrf-token" content="([^"]+)"', start.data).group(1).decode()
        headers = {"Accept": "application/json", "X-CSRF-Token": token}
        result["dev_disabled"] = [
            client.post("/api/dev/engine", json={}, headers=headers).status_code,
            client.post("/prototype/api/dev/engine", json={},
                        headers=headers).status_code,
        ]

        bodies = {
            "/start": start.data.decode(),
            "/workstation": client.get("/workstation").data.decode(),
            "/results": client.get("/results").data.decode(),
            "/trainer/login": client.get("/trainer/login").data.decode(),
        }
        missing = client.get("/not-a-product-route")
        result["not_found"] = [missing.status_code,
                               "prototype/trainer.css" in missing.data.decode(),
                               "/start" in missing.data.decode()]
        bodies["/not-a-product-route"] = missing.data.decode()
        with client.session_transaction() as session:
            session[INSTRUCTOR_SESSION_KEY] = True
        for path in ("/trainer", "/trainer/students", "/trainer/groups",
                     "/trainer/assessments"):
            response = client.get(path)
            result.setdefault("page_status", {})[path] = response.status_code
            bodies[path] = response.data.decode()

        result["page_status"] = {
            **{path: 200 for path in ("/start", "/workstation", "/results",
                                     "/trainer/login")},
            **result.get("page_status", {}),
        }
        forbidden = re.compile(
            r"\b(prototype|demo|fixture|debug)\b|developer tools", re.I)
        result["visible_cues"] = {
            path: sorted(set(match.group(0).lower()
                             for match in forbidden.finditer(visible_text(body))))
            for path, body in bodies.items()
        }
        result["legacy_links"] = {
            path: re.findall(r"(?:href|action)=[\"']/prototype(?:[/\"'])",
                             body, flags=re.I)
            for path, body in bodies.items()
        }
        print("PRODUCT_PROBE=" + json.dumps(result, sort_keys=True))
    """)
    env = os.environ.copy()
    env.pop("REWINDSEC_ENABLE_LEGACY_V1_SURFACES", None)
    env.pop("REWINDSEC2_ENABLE_DEVELOPMENT_TOOLS", None)
    env.update({
        "SIMULATOR_DATABASE_URI": "sqlite:///" + str(root / "app.db").replace("\\", "/"),
        "SANDBOX_LOCAL_ROOT": str(root / "sandboxes"),
        "SANDBOX_BACKEND": "local",
        "REWINDSEC2_SANDBOX_ENABLED": "0",
        "FLASK_SECRET_KEY": "productization-test-secret",
        "SYNTHETIC_IDENTITY_SECRET": "productization-test-identity",
        "INSTRUCTOR_PASSWORD": "productization-test-password",
    })
    completed = subprocess.run(
        [sys.executable, "-c", probe], cwd=str(REPO_ROOT), env=env,
        capture_output=True, text=True, timeout=90, check=True)
    line = next(line for line in completed.stdout.splitlines()
                if line.startswith("PRODUCT_PROBE="))
    return json.loads(line.split("=", 1)[1])


def test_normal_deployment_owns_the_clean_public_route_map(production_probe):
    routes = set(production_probe["routes"])
    assert CANONICAL_PAGES <= routes
    assert CANONICAL_APIS <= routes
    assert production_probe["root"] == [302, "/start"]


def test_historical_browser_urls_canonicalize_but_api_aliases_keep_working(
        production_probe):
    assert production_probe["legacy_browser"] == [
        308, "/start?mode=simulation"]
    assert production_probe["api_alias"] == [200, 200, True]


def test_development_apis_are_unavailable_by_default(production_probe):
    assert production_probe["dev_disabled"] == [404, 404]


def test_normal_pages_render_as_product_surfaces(production_probe):
    assert production_probe["page_status"] == {
        path: 200 for path in CANONICAL_PAGES
    }
    assert all(not cues for cues in production_probe["visible_cues"].values())
    assert all(not links for links in production_probe["legacy_links"].values())


def test_product_404_uses_the_current_design_and_navigation(production_probe):
    assert production_probe["not_found"] == [404, True, True]


def test_trainer_login_uses_the_product_shell_and_normal_password_input(client):
    response = client.get("/trainer/login")
    body = response.data.decode()
    assert response.status_code == 200
    assert "Trainer login" in body
    assert "prototype/base.css" in body and "prototype/trainer.css" in body
    assert "rewindsec.css" not in body
    assert 'autocomplete="current-password"' in body
    assert 'data-integrity="none"' in body
    assert "prototype/integrity.js" not in body
    assert 'action="/trainer/login"' in body


def test_trainer_login_has_specific_error_and_unconfigured_states(
        client, monkeypatch):
    import security

    security.login_throttle.reset()
    refused = client.post(
        "/trainer/login",
        data={"password": "wrong", "csrf_token": csrf_for(client)},
        environ_base={"REMOTE_ADDR": "192.0.2.40"})
    assert refused.status_code == 401
    assert b"Sign-in failed" in refused.data
    assert b"Incorrect password." in refused.data

    monkeypatch.delenv("INSTRUCTOR_PASSWORD", raising=False)
    unavailable = client.get("/trainer/login")
    assert unavailable.status_code == 200
    assert b"Login unavailable" in unavailable.data
    assert b"has not been enabled for this deployment" in unavailable.data
    assert b'disabled aria-disabled="true"' in unavailable.data
    security.login_throttle.reset()


def test_historical_login_get_redirects_to_the_canonical_surface(client):
    response = client.get("/instructor/login")
    assert response.status_code == 308
    assert response.headers["Location"].startswith("/trainer/login")


def test_enrollment_input_is_paste_and_password_manager_friendly():
    source = (PROTOTYPE_TEMPLATES / "entry.html").read_text(encoding="utf-8")
    field = source.split('id="pw-enrol-code"', 1)[1].split(">", 1)[0]
    assert 'autocomplete="one-time-code"' in field
    assert 'autocapitalize="none"' in field
    assert 'spellcheck="false"' in field
    assert ".trim()" in source


def test_clipboard_restriction_is_scoped_to_the_active_simulation():
    source = (PROTOTYPE_STATIC / "integrity.js").read_text(encoding="utf-8")
    assert "data-integrity') !== 'simulation'" in source
    assert "['copy', 'cut', 'paste'].forEach" in source
    base = (PROTOTYPE_TEMPLATES / "_base.html").read_text(encoding="utf-8")
    assert "integrity_scope|default('none') == 'simulation'" in base


def test_trainer_copy_code_is_progressive_and_copies_only_the_code():
    source = (PROTOTYPE_TEMPLATES / "trainer_students.html").read_text(
        encoding="utf-8")
    handler = source.split("copy.addEventListener('click'", 1)[1].split(
        "button.hidden = true", 1)[0]
    assert "var value = code.textContent;" in handler
    assert "navigator.clipboard.writeText(value)" in handler
    assert "document.execCommand('copy')" in handler
    assert "range.selectNodeContents(code)" in handler
    assert "copy.textContent = 'Copied'" in handler
    for forbidden in ("fetch(", "telemetry", "studentId", "learner", "session"):
        assert forbidden not in handler


def test_product_scripts_use_canonical_operational_urls():
    sources = [
        (PROTOTYPE_STATIC / name).read_text(encoding="utf-8")
        for name in ("workstation.js", "results.js", "trainer.js")
    ]
    sources.append((PROTOTYPE_TEMPLATES / "entry.html").read_text(
        encoding="utf-8"))
    operational = re.compile(
        r"(?:fetch|request|get|post|EventSource)\(\s*['\"]/prototype|"
        r"location\.href\s*=\s*['\"]/prototype")
    for source in sources:
        assert not operational.search(source)
