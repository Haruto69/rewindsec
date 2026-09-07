"""Batch 6 production routing, provenance, and low-end projection checks."""

import ast
import os
import pathlib
import subprocess
import sys

from rewindsec.workstation.projection import (MAX_RENDERED_MESSAGE_ENTRIES,
                                              MAX_RENDERED_NOTIFICATIONS)

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_rewindsec2_never_imports_historical_study_learning_scenario_or_evaluation():
    forbidden = ("study", "learning", "scenario_adapters", "evaluation", "sandbox")
    for path in (ROOT / "rewindsec").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module)
        # ``rewindsec.sandbox`` is the new v2 boundary; only a top-level
        # historical ``sandbox`` import is forbidden.
        assert not any(name == prefix or name.startswith(prefix + ".")
                       for name in names for prefix in forbidden), str(path)


def test_normal_app_does_not_mount_obsolete_v1_learner_routes():
    script = r'''
import os, re
os.environ["SIMULATOR_DATABASE_URI"] = "sqlite:///:memory:"
os.environ["FLASK_SECRET_KEY"] = "batch6-route-test"
os.environ["REWINDSEC2_SANDBOX_ENABLED"] = "0"
os.environ.pop("REWINDSEC_ENABLE_LEGACY_V1_SURFACES", None)
import app
c = app.app.test_client()
for path in ("/training", "/training/phishing", "/study", "/resources", "/sandbox/status"):
    print(path, c.get(path).status_code)
print("root", c.get("/").status_code, c.get("/").headers.get("Location", ""))
print("instructor-login", c.get("/instructor/login").status_code)
page = c.get("/start")
token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page.data).group(1).decode()
print("dev", c.post("/api/dev/engine", json={},
                    headers={"X-CSRF-Token": token}).status_code)
'''
    env = dict(os.environ)
    env.pop("REWINDSEC_ENABLE_LEGACY_V1_SURFACES", None)
    env.pop("REWINDSEC2_ENABLE_DEVELOPMENT_TOOLS", None)
    result = subprocess.run([sys.executable, "-c", script], cwd=str(ROOT),
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "/training 404" in result.stdout
    assert "/study 404" in result.stdout
    assert "/resources 404" in result.stdout
    assert "/sandbox/status 404" in result.stdout
    assert "root 302 /start" in result.stdout
    assert "instructor-login 308" in result.stdout
    assert "dev 404" in result.stdout


def test_low_end_projection_bounds_are_explicit_and_nonzero():
    assert MAX_RENDERED_NOTIFICATIONS == 100
    assert MAX_RENDERED_MESSAGE_ENTRIES == 200


def test_static_client_uses_sse_and_has_reduced_motion_support():
    js = (ROOT / "static/prototype/workstation.js").read_text(encoding="utf-8")
    css = "\n".join(path.read_text(encoding="utf-8")
                    for path in (ROOT / "static/prototype").glob("*.css"))
    assert "new window.EventSource" in js
    assert "WebGL" not in js and "three.js" not in js.lower()
    assert "prefers-reduced-motion: reduce" in css
