"""Multi-tenant account + auth-guard tests, driven through Flask's test client.

These promote the manual smoke checks used while building Phase 1 into a
repeatable suite. They spin up no threads and touch no network — the module is
imported (which builds the Flask app) but main() is never called.
"""
import importlib

import pytest


@pytest.fixture
def mt(tmp_path):
    """connection_monitor configured in multi-tenant mode against a temp DB."""
    m = importlib.import_module("connection_monitor")
    m._db = m.db.Storage(str(tmp_path / "test.db"))
    m._db.init_schema()
    # Flip the module-level flags the request path reads. before_request and the
    # auth routes consult these globals live, so mutating them here is enough.
    m.MULTI_TENANT = True
    m.SIGNUP_CODE = "letmein"
    m._init_session_secret()
    return m


def _register(client, **over):
    data = {"email": "a@b.com", "handle": "Alice",
            "password": "hunter2hunter", "code": "letmein"}
    data.update(over)
    return client.post("/register", data=data)


# ── DB layer ────────────────────────────────────────────────────────────────
def test_user_crud(tmp_path):
    from lib import db
    s = db.Storage(str(tmp_path / "u.db"))
    s.init_schema()
    assert s.count_users() == 0
    uid = s.create_user("a@b.com", "hash", "Alice", is_admin=True)
    assert uid == 1
    assert s.create_user("a@b.com", "other", "Dup") is None   # UNIQUE email
    assert s.count_users() == 1
    u = s.get_user_by_email("a@b.com")
    assert u["handle"] == "Alice" and u["is_admin"] == 1
    assert s.get_user_by_id(uid)["email"] == "a@b.com"
    assert s.get_user_by_email("nobody@x.com") is None


# ── Auth guard ────────────────────────────────────────────────────────────────
def test_page_requires_login(mt):
    r = mt.app.test_client().get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_api_requires_login(mt):
    r = mt.app.test_client().get("/api/state")
    assert r.status_code == 401 and r.get_json()["error"] == "login required"


def test_healthz_and_ingest_bypass_session(mt):
    c = mt.app.test_client()
    assert c.get("/healthz").status_code == 200
    # Ingest is exempt from the login-session guard: an unauthenticated call
    # gets the token-auth 401 (JSON), not a 302 redirect to /login.
    r = c.post("/api/ingest", json={})
    assert r.status_code == 401
    assert r.get_json()["error"] == "missing API token"


# ── Registration + login flow ────────────────────────────────────────────────
def test_register_validation(mt):
    c = mt.app.test_client()
    assert b"Invalid invite code" in _register(c, code="nope").data
    assert b"at least 8" in _register(c, password="short").data
    assert b"valid email" in _register(c, email="notanemail").data


def test_register_login_logout(mt):
    c = mt.app.test_client()
    r = _register(c)
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert c.get("/").status_code == 200            # session established
    assert mt._db.get_user_by_email("a@b.com")["is_admin"] == 1  # first = admin

    c.get("/logout")
    assert c.get("/").status_code == 302            # session cleared

    assert b"Invalid email or password" in c.post(
        "/login", data={"email": "a@b.com", "password": "WRONG"}).data
    r = c.post("/login", data={"email": "a@b.com", "password": "hunter2hunter"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_second_user_not_admin(mt):
    c = mt.app.test_client()
    _register(c)                                     # Alice (admin)
    c.get("/logout")
    _register(c, email="b@c.com", handle="Bob")
    assert mt._db.get_user_by_email("b@c.com")["is_admin"] == 0
