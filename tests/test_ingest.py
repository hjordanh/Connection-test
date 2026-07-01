"""Phase 2: per-agent tokens + owner-bound ingest."""
import hashlib
import importlib
import re

import pytest


@pytest.fixture
def mt(tmp_path):
    m = importlib.import_module("connection_monitor")
    m._db = m.db.Storage(str(tmp_path / "test.db"))
    m._db.init_schema()
    m.MULTI_TENANT = True
    m.SIGNUP_CODE = "letmein"
    m.INGEST_MIN_INTERVAL_S = 20
    m._init_session_secret()
    return m


def _signup(m, email="a@b.com", handle="Alice"):
    """Register (and log in) a user; returns an authenticated client."""
    c = m.app.test_client()
    c.post("/register", data={"email": email, "handle": handle,
                              "password": "hunter2hunter", "code": "letmein"})
    return c


def _make_token(client, host="jordans-mbp", label="home"):
    """Create a machine token via /machines and scrape the one-time value."""
    r = client.post("/machines", data={"monitor_host": host, "label": label})
    m = re.search(rb"INGEST_API_KEY=(\S+)", r.data)
    assert m, "token not shown on machines page"
    return m.group(1).decode()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


PING = {"ping_samples": [["2026-01-01T00:00:00", 12.3]]}


def test_token_issue_and_ingest(mt):
    c = _signup(mt)
    token = _make_token(c, host="mbp1")
    r = mt.app.test_client().post("/api/ingest", json=PING, headers=_auth(token))
    assert r.status_code == 200
    # Stored host is namespaced under the owner's user id, not client-supplied.
    user = mt._db.get_user_by_email("a@b.com")
    hosts = [h["monitor_host"] for h in mt._db.load_hosts()]
    assert f'{user["id"]}:mbp1' in hosts


def test_owner_binding_ignores_body_host(mt):
    c = _signup(mt)
    token = _make_token(c, host="mbp1")
    # Attacker-style body trying to write as someone else — must be ignored.
    payload = dict(PING, monitor_host="99:victim")
    r = mt.app.test_client().post("/api/ingest", json=payload, headers=_auth(token))
    assert r.status_code == 200
    user = mt._db.get_user_by_email("a@b.com")
    hosts = [h["monitor_host"] for h in mt._db.load_hosts()]
    assert f'{user["id"]}:mbp1' in hosts
    assert "99:victim" not in hosts


def test_missing_and_bad_token(mt):
    cli = mt.app.test_client()
    assert cli.post("/api/ingest", json=PING).status_code == 401
    assert cli.post("/api/ingest", json=PING,
                    headers=_auth("not-a-real-token")).status_code == 401


def test_revoked_token_rejected(mt):
    c = _signup(mt)
    token = _make_token(c, host="mbp1")
    assert mt.app.test_client().post("/api/ingest", json=PING,
                                     headers=_auth(token)).status_code == 200
    # Revoke the (only) token, then a fresh push must fail.
    user = mt._db.get_user_by_email("a@b.com")
    tid = mt._db.list_agent_tokens(user["id"])[0]["id"]
    c.post(f"/machines/{tid}/revoke")
    r = mt.app.test_client().post("/api/ingest", json=PING, headers=_auth(token))
    assert r.status_code == 401


def test_malformed_payload_400(mt):
    c = _signup(mt)
    token = _make_token(c, host="mbp1")
    # site_samples must be an object, not a list.
    r = mt.app.test_client().post("/api/ingest", json={"site_samples": []},
                                  headers=_auth(token))
    assert r.status_code == 400


def test_rate_limit(mt):
    c = _signup(mt)
    token = _make_token(c, host="mbp1")
    cli = mt.app.test_client()
    assert cli.post("/api/ingest", json=PING, headers=_auth(token)).status_code == 200
    # Immediate second push is under the min interval → throttled.
    assert cli.post("/api/ingest", json=PING, headers=_auth(token)).status_code == 429


def test_cross_user_revoke_denied(mt):
    s = mt._db
    a = s.create_user("a@b.com", "h", "Alice")
    b = s.create_user("b@c.com", "h", "Bob")
    tid = s.create_agent_token(a, "mbp", hashlib.sha256(b"x").hexdigest())
    # Bob cannot revoke Alice's token; Alice can.
    assert s.revoke_agent_token(tid, b) is False
    assert s.revoke_agent_token(tid, a) is True
