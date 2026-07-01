"""Phase 3: read-side isolation, endpoint gating, and the /compare leaderboard."""
import re
from datetime import datetime, timedelta


def _recent(offsets_secs):
    """ISO timestamps a few seconds in the past, so they fall inside the
    leaderboard's 24h window regardless of the wall clock."""
    now = datetime.now()
    return [(now - timedelta(seconds=s)).isoformat() for s in offsets_secs]


def _user_client(mt, post_form, email, handle):
    c = mt.app.test_client()
    post_form(c, "/register", {"email": email, "handle": handle,
                               "password": "hunter2hunter", "code": "letmein"})
    return c


def _token(mt, post_form, client, host):
    r = post_form(client, "/machines", {"monitor_host": host, "label": ""})
    return re.search(rb"INGEST_API_KEY=(\S+)", r.data).group(1).decode()


def _ingest(mt, token, pings):
    return mt.app.test_client().post(
        "/api/ingest", json={"ping_samples": pings},
        headers={"Authorization": f"Bearer {token}"})


def test_compare_leaderboard(mt, post_form):
    alice = _user_client(mt, post_form, "a@b.com", "Alice")
    tok = _token(mt, post_form, alice, "mbp")
    t0, t1, t2 = _recent([30, 20, 10])
    # 2 good pings + 1 failed → uptime 66.7%
    assert _ingest(mt, tok, [[t0, 10.0], [t1, None], [t2, 20.0]]).status_code == 200
    board = alice.get("/api/compare").get_json()["hosts"]
    assert len(board) == 1
    row = board[0]
    assert row["handle"] == "Alice" and row["machine"] == "mbp"
    assert row["is_you"] is True
    assert row["uptime_pct"] == 66.7
    assert row["ping_p50"] is not None


def test_compare_sees_group_but_metrics_are_safe(mt, post_form):
    alice = _user_client(mt, post_form, "a@b.com", "Alice")
    bob = _user_client(mt, post_form, "b@c.com", "Bob")
    (ta,) = _recent([15])
    _ingest(mt, _token(mt, post_form, alice, "mbp-a"), [[ta, 10.0]])
    _ingest(mt, _token(mt, post_form, bob, "mbp-b"), [[ta, 50.0]])
    # Everyone sees the whole group on the leaderboard...
    board = bob.get("/api/compare").get_json()["hosts"]
    handles = {r["handle"] for r in board}
    assert handles == {"Alice", "Bob"}
    # ...but only safe aggregate fields are exposed (no fingerprints/labels/etc).
    allowed = {"handle", "machine", "is_you", "last_seen", "uptime_pct",
               "ping_p50", "ping_p90", "download_mbps", "upload_mbps",
               "outages", "samples"}
    for r in board:
        assert set(r) <= allowed


def test_state_isolation_across_users(mt, post_form):
    alice = _user_client(mt, post_form, "a@b.com", "Alice")   # id 1
    bob = _user_client(mt, post_form, "b@c.com", "Bob")       # id 2
    (ta,) = _recent([15])
    _ingest(mt, _token(mt, post_form, alice, "mbp"), [[ta, 10.0]])
    # Bob cannot read Alice's namespaced host.
    assert bob.get("/api/state?host=1:mbp").status_code == 404
    # Bob's own hosts list doesn't include Alice's machine.
    bob_hosts = [h["monitor_host"] for h in bob.get("/api/hosts").get_json()["hosts"]]
    assert all(not h.startswith("1:") for h in bob_hosts)


def test_state_endpoints_gated_in_mt(mt, post_form):
    c = _user_client(mt, post_form, "a@b.com", "Alice")
    for path in ("/log", "/api/log", "/api/site_history?host=x",
                 "/api/timeline", "/api/diagnoses", "/diagnose"):
        assert c.get(path).status_code == 404, path
    # Mutating _state endpoints are gated too.
    assert c.post("/api/dismiss", json={"outage_id": "x"}).status_code == 404
    assert c.delete("/api/diagnoses/abc").status_code == 404


def test_root_redirects_to_compare(mt, post_form):
    c = _user_client(mt, post_form, "a@b.com", "Alice")
    r = c.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/compare")
