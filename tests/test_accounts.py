"""Multi-tenant account + auth-guard tests, driven through Flask's test client."""


def _register(post_form, client, **over):
    data = {"email": "a@b.com", "handle": "Alice",
            "password": "hunter2hunter", "code": "letmein"}
    data.update(over)
    return post_form(client, "/register", data)


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
    r = mt.app.test_client().get("/compare")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_api_requires_login(mt):
    r = mt.app.test_client().get("/api/state")
    assert r.status_code == 401 and r.get_json()["error"] == "login required"


def test_healthz_and_ingest_bypass_session(mt):
    c = mt.app.test_client()
    assert c.get("/healthz").status_code == 200
    r = c.post("/api/ingest", json={})
    assert r.status_code == 401
    assert r.get_json()["error"] == "missing API token"


# ── Registration + login flow ────────────────────────────────────────────────
def test_register_validation(mt, post_form):
    c = mt.app.test_client()
    assert b"Invalid invite code" in _register(post_form, c, code="nope").data
    assert b"at least 8" in _register(post_form, c, password="short").data
    assert b"valid email" in _register(post_form, c, email="notanemail").data


def test_register_login_logout(mt, post_form):
    c = mt.app.test_client()
    r = _register(post_form, c)
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert c.get("/compare").status_code == 200        # session established
    assert mt._db.get_user_by_email("a@b.com")["is_admin"] == 1  # first = admin

    c.get("/logout")
    assert c.get("/compare").status_code == 302        # session cleared

    assert b"Invalid email or password" in post_form(
        c, "/login", {"email": "a@b.com", "password": "WRONG"}).data
    r = post_form(c, "/login", {"email": "a@b.com", "password": "hunter2hunter"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_second_user_not_admin(mt, post_form):
    c = mt.app.test_client()
    _register(post_form, c)                            # Alice (admin)
    c.get("/logout")
    _register(post_form, c, email="b@c.com", handle="Bob")
    assert mt._db.get_user_by_email("b@c.com")["is_admin"] == 0


def test_csrf_required(mt):
    c = mt.app.test_client()
    c.get("/login")   # seed a session CSRF token
    # POST without the token is rejected.
    r = c.post("/register", data={"email": "a@b.com", "handle": "A",
                                  "password": "hunter2hunter", "code": "letmein"})
    assert r.status_code == 400
