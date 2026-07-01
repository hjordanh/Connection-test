"""Shared pytest fixtures for the multi-tenant server tests.

The module is imported once (which builds the Flask app); main() is never
called, so no probe threads or network activity start.
"""
import importlib
import re

import pytest


@pytest.fixture
def mt(tmp_path):
    """connection_monitor configured in multi-tenant mode against a temp DB."""
    m = importlib.import_module("connection_monitor")
    m._db = m.db.Storage(str(tmp_path / "test.db"))
    m._db.init_schema()
    # These module globals are read live by the request path.
    m.MULTI_TENANT = True
    m.SIGNUP_CODE = "letmein"
    m.INGEST_MIN_INTERVAL_S = 20
    m._init_session_secret()
    return m


@pytest.fixture
def post_form():
    """POST a form with the session's CSRF token auto-attached.

    Seeds the token from /login (which any client can GET) unless the caller
    already supplied one.
    """
    def _post(client, url, data=None):
        d = dict(data or {})
        if "csrf" not in d:
            # The CSRF token is per-session and stable. Probe a page that
            # renders a form for this client's auth state: /machines when
            # logged in, /login when anonymous.
            token = None
            for probe in ("/machines", "/login"):
                m = re.search(rb'name="csrf" value="([^"]+)"', client.get(probe).data)
                if m:
                    token = m.group(1).decode()
                    break
            assert token, "no CSRF token found"
            d["csrf"] = token
        return client.post(url, data=d)
    return _post
