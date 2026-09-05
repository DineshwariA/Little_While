import os
import uuid
import datetime as dt
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
TEST_EMAIL = "littlewhile.test@example.com"
TEST_PASSWORD = "LittleWhile123!"


def _register_or_login(session: requests.Session, email: str, password: str, name: str = "Test User"):
    r = session.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password})
    if r.status_code != 200:
        r = session.post(f"{BASE_URL}/api/auth/register", json={"email": email, "password": password, "display_name": name})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def user_a():
    s = requests.Session()
    _register_or_login(s, TEST_EMAIL, TEST_PASSWORD)
    return s


@pytest.fixture
def user_b():
    s = requests.Session()
    email = f"TEST_{uuid.uuid4().hex[:8]}@example.com"
    _register_or_login(s, email, "TestPass123!", "TEST User B")
    return s, email


def test_calendar_requires_auth():
    r = requests.get(f"{BASE_URL}/api/sessions/calendar", params={"year": 2026, "month": 1})
    assert r.status_code == 401


def test_calendar_returns_current_month_shape(user_a):
    today = dt.date.today()
    r = user_a.get(f"{BASE_URL}/api/sessions/calendar", params={"year": today.year, "month": today.month})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["month"] == f"{today.year:04d}-{today.month:02d}"
    assert "timezone" in data and "today" in data and isinstance(data["days"], list)


def test_calendar_invalid_month(user_a):
    r = user_a.get(f"{BASE_URL}/api/sessions/calendar", params={"year": 2026, "month": 13})
    assert r.status_code == 422


def test_calendar_reflects_completed_session(user_a):
    # Start + finish a session
    activities = user_a.get(f"{BASE_URL}/api/activities").json()
    assert activities
    activity = activities[0]
    started = user_a.post(f"{BASE_URL}/api/sessions/start", json={"activity_id": activity["id"], "planned_duration": 5})
    assert started.status_code == 200
    sid = started.json()["id"]
    fin = user_a.post(f"{BASE_URL}/api/sessions/{sid}/finish",
                      json={"outcome": "completed", "notes": "TEST_calendar_note", "continued": ""})
    assert fin.status_code == 200

    today = dt.date.today()
    r = user_a.get(f"{BASE_URL}/api/sessions/calendar", params={"year": today.year, "month": today.month})
    assert r.status_code == 200
    data = r.json()
    today_key = data["today"]
    matches = [d for d in data["days"] if d["date"] == today_key]
    assert matches, f"today {today_key} missing in days={[d['date'] for d in data['days']]}"
    day = matches[0]
    assert day["total_minutes"] >= 1
    assert any(s["title"] == activity["title"] for s in day["sessions"])
    assert any(s.get("notes") == "TEST_calendar_note" for s in day["sessions"])
    assert len(day["categories"]) >= 1


def test_calendar_privacy_between_users(user_a, user_b):
    b_session, b_email = user_b
    today = dt.date.today()
    # User A has data from previous test scope-wise? Fresh function scope — create one for A
    acts = user_a.get(f"{BASE_URL}/api/activities").json()
    started = user_a.post(f"{BASE_URL}/api/sessions/start", json={"activity_id": acts[0]["id"], "planned_duration": 3})
    if started.status_code == 200:
        sid = started.json()["id"]
        user_a.post(f"{BASE_URL}/api/sessions/{sid}/finish", json={"outcome": "completed", "notes": "TEST_priv", "continued": ""})
    r_b = b_session.get(f"{BASE_URL}/api/sessions/calendar", params={"year": today.year, "month": today.month})
    assert r_b.status_code == 200
    for d in r_b.json()["days"]:
        for s in d["sessions"]:
            assert s.get("notes") != "TEST_priv"


def test_regression_dashboard_and_activities(user_a):
    assert user_a.get(f"{BASE_URL}/api/activities").status_code == 200
    assert user_a.get(f"{BASE_URL}/api/dashboard").status_code == 200
    assert user_a.get(f"{BASE_URL}/api/auth/me").status_code == 200
