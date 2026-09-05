import os
import uuid
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")


@pytest.fixture
def client():
    return requests.Session()


def test_auth_and_starter_data(client):
    email = f"TEST_{uuid.uuid4().hex}@example.com"
    response = client.post(f"{BASE_URL}/api/auth/register", json={"email": email, "password": "TestPass123!", "display_name": "Test Person"})
    assert response.status_code == 200
    assert response.json()["email"] == email.lower()
    assert "access_token" in client.cookies and "refresh_token" in client.cookies
    assert client.get(f"{BASE_URL}/api/auth/me").json()["email"] == email.lower()
    activities = client.get(f"{BASE_URL}/api/activities")
    assert activities.status_code == 200 and len(activities.json()) >= 8


def test_login_logout_and_google_setup(client):
    response = client.post(f"{BASE_URL}/api/auth/login", json={"email": "littlewhile.test@example.com", "password": "LittleWhile123!"})
    assert response.status_code == 200
    assert client.post(f"{BASE_URL}/api/auth/google").status_code == 501
    assert client.post(f"{BASE_URL}/api/auth/logout").json()["ok"] is True
    assert client.get(f"{BASE_URL}/api/auth/me").status_code == 401


def test_activity_session_pause_finish_and_stats(client):
    login = client.post(f"{BASE_URL}/api/auth/login", json={"email": "littlewhile.test@example.com", "password": "LittleWhile123!"})
    assert login.status_code == 200
    activity = client.get(f"{BASE_URL}/api/activities").json()[0]
    started = client.post(f"{BASE_URL}/api/sessions/start", json={"activity_id": activity["id"], "planned_duration": 5})
    assert started.status_code == 200 and started.json()["outcome"] == "active"
    sid = started.json()["id"]
    paused = client.patch(f"{BASE_URL}/api/sessions/{sid}/pause", json={"paused": True})
    assert paused.status_code == 200 and paused.json()["paused_at"]
    resumed = client.patch(f"{BASE_URL}/api/sessions/{sid}/pause", json={"paused": False})
    assert resumed.status_code == 200 and resumed.json()["paused_at"] is None
    finished = client.post(f"{BASE_URL}/api/sessions/{sid}/finish", json={"outcome": "completed", "notes": "TEST_note", "continued": "TEST_next"})
    assert finished.status_code == 200 and finished.json()["outcome"] == "completed"
    dashboard = client.get(f"{BASE_URL}/api/dashboard").json()
    assert dashboard["stats"]["total_sessions"] >= 1
