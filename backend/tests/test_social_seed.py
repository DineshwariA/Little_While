"""Backend regression tests for the 50 Social starter-activities addition.

Covers:
- Auth flow (register / login / /auth/me) regression
- Fresh-user seeding counts: 408 total with per-category distribution
- Social titles unique + duration coverage {5,10,20,30} minimum
- Existing-user seeding is idempotent (re-login does not re-seed)
- GET /api/activities returns all 408 (previous cap was 200; now to_list(2000))
- Custom activity creation via POST /api/activities appears in GET
- PATCH /api/activities/{id}/favorite toggles favorite flag
"""
import os
import time
import uuid
import requests
import pytest
from collections import Counter

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        v = line.split("=", 1)[1].strip()
                        break
        except FileNotFoundError:
            pass
    assert v, "REACT_APP_BACKEND_URL missing"
    return v.rstrip("/")


BASE_URL = _load_backend_url()
API = f"{BASE_URL}/api"

EXPECTED_COUNTS = {
    "Creativity": 51,
    "Learning": 51,
    "Coding / Building": 51,
    "Reading": 51,
    "Wellness": 51,
    "Movement": 51,
    "Brain Gym": 51,
    "Social": 50,
    "Everyday Life": 51,
    "Personal Growth": 50,
}
EXPECTED_TOTAL = sum(EXPECTED_COUNTS.values())  # 508


def _new_email():
    return f"test-social-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}@example.com"


@pytest.fixture(scope="module")
def fresh_session():
    s = requests.Session()
    email = _new_email()
    password = "TestPass123!"
    r = s.post(f"{API}/auth/register",
               json={"email": email, "password": password, "display_name": "Social Tester"})
    assert r.status_code == 200, f"register failed: {r.status_code} {r.text}"
    return {"session": s, "email": email, "password": password, "user": r.json()}


@pytest.fixture(scope="module")
def persistent_session():
    """Login the pre-existing test account from test_credentials.md."""
    s = requests.Session()
    r = s.post(f"{API}/auth/login",
               json={"email": "littlewhile.test@example.com", "password": "LittleWhile123!"})
    if r.status_code != 200:
        pytest.skip(f"persistent test account login failed: {r.status_code} {r.text}")
    return s


# ---------- Auth regression ----------
class TestAuthRegression:
    def test_register_returns_user_and_sets_cookie(self, fresh_session):
        u = fresh_session["user"]
        assert "id" in u and u["email"] == fresh_session["email"]
        # Auth cookie should be set
        cookies = fresh_session["session"].cookies
        assert any(c.name == "access_token" for c in cookies), f"cookies: {list(cookies)}"

    def test_auth_me_returns_current_user(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/auth/me")
        assert r.status_code == 200, r.text
        assert r.json()["email"] == fresh_session["email"]

    def test_login_existing_account_works(self, fresh_session):
        s = requests.Session()
        r = s.post(f"{API}/auth/login",
                   json={"email": fresh_session["email"], "password": fresh_session["password"]})
        assert r.status_code == 200, r.text
        assert r.json()["email"] == fresh_session["email"]


# ---------- Seeding ----------
class TestFreshUserSeeding:
    def test_total_and_per_category_counts(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        assert r.status_code == 200, r.text
        acts = r.json()
        assert len(acts) == EXPECTED_TOTAL, f"expected {EXPECTED_TOTAL}, got {len(acts)}"
        counts = Counter(a["category"] for a in acts)
        for cat, expected in EXPECTED_COUNTS.items():
            assert counts.get(cat, 0) == expected, f"{cat}: expected {expected} got {counts.get(cat,0)}"

    def test_social_titles_unique(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        social = [a for a in r.json() if a["category"] == "Social"]
        assert len(social) == 50
        titles = [a["title"] for a in social]
        assert len(set(titles)) == 50, "duplicate Social titles found"

    def test_social_duration_coverage(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        social = [a for a in r.json() if a["category"] == "Social"]
        durations = set(a["duration"] for a in social)
        # Required minimum coverage per spec
        for d in (5, 10, 20, 30):
            assert d in durations, f"Social missing duration bucket {d} (got {sorted(durations)})"
        allowed = {5, 10, 15, 20, 30, 45, 60}
        assert durations.issubset(allowed), f"unsupported Social durations: {durations - allowed}"

    def test_personal_growth_titles_unique(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        pg = [a for a in r.json() if a["category"] == "Personal Growth"]
        assert len(pg) == 50
        titles = [a["title"] for a in pg]
        assert len(set(titles)) == 50, "duplicate Personal Growth titles found"

    def test_personal_growth_duration_coverage(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        pg = [a for a in r.json() if a["category"] == "Personal Growth"]
        durations = set(a["duration"] for a in pg)
        for d in (5, 10, 20, 30):
            assert d in durations, f"Personal Growth missing duration bucket {d} (got {sorted(durations)})"
        allowed = {5, 10, 15, 20, 30, 45, 60}
        assert durations.issubset(allowed), f"unsupported Personal Growth durations: {durations - allowed}"


# ---------- Idempotency ----------
class TestSeedingIdempotency:
    def test_relogin_does_not_reseed(self, fresh_session):
        # login again in a new session
        s = requests.Session()
        r = s.post(f"{API}/auth/login",
                   json={"email": fresh_session["email"], "password": fresh_session["password"]})
        assert r.status_code == 200
        r2 = s.get(f"{API}/activities")
        assert r2.status_code == 200
        assert len(r2.json()) == EXPECTED_TOTAL

    def test_persistent_account_not_reseeded(self, persistent_session):
        r = persistent_session.get(f"{API}/activities")
        assert r.status_code == 200
        # We can't assert exact count for this pre-existing account but it should be > 0
        # and calling /auth/me + /activities twice should return the same count.
        n1 = len(r.json())
        r2 = persistent_session.get(f"{API}/activities")
        assert len(r2.json()) == n1


# ---------- Explore / no-truncation ----------
class TestExploreNoTruncation:
    def test_activities_not_capped_at_200(self, fresh_session):
        r = fresh_session["session"].get(f"{API}/activities")
        assert len(r.json()) > 200, "activities list appears truncated at 200"


# ---------- Custom activity + favorite ----------
class TestCustomAndFavorite:
    def test_create_custom_activity_and_verify_persistence(self, fresh_session):
        s = fresh_session["session"]
        payload = {
            "title": "TEST_custom_activity",
            "description": "created by pytest",
            "category": "Social",
            "duration": 15,
            "effort": "Gentle",
            "goal": "",
            "notes": "",
        }
        r = s.post(f"{API}/activities", json=payload)
        assert r.status_code == 200, r.text
        created = r.json()
        assert created["title"] == payload["title"]
        assert "id" in created
        # verify via GET
        r2 = s.get(f"{API}/activities")
        assert any(a["id"] == created["id"] for a in r2.json())

    def test_toggle_favorite(self, fresh_session):
        s = fresh_session["session"]
        r = s.get(f"{API}/activities")
        target = next(a for a in r.json() if a["category"] == "Social")
        initial = target.get("favorite", False)
        r2 = s.patch(f"{API}/activities/{target['id']}/favorite")
        assert r2.status_code == 200, r2.text
        # verify flipped
        r3 = s.get(f"{API}/activities")
        after = next(a for a in r3.json() if a["id"] == target["id"])
        assert after["favorite"] == (not initial)
