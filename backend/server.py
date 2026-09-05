from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")

import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]
JWT_ALGORITHM = "HS256"
JWT_SECRET = os.environ["JWT_SECRET"]
logger = logging.getLogger("little-while")

app = FastAPI(title="Little While API")
api = APIRouter(prefix="/api")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {"id": user["id"], "email": user["email"], "display_name": user.get("display_name", "Friend"),
            "timezone": user.get("timezone", "UTC"), "theme": user.get("theme", "light")}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def token(user_id: str, kind: str, minutes: int) -> str:
    return jwt.encode({"sub": user_id, "type": kind, "exp": now() + timedelta(minutes=minutes)}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth(response: Response, user_id: str) -> None:
    response.set_cookie("access_token", token(user_id, "access", 15), httponly=True, secure=True, samesite="none", max_age=900)
    response.set_cookie("refresh_token", token(user_id, "refresh", 10080), httponly=True, secure=True, samesite="none", max_age=604800)


async def current_user(request: Request) -> dict[str, Any]:
    raw = request.cookies.get("access_token")
    if not raw:
        header = request.headers.get("Authorization", "")
        raw = header[7:] if header.startswith("Bearer ") else None
    if not raw:
        raise HTTPException(401, "Please sign in to continue.")
    try:
        payload = jwt.decode(raw, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(401, "Your session has expired.")
    except jwt.PyJWTError:
        raise HTTPException(401, "Your session has expired.")
    user = await db.users.find_one({"id": payload.get("sub")}, {"_id": 0})
    if not user:
        raise HTTPException(401, "Account not found.")
    return user


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: str = Field(min_length=1, max_length=60)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ResetRequest(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str
    password: str = Field(min_length=8)


class ProfileIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=60)
    timezone: str = "UTC"
    theme: str = "light"


class ActivityIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = ""
    category: str = "Personal growth"
    duration: int = Field(default=20, ge=1, le=240)
    effort: str = "Gentle"
    goal: str = ""
    notes: str = ""


class StartIn(BaseModel):
    activity_id: str
    planned_duration: int = Field(ge=1, le=240)


class FinishIn(BaseModel):
    outcome: str
    notes: str = ""
    continued: str = ""


class PauseIn(BaseModel):
    paused: bool


class IntentionIn(BaseModel):
    intention: str = Field(min_length=1, max_length=280)


STARTER_ACTIVITIES = [
    ("Read 10 pages", "A small chapter, a quiet corner.", "Reading", 20),
    ("Sketch something", "Follow an idea without judging it.", "Creativity", 20),
    ("Learn a new concept", "Let curiosity choose the direction.", "Learning", 30),
    ("Go for a walk", "Notice five things you usually miss.", "Movement", 20),
    ("Solve a puzzle", "Give your mind a playful stretch.", "Brain Gym", 15),
    ("Practice Python", "Build one small thing, one step at a time.", "Coding / Building", 30),
    ("Journal for 10 minutes", "Make room for what is on your mind.", "Wellness", 10),
    ("Tidy one small space", "A drawer, a desk, or just one surface.", "Everyday Life", 15),
]


async def seed_user(user_id: str) -> None:
    if await db.activities.count_documents({"user_id": user_id}) > 0:
        return
    docs = [{"id": str(uuid.uuid4()), "user_id": user_id, "title": title, "description": description,
             "category": category, "duration": duration, "effort": "Gentle", "goal": "", "notes": "",
             "favorite": category in {"Reading", "Wellness"}, "created_at": iso(now())}
            for title, description, category, duration in STARTER_ACTIVITIES]
    await db.activities.insert_many(docs)


@api.post("/auth/register")
async def register(data: RegisterIn, response: Response):
    email = data.email.lower()
    if await db.users.find_one({"email": email}, {"_id": 0}):
        raise HTTPException(409, "An account with that email already exists.")
    user = {"id": str(uuid.uuid4()), "email": email, "password_hash": hash_password(data.password),
            "display_name": data.display_name.strip(), "timezone": "UTC", "theme": "light", "created_at": iso(now())}
    await db.users.insert_one(user)
    await seed_user(user["id"])
    set_auth(response, user["id"])
    return public_user(user)


@api.post("/auth/login")
async def login(data: LoginIn, request: Request, response: Response):
    email = data.email.lower()
    identifier = email
    attempt = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    locked_until = attempt.get("locked_until") if attempt else None
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until and locked_until > now():
        raise HTTPException(429, "Too many attempts. Please wait 15 minutes before trying again.")
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user or not verify_password(data.password, user.get("password_hash", "")):
        attempts = (attempt.get("attempts", 0) if attempt else 0) + 1
        update = {"identifier": identifier, "attempts": attempts, "last_failed": now()}
        if attempts >= 5:
            update["locked_until"] = now() + timedelta(minutes=15)
        await db.login_attempts.update_one({"identifier": identifier}, {"$set": update}, upsert=True)
        raise HTTPException(401, "Email or password does not match.")
    await db.login_attempts.delete_one({"identifier": identifier})
    await seed_user(user["id"])
    set_auth(response, user["id"])
    return public_user(user)


@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"ok": True}


@api.get("/auth/me")
async def me(user=Depends(current_user)):
    return public_user(user)


@api.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    raw = request.cookies.get("refresh_token")
    if not raw:
        raise HTTPException(401, "Please sign in again.")
    try:
        payload = jwt.decode(raw, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Please sign in again.")
        user = await db.users.find_one({"id": payload.get("sub")}, {"_id": 0})
        if not user:
            raise HTTPException(401, "Please sign in again.")
        set_auth(response, user["id"])
        return public_user(user)
    except jwt.PyJWTError:
        raise HTTPException(401, "Please sign in again.")


@api.post("/auth/forgot-password")
async def forgot_password(data: ResetRequest):
    user = await db.users.find_one({"email": data.email.lower()}, {"_id": 0})
    if user:
        reset = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({"token": reset, "user_id": user["id"], "expires_at": now() + timedelta(hours=1), "used": False})
        logger.info("Password reset link for %s: /reset-password?token=%s", data.email, reset)
    return {"message": "If that email is registered, a reset link is ready. Check your inbox shortly."}


@api.post("/auth/reset-password")
async def reset_password(data: ResetIn):
    item = await db.password_reset_tokens.find_one({"token": data.token, "used": False})
    expires_at = item.get("expires_at") if item else None
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not item or not expires_at or expires_at < now():
        raise HTTPException(400, "That reset link is invalid or has expired.")
    await db.users.update_one({"id": item["user_id"]}, {"$set": {"password_hash": hash_password(data.password)}})
    await db.password_reset_tokens.update_one({"token": data.token}, {"$set": {"used": True}})
    return {"message": "Your password was updated. You can sign in now."}


@api.post("/auth/google")
async def google_placeholder():
    raise HTTPException(501, "Google sign-in is ready for OAuth credentials. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable it.")


@api.patch("/profile")
async def update_profile(data: ProfileIn, user=Depends(current_user)):
    await db.users.update_one({"id": user["id"]}, {"$set": data.model_dump()})
    return public_user({**user, **data.model_dump()})


@api.get("/activities")
async def activities(user=Depends(current_user)):
    return await db.activities.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", 1).to_list(200)


@api.post("/activities")
async def create_activity(data: ActivityIn, user=Depends(current_user)):
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], **data.model_dump(), "favorite": False, "created_at": iso(now())}
    await db.activities.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


@api.patch("/activities/{activity_id}/favorite")
async def favorite_activity(activity_id: str, user=Depends(current_user)):
    activity = await db.activities.find_one({"id": activity_id, "user_id": user["id"]}, {"_id": 0})
    if not activity:
        raise HTTPException(404, "Activity not found.")
    value = not activity.get("favorite", False)
    await db.activities.update_one({"id": activity_id, "user_id": user["id"]}, {"$set": {"favorite": value}})
    return {**activity, "favorite": value}


@api.delete("/activities/{activity_id}")
async def delete_activity(activity_id: str, user=Depends(current_user)):
    result = await db.activities.delete_one({"id": activity_id, "user_id": user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(404, "Activity not found.")
    return {"ok": True}


def day_key(value: str, timezone_name: str) -> str:
    try:
        from zoneinfo import ZoneInfo
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(ZoneInfo(timezone_name)).date().isoformat()
    except Exception:
        return value[:10]


def today_key(timezone_name: str) -> str:
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(timezone_name)).date().isoformat()
    except Exception:
        return datetime.now(timezone.utc).date().isoformat()


def stats_for(sessions: list[dict[str, Any]], timezone_name: str) -> dict[str, Any]:
    complete = [s for s in sessions if s.get("outcome") in {"completed", "partial"}]
    days = sorted({day_key(s["ended_at"], timezone_name) for s in complete}, reverse=True)
    current = longest = run = 0
    if days:
        today = datetime.fromisoformat(today_key(timezone_name)).date()
        first = datetime.fromisoformat(days[0]).date()
        if (today - first).days <= 1:
            cursor = first
            for value in days:
                if datetime.fromisoformat(value).date() == cursor:
                    run += 1; cursor -= timedelta(days=1)
                else: break
            current = run
        ordered = sorted(datetime.fromisoformat(value).date() for value in days)
        streak = 1
        for left, right in zip(ordered, ordered[1:]):
            streak = streak + 1 if (right - left).days == 1 else 1
            longest = max(longest, streak)
        longest = max(longest, 1)
    category_counts: dict[str, int] = {}
    for session in complete:
        category_counts[session.get("category", "Other")] = category_counts.get(session.get("category", "Other"), 0) + session.get("actual_duration", 0)
    most_active = max(category_counts, key=category_counts.get) if category_counts else "—"
    return {"current_streak": current, "longest_streak": longest, "total_sessions": len(complete),
            "total_minutes": sum(s.get("actual_duration", 0) for s in complete), "most_active_category": most_active,
            "active_days": len(days), "today_sessions": sum(day_key(s["ended_at"], timezone_name) == today_key(timezone_name) for s in complete),
            "completion_rate": round(len([s for s in sessions if s.get("outcome") == "completed"]) / len(sessions) * 100) if sessions else 0,
            "category_minutes": category_counts}


@api.get("/dashboard")
async def dashboard(user=Depends(current_user)):
    sessions = await db.sessions.find({"user_id": user["id"], "outcome": {"$ne": "active"}}, {"_id": 0}).sort("ended_at", -1).to_list(500)
    active = await db.sessions.find_one({"user_id": user["id"], "outcome": "active"}, {"_id": 0})
    intention = await db.intentions.find_one({"user_id": user["id"], "date": today_key(user.get("timezone", "UTC"))}, {"_id": 0})
    return {"sessions": sessions, "active_session": active, "stats": stats_for(sessions, user.get("timezone", "UTC")), "intention": intention}


@api.post("/sessions/start")
async def start_session(data: StartIn, user=Depends(current_user)):
    existing = await db.sessions.find_one({"user_id": user["id"], "outcome": "active"}, {"_id": 0})
    if existing:
        return existing
    activity = await db.activities.find_one({"id": data.activity_id, "user_id": user["id"]}, {"_id": 0})
    if not activity:
        raise HTTPException(404, "Choose an activity first.")
    started = now()
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], "activity_id": activity["id"], "title": activity["title"],
           "category": activity["category"], "started_at": iso(started), "planned_duration": data.planned_duration,
           "outcome": "active", "actual_duration": 0, "notes": "", "continued": "", "paused_at": None, "paused_seconds": 0}
    await db.sessions.insert_one(doc)
    return {key: value for key, value in doc.items() if key != "_id"}


@api.patch("/sessions/{session_id}/pause")
async def pause_session(session_id: str, data: PauseIn, user=Depends(current_user)):
    session = await db.sessions.find_one({"id": session_id, "user_id": user["id"], "outcome": "active"}, {"_id": 0})
    if not session:
        raise HTTPException(404, "That focus session is no longer active.")
    if data.paused and not session.get("paused_at"):
        await db.sessions.update_one({"id": session_id}, {"$set": {"paused_at": iso(now())}})
    elif not data.paused and session.get("paused_at"):
        paused_for = max(0, (now() - datetime.fromisoformat(session["paused_at"])).total_seconds())
        await db.sessions.update_one({"id": session_id}, {"$set": {"paused_at": None}, "$inc": {"paused_seconds": paused_for}})
    return await db.sessions.find_one({"id": session_id}, {"_id": 0})


@api.post("/sessions/{session_id}/finish")
async def finish_session(session_id: str, data: FinishIn, user=Depends(current_user)):
    if data.outcome not in {"completed", "partial", "skipped"}:
        raise HTTPException(422, "Choose a valid session outcome.")
    session = await db.sessions.find_one({"id": session_id, "user_id": user["id"], "outcome": "active"}, {"_id": 0})
    if not session:
        raise HTTPException(404, "That focus session is no longer active.")
    ended = now()
    paused_seconds = session.get("paused_seconds", 0)
    if session.get("paused_at"):
        paused_seconds += (ended - datetime.fromisoformat(session["paused_at"])).total_seconds()
    elapsed = max(1, round(((ended - datetime.fromisoformat(session["started_at"])).total_seconds() - paused_seconds) / 60))
    actual = min(session["planned_duration"], elapsed)
    update = {"ended_at": iso(ended), "actual_duration": actual, "outcome": data.outcome, "notes": data.notes, "continued": data.continued}
    await db.sessions.update_one({"id": session_id, "user_id": user["id"]}, {"$set": update})
    return {**session, **update}


@api.get("/sessions/calendar")
async def calendar_view(year: int, month: int, user=Depends(current_user)):
    if month < 1 or month > 12 or year < 2000 or year > 3000:
        raise HTTPException(422, "Choose a valid month.")
    tz_name = user.get("timezone", "UTC")
    sessions = await db.sessions.find({"user_id": user["id"], "outcome": {"$in": ["completed", "partial", "skipped"]}}, {"_id": 0}).sort("ended_at", -1).to_list(2000)
    prefix = f"{year:04d}-{month:02d}"
    days: dict[str, dict[str, Any]] = {}
    for session in sessions:
        key = day_key(session["ended_at"], tz_name)
        if not key.startswith(prefix):
            continue
        entry = days.setdefault(key, {"date": key, "total_minutes": 0, "sessions": [], "categories": set(), "completed": 0, "partial": 0, "skipped": 0})
        entry["total_minutes"] += session.get("actual_duration", 0)
        entry["categories"].add(session.get("category", "Other"))
        entry[session["outcome"]] = entry.get(session["outcome"], 0) + 1
        entry["sessions"].append({"id": session["id"], "title": session["title"], "category": session.get("category", "Other"),
                                   "actual_duration": session.get("actual_duration", 0), "outcome": session["outcome"],
                                   "notes": session.get("notes", ""), "continued": session.get("continued", "")})
    return {"month": prefix, "timezone": tz_name, "today": today_key(tz_name),
            "days": [{**entry, "categories": sorted(entry["categories"])} for entry in sorted(days.values(), key=lambda x: x["date"])]}


@api.post("/intentions")
async def save_intention(data: IntentionIn, user=Depends(current_user)):
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], "date": today_key(user.get("timezone", "UTC")), "intention": data.intention, "created_at": iso(now())}
    await db.intentions.update_one({"user_id": user["id"], "date": doc["date"]}, {"$set": doc}, upsert=True)
    return doc


api_root = api
app.include_router(api_root)
origins = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(CORSMiddleware, allow_origins=[] if origins == ["*"] else origins, allow_origin_regex=r"https?://(localhost|.*\.preview\.emergentagent\.com)(:\d+)?$", allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("identifier", unique=True)


@app.on_event("shutdown")
async def shutdown():
    client.close()