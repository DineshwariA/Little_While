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
import hashlib
import hmac
import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from requests_oauthlib import OAuth2Session

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]
JWT_ALGORITHM = "HS256"
JWT_SECRET = os.environ["JWT_SECRET"]
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
FRONTEND_POST_LOGIN_URL = os.environ.get("FRONTEND_POST_LOGIN_URL", "").strip() or "/"
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = ["openid", "email", "profile"]
GOOGLE_STATE_COOKIE = "google_oauth_state"
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
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


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
    ("5-minute freehand doodle", "Let your pen wander with no plan at all.", "Creativity", 5),
    ("Sketch an object near you", "Really see the thing that's been sitting there.", "Creativity", 10),
    ("Write a six-line poem", "Six lines. Any subject. No pressure.", "Creativity", 10),
    ("Take three interesting photos", "Look for what you'd usually walk past.", "Creativity", 10),
    ("Draw using only geometric shapes", "Circles, squares, triangles — see what appears.", "Creativity", 15),
    ("Write a tiny fictional scene", "One character, one moment, one page.", "Creativity", 15),
    ("Create a color palette from your surroundings", "Pick five colors from the room around you.", "Creativity", 10),
    ("Sketch your cup or bottle", "The one within arm's reach counts.", "Creativity", 10),
    ("Write down ten unusual ideas", "The stranger the better. Nothing has to be good.", "Creativity", 10),
    ("Make a one-page mind map", "One idea in the middle, branches wherever they go.", "Creativity", 20),
    ("Try blind contour drawing", "Draw without looking down at the paper.", "Creativity", 10),
    ("Write a haiku", "Five, seven, five. A whole small world.", "Creativity", 5),
    ("Photograph interesting textures", "Bark, fabric, tile — collect what your eye likes.", "Creativity", 15),
    ("Design a simple logo", "Just for fun — a logo for a made-up shop.", "Creativity", 30),
    ("Create a fictional character", "Give them a name, a hope, and a habit.", "Creativity", 20),
    ("Write a postcard to your future self", "One year from now. Say something honest.", "Creativity", 15),
    ("Make a tiny paper craft", "A folded animal, a small envelope, a paper star.", "Creativity", 20),
    ("Sketch a plant", "Any leaf, any angle. Slow lines.", "Creativity", 15),
    ("Write a short dialogue", "Two people, a quiet disagreement, a soft ending.", "Creativity", 15),
    ("Create a three-word story", "Beginning, middle, end — in three words.", "Creativity", 5),
    ("Experiment with typography", "Draw the same word five different ways.", "Creativity", 20),
    ("Draw your surroundings from memory", "Close your eyes first. Then sketch what you saw.", "Creativity", 20),
    ("Write five alternate endings to a story", "Any story you love — reimagine the last page.", "Creativity", 30),
    ("Create a simple pattern", "Repeat one small shape until it feels like a rhythm.", "Creativity", 15),
    ("Make a mini collage", "Scraps, magazines, sticky notes — arrange them.", "Creativity", 30),
    ("Write a description of a place without naming it", "Let the details do the naming.", "Creativity", 15),
    ("Photograph something ordinary from an unusual angle", "Get low, get close, get behind it.", "Creativity", 10),
    ("Sketch with your non-dominant hand", "Wobbly is the whole point.", "Creativity", 10),
    ("Create a fictional book title", "The book doesn't exist yet — but its title does.", "Creativity", 5),
    ("Write a 100-word story", "Exactly one hundred. Every word carries weight.", "Creativity", 20),
    ("Design a simple poster concept", "One idea, one image, one line of text.", "Creativity", 30),
    ("Draw an imaginary room", "A room that only exists in your head. Furnish it.", "Creativity", 30),
    ("Write ten possible inventions", "Useful, silly, impossible — write them all down.", "Creativity", 15),
    ("Create a character mood board", "Colors, places, textures, songs — the feeling of them.", "Creativity", 30),
    ("Turn a random object into a story", "The pen becomes a hero. Where does it go?", "Creativity", 20),
    ("Try a new lettering style", "Serif, brush, blocky — copy something you love.", "Creativity", 20),
    ("Sketch something using only five lines", "Five lines total. Choose them carefully.", "Creativity", 10),
    ("Write a short mystery opening", "Just the first paragraph. Leave the rest hanging.", "Creativity", 15),
    ("Create a simple geometric illustration", "Grids, angles, quiet symmetry.", "Creativity", 20),
    ("Make a visual gratitude page", "Draw or letter three things you're glad about.", "Creativity", 20),
    ("Write a tiny comic script", "Three panels. A beginning, a beat, a punchline.", "Creativity", 30),
    ("Create three different versions of the same sketch", "Same subject, three moods.", "Creativity", 30),
    ("Photograph five colors around you", "One frame per color, wherever you find it.", "Creativity", 10),
    ("Invent a fictional place", "A town, an island, a hidden street — describe it.", "Creativity", 20),
    ("Write a short nature description", "The tree outside, the way the light falls.", "Creativity", 15),
    ("Design a fictional app icon", "A tiny square for an app that doesn't exist yet.", "Creativity", 30),
    ("Draw a scene from a dream", "Any dream — real or half-remembered.", "Creativity", 30),
    ("Create a simple bookmark design", "Something you'd want to slide into your favorite book.", "Creativity", 20),
    ("Write a story beginning with an unusual sentence", "Start somewhere strange. See where it goes.", "Creativity", 20),
    ("Make a one-page creative journal entry", "Words, sketches, arrows — however it wants to look.", "Creativity", 20),
    ("Learn the basics of a new language", "Pick one — even a few words start a thread.", "Learning", 30),
    ("Learn five new vocabulary words", "Words you'd like to actually use this week.", "Learning", 10),
    ("Study one unfamiliar concept", "Choose one you've heard of but never really understood.", "Learning", 20),
    ("Watch a short educational lecture", "One talk, one topic, one notebook nearby.", "Learning", 20),
    ("Read an introductory article about a new topic", "Beginner-friendly. Curiosity first, depth later.", "Learning", 15),
    ("Learn how a common technology works", "Wi-Fi, batteries, screens — pick one and dig in.", "Learning", 20),
    ("Research the history of something around you", "The building, the street name, the object on your desk.", "Learning", 30),
    ("Learn one new keyboard shortcut", "One shortcut, well-practiced, saves a lot of tiny minutes.", "Learning", 5),
    ("Study a famous invention", "How it came to be, and who was behind it.", "Learning", 20),
    ("Learn the basics of a scientific concept", "Gravity, entropy, DNA — start with the shape of the idea.", "Learning", 20),
    ("Explore how a household appliance works", "Your kettle or fridge has a story worth knowing.", "Learning", 15),
    ("Learn five facts about space", "Small facts about very large things.", "Learning", 10),
    ("Study one historical event", "One event, one lens, one honest look.", "Learning", 30),
    ("Learn the basics of personal finance", "Budgets, interest, savings — quiet foundations.", "Learning", 30),
    ("Research an interesting animal", "Find one whose life is stranger than you expected.", "Learning", 15),
    ("Learn about a different culture", "Traditions, rhythms, meals — one culture at a time.", "Learning", 30),
    ("Study the basics of psychology", "How minds notice, decide, and remember.", "Learning", 45),
    ("Learn one useful mathematical concept", "Probability, ratios, exponents — pick one and befriend it.", "Learning", 20),
    ("Explore an unfamiliar branch of science", "Geology, immunology, astrophysics — wander somewhere new.", "Learning", 30),
    ("Learn the basics of a programming concept", "Loops, functions, variables — read, then try one.", "Learning", 30),
    ("Study one famous person's contribution to society", "The work, not just the name.", "Learning", 20),
    ("Learn how a search engine works", "Crawling, indexing, ranking — the quiet layers behind the box.", "Learning", 20),
    ("Research how the internet works", "Packets, DNS, cables under the sea.", "Learning", 30),
    ("Learn the basics of cybersecurity", "Passwords, phishing, two-factor — the everyday defences.", "Learning", 30),
    ("Study one concept from artificial intelligence", "One idea, gently — not the whole field at once.", "Learning", 20),
    ("Learn about a new country", "Geography, food, a few phrases, a bit of its story.", "Learning", 20),
    ("Explore the history of your city", "Old maps, old names, old photographs.", "Learning", 30),
    ("Learn how weather forecasting works", "Pressure, models, and educated guesses.", "Learning", 15),
    ("Study the basics of climate science", "Carbon, oceans, cycles — the shape of the picture.", "Learning", 45),
    ("Learn about an important environmental issue", "One issue, understood well, is better than ten skimmed.", "Learning", 20),
    ("Learn five useful phrases in another language", "The ones you'd actually say out loud.", "Learning", 10),
    ("Explore a topic using three different sources", "Compare what they agree on and what they don't.", "Learning", 45),
    ("Learn one practical life skill", "Sewing a button, jump-starting a car, folding a shirt well.", "Learning", 20),
    ("Learn how to read a simple chart or graph", "Axes, scales, and what the shape is really saying.", "Learning", 10),
    ("Study one interesting business concept", "Supply and demand, unit economics, network effects.", "Learning", 20),
    ("Learn the basics of entrepreneurship", "How ideas turn into things people can use.", "Learning", 45),
    ("Research how a product you use is made", "From raw material to your hand.", "Learning", 20),
    ("Learn one new study technique", "Spaced repetition, active recall — try one, gently.", "Learning", 15),
    ("Explore an unfamiliar academic subject", "Anthropology, linguistics, philosophy — a door you haven't opened.", "Learning", 30),
    ("Learn how a camera captures an image", "Light, lens, sensor — a small miracle explained.", "Learning", 15),
    ("Study the basics of nutrition", "Macros, micros, and how your body actually uses them.", "Learning", 30),
    ("Learn about a famous scientific discovery", "The story around the finding is often the best part.", "Learning", 20),
    ("Research the origin of a common word", "Etymology has quiet surprises.", "Learning", 10),
    ("Learn how GPS works", "Satellites, timing, and a very good guess.", "Learning", 15),
    ("Explore how maps and navigation work", "Projections, coordinates, and old ways of finding north.", "Learning", 20),
    ("Learn one concept from economics", "Inflation, incentives, opportunity cost — pick one.", "Learning", 20),
    ("Study a topic you normally know nothing about", "Choose the one you keep meaning to look up.", "Learning", 30),
    ("Learn something from a tutorial and write down three takeaways", "Turn watching into remembering.", "Learning", 30),
    ("Teach yourself a concept well enough to explain it simply", "If you can explain it, you know it.", "Learning", 45),
    ("Spend focused time becoming curious about something completely new", "No goal — just follow the thread.", "Learning", 60),
    ("Build a simple calculator", "Add, subtract, multiply, divide — from scratch.", "Coding / Building", 30),
    ("Create a number guessing game", "Player picks, computer guesses — or the other way around.", "Coding / Building", 20),
    ("Build a digital clock", "Hours, minutes, seconds, ticking on the page.", "Coding / Building", 20),
    ("Make a countdown timer", "Start, stop, and land on zero cleanly.", "Coding / Building", 20),
    ("Create a random quote generator", "One button, one quote, one small delight.", "Coding / Building", 15),
    ("Build a simple to-do list", "Add, check off, and clear — the classic small app.", "Coding / Building", 45),
    ("Create a password generator", "Length, symbols, numbers — your own recipe.", "Coding / Building", 20),
    ("Make a unit converter", "Metres to feet, kilos to pounds — pick a few pairs.", "Coding / Building", 30),
    ("Build a temperature converter", "Celsius, Fahrenheit, Kelvin — all three, one form.", "Coding / Building", 15),
    ("Create a tip calculator", "Amount, percentage, split — clear numbers, clear code.", "Coding / Building", 15),
    ("Make a simple age calculator", "Give it a birthday, get a number back.", "Coding / Building", 15),
    ("Build a multiplication table generator", "One input, a whole grid of answers.", "Coding / Building", 10),
    ("Create a BMI calculator", "Height, weight, one small formula.", "Coding / Building", 20),
    ("Make a simple expense tracker", "Add an expense, see the running total.", "Coding / Building", 45),
    ("Build a character counter", "Live count as the user types.", "Coding / Building", 10),
    ("Create a word counter", "Split, count, display — a nice small warm-up.", "Coding / Building", 10),
    ("Make a palindrome checker", "Reverse the string and compare.", "Coding / Building", 10),
    ("Build a prime number checker", "One input, one honest yes or no.", "Coding / Building", 15),
    ("Create a Fibonacci sequence generator", "N terms, printed cleanly.", "Coding / Building", 15),
    ("Make a factorial calculator", "Loop or recursion — either way, one answer.", "Coding / Building", 10),
    ("Build a simple quiz program", "A few questions, a running score, a friendly end.", "Coding / Building", 30),
    ("Create a rock paper scissors game", "Player vs. computer, best of five if you like.", "Coding / Building", 20),
    ("Make a dice rolling simulator", "One die, then two, then a button to roll them.", "Coding / Building", 10),
    ("Build a coin toss simulator", "Heads or tails — the smallest program that still feels like a program.", "Coding / Building", 5),
    ("Create a basic text analyzer", "Characters, words, sentences — three numbers, one input.", "Coding / Building", 20),
    ("Make a simple contact list", "Add a name, add a number, list them below.", "Coding / Building", 30),
    ("Build a student grade calculator", "Marks in, letter grade out.", "Coding / Building", 20),
    ("Create a marks average calculator", "Any number of subjects, one clean average.", "Coding / Building", 15),
    ("Make a simple shopping list", "Add, remove, tick off — small but complete.", "Coding / Building", 30),
    ("Build a random color generator", "One click, one hex code, one swatch on screen.", "Coding / Building", 10),
    ("Create a simple HTML profile page", "Name, photo, a short intro — pure HTML.", "Coding / Building", 30),
    ("Build a personal introduction webpage", "One page that quietly says who you are.", "Coding / Building", 30),
    ("Create a responsive card component", "Looks right on phone, tablet, and desktop.", "Coding / Building", 30),
    ("Make a simple navigation bar", "Links, a logo, and a mobile-friendly menu.", "Coding / Building", 30),
    ("Build a CSS button collection", "Primary, ghost, disabled — a small kit of your own.", "Coding / Building", 30),
    ("Create a responsive landing page", "Hero, features, footer — nothing fancy, everything working.", "Coding / Building", 60),
    ("Make a simple image gallery", "A grid of images, a click to see them larger.", "Coding / Building", 45),
    ("Build a basic login form UI", "Just the form. Validation later.", "Coding / Building", 30),
    ("Create a registration form UI", "Fields, labels, and a clear submit button.", "Coding / Building", 30),
    ("Make a simple portfolio section", "A few projects, laid out like a proud row.", "Coding / Building", 45),
    ("Build a responsive pricing card", "Three tiers, one highlighted — the classic pattern.", "Coding / Building", 30),
    ("Create a simple FAQ section", "Questions that open and close with a soft click.", "Coding / Building", 30),
    ("Make a CSS loading animation", "A spinner, a bar, or a bouncing dot.", "Coding / Building", 20),
    ("Build a dark mode toggle", "Save the choice, honour the system, feel the theme flip.", "Coding / Building", 30),
    ("Create a simple progress bar", "Fills as a value increases — clear and satisfying.", "Coding / Building", 20),
    ("Make a basic JavaScript interactive webpage", "A page that responds — clicks, inputs, tiny surprises.", "Coding / Building", 45),
    ("Build a keyboard event demo", "Show the key, the code, the moment it was pressed.", "Coding / Building", 20),
    ("Create a simple form validation demo", "Empty fields, wrong emails, kind error messages.", "Coding / Building", 30),
    ("Make a local storage mini project", "Save something on refresh — a note, a name, a toggle.", "Coding / Building", 45),
    ("Build a small API data display", "Fetch, parse, show — one endpoint, one clean list.", "Coding / Building", 45),
    ("Read a short article", "Something you've been meaning to open — now's the time.", "Reading", 10),
    ("Read one chapter of a book", "One chapter, one warm cup, no rush.", "Reading", 30),
    ("Read five pages of a book", "Small but honest progress.", "Reading", 10),
    ("Read a technical blog post", "The kind you'd usually skim — read it properly.", "Reading", 20),
    ("Read a research paper abstract", "The whole idea, distilled into one paragraph.", "Reading", 5),
    ("Read a short essay", "One writer, one argument, one page or two.", "Reading", 15),
    ("Read a news analysis", "Beyond the headline — what someone thinks it means.", "Reading", 15),
    ("Read a biography excerpt", "A slice of someone's life, well told.", "Reading", 20),
    ("Read a science article", "One new idea from the corners of the field.", "Reading", 20),
    ("Read a history article", "Old story, new lens.", "Reading", 20),
    ("Read a technology article", "Something recent, something worth understanding.", "Reading", 15),
    ("Read a psychology article", "Notice one thing about how minds work.", "Reading", 20),
    ("Read a productivity article", "Take what fits your life; leave the rest.", "Reading", 15),
    ("Read a design article", "Type, colour, hierarchy — a quiet vocabulary lesson.", "Reading", 20),
    ("Read a programming tutorial", "Read all the way through before you touch the keyboard.", "Reading", 30),
    ("Read a documentation page", "The one you've been avoiding.", "Reading", 15),
    ("Read an interesting Wikipedia article", "Follow the first link that catches your eye.", "Reading", 20),
    ("Read a book introduction", "The doorway the author built for you.", "Reading", 15),
    ("Read a book conclusion", "Sometimes the ending is where the honest thinking lives.", "Reading", 10),
    ("Read a poem", "One poem, twice — the second read is always richer.", "Reading", 5),
    ("Read a short story", "A whole world in a handful of pages.", "Reading", 30),
    ("Read a personal essay", "Someone thinking out loud, honestly.", "Reading", 15),
    ("Read a case study", "What happened, why it mattered, what they learned.", "Reading", 30),
    ("Read an interview transcript", "Voices are different from summaries.", "Reading", 20),
    ("Read a product review", "How someone thinks about the thing you were curious about.", "Reading", 10),
    ("Read a beginner programming guide", "Even seasoned coders enjoy a first-principles refresher.", "Reading", 30),
    ("Read about a new technology", "One new tool or idea reshaping something.", "Reading", 20),
    ("Read about an unfamiliar topic", "Pick a subject you know nothing about, and start.", "Reading", 20),
    ("Read about a historical event", "One event, one honest telling.", "Reading", 20),
    ("Read about a famous invention", "The story behind the thing you use every day.", "Reading", 15),
    ("Read about a scientific discovery", "The moment someone saw what no one had seen.", "Reading", 20),
    ("Read about a famous person", "Not the myth — the work.", "Reading", 20),
    ("Read about a different culture", "Traditions, rhythms, food, and how it's all threaded together.", "Reading", 30),
    ("Read a financial literacy article", "One idea today, quiet compounding tomorrow.", "Reading", 20),
    ("Read a career advice article", "Take one useful sentence and leave the noise.", "Reading", 15),
    ("Read a communication guide", "How to say the harder thing well.", "Reading", 20),
    ("Read a leadership article", "Leadership by example, not by volume.", "Reading", 15),
    ("Read a problem-solving article", "A framework you might quietly reuse later.", "Reading", 20),
    ("Read a learning strategy article", "How you learn matters as much as what you learn.", "Reading", 15),
    ("Read a computer science concept", "One clean explanation, then close the tab.", "Reading", 20),
    ("Read an AI article", "One thoughtful piece, not ten hot takes.", "Reading", 20),
    ("Read a data science article", "How numbers become questions become stories.", "Reading", 30),
    ("Read a cybersecurity article", "One small habit today, one fewer worry tomorrow.", "Reading", 20),
    ("Read a web development article", "Something new from the platform, explained plainly.", "Reading", 20),
    ("Read a user experience article", "How small choices become big feelings.", "Reading", 15),
    ("Read an open-source project README", "The front door of a project — read it slowly.", "Reading", 10),
    ("Read a programming documentation example", "One example, understood well, is worth ten skimmed.", "Reading", 15),
    ("Read a technical concept and summarize it", "Read it, then write it back in your own words.", "Reading", 45),
    ("Read something outside your usual interests", "The stretch is quiet, but it does count.", "Reading", 60),
    ("Read something you bookmarked earlier", "The tab you keep meaning to open — this is its moment.", "Reading", 20),
    ("Take five quiet minutes", "Nothing to do, nothing to solve — just five minutes.", "Wellness", 5),
    ("Practice slow breathing", "In for four, hold for four, out for six.", "Wellness", 5),
    ("Do a short mindfulness session", "Notice the room, the breath, the small sounds.", "Wellness", 15),
    ("Sit quietly without your phone", "Let the small urge to check it come and go.", "Wellness", 10),
    ("Take a mindful tea break", "Water, kettle, warmth, patience.", "Wellness", 10),
    ("Write three things you appreciate", "Small and specific beats big and vague.", "Wellness", 5),
    ("Write down how you feel", "One honest sentence is enough.", "Wellness", 10),
    ("Do a short gratitude reflection", "Look back at the day and find something quiet to keep.", "Wellness", 10),
    ("Practice a body scan", "Head to toes — notice, don't judge.", "Wellness", 15),
    ("Spend time in silence", "No music, no talking, no plans. Just the room.", "Wellness", 20),
    ("Listen to calming music", "One album, no skipping.", "Wellness", 20),
    ("Take a screen-free break", "Everything can wait for half an hour.", "Wellness", 30),
    ("Step outside for fresh air", "A few slow breaths under the actual sky.", "Wellness", 10),
    ("Spend five minutes in sunlight", "Warm face, softer shoulders.", "Wellness", 5),
    ("Watch the clouds", "Let something slow lead the pace.", "Wellness", 10),
    ("Sit somewhere peaceful", "Choose the corner that always feels a bit softer.", "Wellness", 20),
    ("Have a mindful snack", "Notice the taste, the texture, the temperature.", "Wellness", 10),
    ("Drink a glass of water slowly", "Small sips, a little pause, a small kindness.", "Wellness", 5),
    ("Make a relaxing drink", "Tea, cocoa, warm water and lemon — whichever fits the hour.", "Wellness", 10),
    ("Tidy your personal space", "A calm room is a quiet kindness to future you.", "Wellness", 15),
    ("Organize your bedside area", "The last thing you see at night deserves a little care.", "Wellness", 15),
    ("Refresh your study space", "Clear the desk, wipe it down, reset the lamp.", "Wellness", 20),
    ("Make your bed", "One small finished thing, first thing.", "Wellness", 5),
    ("Declutter one small area", "One drawer, one shelf, one basket.", "Wellness", 15),
    ("Put away things you used today", "Return each thing to where it belongs.", "Wellness", 10),
    ("Prepare a comfortable workspace", "Chair, light, water, a little space to breathe.", "Wellness", 15),
    ("Take a slow walk", "No destination, no pace goal, no phone in hand.", "Wellness", 20),
    ("Walk without checking your phone", "Let the walk be the whole thing.", "Wellness", 30),
    ("Stretch gently", "Only as far as feels good — never further.", "Wellness", 10),
    ("Do a short mobility session", "Wrists, ankles, neck, hips — one at a time.", "Wellness", 15),
    ("Relax your shoulders", "Drop them, roll them, breathe them down.", "Wellness", 5),
    ("Unclench your jaw and breathe", "Notice how tightly you were holding it.", "Wellness", 5),
    ("Do a simple posture reset", "Feet, hips, ribs, crown — stack softly.", "Wellness", 5),
    ("Take a movement break", "Stand, roll, wiggle, sit back down feeling looser.", "Wellness", 10),
    ("Dance to one favorite song", "One song, full commitment, no witnesses required.", "Wellness", 5),
    ("Do a gentle full-body stretch", "Head to toes, breath by breath.", "Wellness", 15),
    ("Spend time with a hobby", "The one that quietly restores you.", "Wellness", 45),
    ("Draw something just for fun", "No plan, no audience, no expectation.", "Wellness", 20),
    ("Listen to your favorite playlist", "Not as background — actually listen.", "Wellness", 30),
    ("Spend time with a pet", "Their pace is a good pace to borrow.", "Wellness", 20),
    ("Call someone you care about", "Even a short call goes a long way.", "Wellness", 30),
    ("Have a device-free conversation", "Phones down. Eyes up.", "Wellness", 30),
    ("Write a short journal entry", "A page, a paragraph, a single line — whatever fits.", "Wellness", 15),
    ("Write about your day", "The good, the plain, and the small surprises.", "Wellness", 20),
    ("Write what is on your mind", "Get it out of the head and onto the page.", "Wellness", 15),
    ("Plan something enjoyable", "A small thing to look forward to this week.", "Wellness", 20),
    ("Prepare tomorrow's essentials", "Clothes, bag, water bottle — tomorrow, thanking you.", "Wellness", 15),
    ("Create a relaxing evening routine", "A short sequence that helps you land softly.", "Wellness", 45),
    ("Do something that makes you smile", "Rewatch it, replay it, revisit it — no guilt.", "Wellness", 20),
    ("Give yourself uninterrupted quiet time", "One hour, no notifications, no expectations.", "Wellness", 60),
    ("Take a five-minute walk", "Short, unhurried, on purpose.", "Movement", 5),
    ("Take a ten-minute walk", "Just enough to reset the head and the shoulders.", "Movement", 10),
    ("Walk around your building", "One easy loop — count it as movement.", "Movement", 10),
    ("Walk around your campus", "Take a route you don't usually take.", "Movement", 15),
    ("Take the stairs", "Skip the lift once — small legs, big habit.", "Movement", 5),
    ("Do a quick morning stretch", "A gentle way to say good morning to your body.", "Movement", 5),
    ("Do an evening stretch", "Undo the day, one soft stretch at a time.", "Movement", 10),
    ("Stretch your arms and shoulders", "Reach up, roll back, breathe out.", "Movement", 5),
    ("Stretch your legs gently", "Hamstrings, calves, quads — a slow tour.", "Movement", 5),
    ("Stretch your back gently", "Small movements, big relief.", "Movement", 5),
    ("Do a full-body stretch", "Head to toes, one round.", "Movement", 15),
    ("Do a short mobility routine", "Wrists, ankles, hips — the joints that carry you.", "Movement", 10),
    ("Do a standing mobility break", "Stand up, roll it out, sit back down looser.", "Movement", 5),
    ("Do a desk stretch break", "Neck, shoulders, wrists, hips — right at your chair.", "Movement", 5),
    ("Do a posture reset", "Feet, hips, ribs, crown — stack softly.", "Movement", 5),
    ("Do a simple warm-up", "Wake the body before you ask it for more.", "Movement", 10),
    ("Do a quick bodyweight routine", "Squats, push-ups, planks — one small set of each.", "Movement", 15),
    ("Do a beginner squat session", "Slow reps beat fast reps every time.", "Movement", 10),
    ("Do a gentle lunge session", "One leg at a time, wobbles included.", "Movement", 10),
    ("Do a short calf raise session", "Up on the toes, down slowly.", "Movement", 5),
    ("Do a simple wall sit", "Back to the wall, thighs parallel, count the breaths.", "Movement", 5),
    ("Do a short plank session", "Short holds, honest form.", "Movement", 5),
    ("Do a beginner core session", "Small, controlled, and kind to your lower back.", "Movement", 15),
    ("Do a short leg workout", "A few honest sets — legs remember the effort.", "Movement", 20),
    ("Do a short arm workout", "Bodyweight or bands — small movements, real progress.", "Movement", 20),
    ("Do a simple upper-body routine", "Push, pull, press — the classic three.", "Movement", 20),
    ("Do a simple lower-body routine", "Squats, lunges, bridges — a friendly rotation.", "Movement", 20),
    ("Do a light full-body routine", "A little of everything, none of it too hard.", "Movement", 30),
    ("Dance to three songs", "Three songs, no breaks, no witnesses required.", "Movement", 15),
    ("Dance to your favorite song", "The one that always works. You know the one.", "Movement", 5),
    ("Have a ten-minute dance break", "Ten minutes of moving to whatever you love.", "Movement", 10),
    ("Try a simple freestyle dance", "No steps, no plan — just move.", "Movement", 10),
    ("Walk while listening to music", "One album, one loop, one calmer you.", "Movement", 30),
    ("Walk without your phone", "Leave it. The walk will still find you.", "Movement", 20),
    ("Explore a new walking route", "A street you've never turned down.", "Movement", 30),
    ("Walk somewhere nearby", "The park, the shop, the long way home.", "Movement", 20),
    ("Spend fifteen minutes moving outdoors", "Any movement, any pace, any weather that's kind.", "Movement", 15),
    ("Take a movement break between study sessions", "Stand, stretch, walk to a window — then back.", "Movement", 5),
    ("Move around during a screen break", "Anything but sitting still.", "Movement", 5),
    ("Do a short balance practice", "One leg, then the other, then a wobble, then a laugh.", "Movement", 10),
    ("Practice standing on one leg", "Thirty seconds each side, twice.", "Movement", 5),
    ("Do a gentle side-to-side stretch", "Reach one way, breathe, reach the other.", "Movement", 10),
    ("Do a short neck and shoulder reset", "Slow circles, soft breath, softer shoulders.", "Movement", 5),
    ("Do a five-minute movement flow", "One easy sequence, start to finish.", "Movement", 5),
    ("Do a ten-minute movement flow", "A longer flow — build up gently.", "Movement", 10),
    ("Do a twenty-minute movement session", "Warm-up, main set, wind-down.", "Movement", 20),
    ("Play a casual outdoor game", "Frisbee, catch, tag — any excuse to be outside.", "Movement", 60),
    ("Play badminton for a while", "Rally, laugh, miss a few, keep going.", "Movement", 45),
    ("Take a relaxed evening walk", "Slow pace, soft light, one loop around the block.", "Movement", 30),
    ("Move freely for ten minutes", "No format, no plan — just move.", "Movement", 10),
    ("Solve a logic puzzle", "One puzzle, one clean deduction.", "Brain Gym", 15),
    ("Solve a number puzzle", "Small grids, small satisfactions.", "Brain Gym", 15),
    ("Solve a pattern puzzle", "Find the rule hiding in plain sight.", "Brain Gym", 15),
    ("Complete a sequence challenge", "What comes next — and why?", "Brain Gym", 10),
    ("Find the missing number", "One blank, one honest guess, one check.", "Brain Gym", 5),
    ("Find the odd one out", "Look twice — the answer isn't always the loudest.", "Brain Gym", 5),
    ("Solve a simple riddle", "Small twist, small smile.", "Brain Gym", 5),
    ("Solve three riddles", "Three little puzzles, three little wins.", "Brain Gym", 15),
    ("Try a lateral thinking puzzle", "The obvious answer isn't the one you want.", "Brain Gym", 15),
    ("Solve a Sudoku puzzle", "Easy grid, quiet focus.", "Brain Gym", 20),
    ("Complete a mini crossword", "Small grid, satisfying finish.", "Brain Gym", 15),
    ("Solve a word puzzle", "Anagrams, ladders, or a good old cryptic clue.", "Brain Gym", 10),
    ("Play a short chess puzzle", "Find the best move in the given position.", "Brain Gym", 10),
    ("Solve a chess tactic", "Fork, pin, skewer — spot the pattern.", "Brain Gym", 10),
    ("Play a quick chess game", "One game, honest moves, no takebacks.", "Brain Gym", 30),
    ("Analyze a chess position", "Slow down and read the board.", "Brain Gym", 20),
    ("Practice chess openings", "One opening, a few lines, deep enough to remember.", "Brain Gym", 30),
    ("Memorize ten random words", "Read once, look away, recall.", "Brain Gym", 10),
    ("Test your short-term memory", "A small list, a short pause, an honest recall.", "Brain Gym", 10),
    ("Memorize a short number sequence", "Digits in, then out — nothing on the page.", "Brain Gym", 5),
    ("Try a visual memory challenge", "Look at a scene for ten seconds, then describe it.", "Brain Gym", 10),
    ("Recall everything from a short list", "Groceries, capitals, colours — anything counts.", "Brain Gym", 5),
    ("Create your own memory challenge", "Write it now, test yourself tomorrow.", "Brain Gym", 20),
    ("Practice mental arithmetic", "No paper, no calculator — just the head.", "Brain Gym", 10),
    ("Solve ten mental math problems", "One after another, quietly.", "Brain Gym", 15),
    ("Practice multiplication mentally", "Times tables you never fully trusted.", "Brain Gym", 10),
    ("Practice percentage calculations", "Tips, discounts, splits — the everyday kind.", "Brain Gym", 10),
    ("Solve a quick estimation challenge", "Guess first, calculate second, compare.", "Brain Gym", 5),
    ("Calculate without a calculator", "Bills, splits, receipts — pen optional.", "Brain Gym", 15),
    ("Find a pattern in numbers", "Sequences hide in odd places.", "Brain Gym", 10),
    ("Decode a simple cipher", "Caesar, Atbash, or your own invented rule.", "Brain Gym", 20),
    ("Create a simple cipher", "Design a rule, encode a sentence, hand it to a friend.", "Brain Gym", 20),
    ("Solve a sequence of clues", "One clue leads to the next — a paper trail of thinking.", "Brain Gym", 20),
    ("Complete a logic grid puzzle", "Rows, columns, and a lot of process of elimination.", "Brain Gym", 30),
    ("Solve a deduction puzzle", "Rule things out until only one thing is left.", "Brain Gym", 20),
    ("Find connections between words", "Two words, one unexpected link.", "Brain Gym", 10),
    ("Find as many uses for one object", "A brick, a spoon, a rubber band — go wide.", "Brain Gym", 10),
    ("Brainstorm ten solutions to a problem", "Even the silly ones — they loosen the good ones.", "Brain Gym", 15),
    ("Challenge an assumption", "Pick one you rely on and take a fresh look.", "Brain Gym", 15),
    ("Analyze a problem from two perspectives", "Argue for it, then against it.", "Brain Gym", 20),
    ("Break a problem into smaller parts", "One big thing becomes a list of small things.", "Brain Gym", 20),
    ("Explain a concept from memory", "If you can explain it out loud, you know it.", "Brain Gym", 15),
    ("Learn and recall five new facts", "Read once, close the tab, recall.", "Brain Gym", 15),
    ("Research an unfamiliar topic", "One topic, three sources, quiet notes.", "Brain Gym", 45),
    ("Compare two ideas", "Side by side — where they agree, where they don't.", "Brain Gym", 20),
    ("Spot logical flaws in an argument", "Read slowly. Which step doesn't actually follow?", "Brain Gym", 20),
    ("Practice asking better questions", "The right question does half the thinking.", "Brain Gym", 15),
    ("Solve a beginner coding puzzle", "Small input, small output, satisfying click.", "Brain Gym", 30),
    ("Trace a short piece of code mentally", "Read line by line and predict the result.", "Brain Gym", 15),
    ("Create your own brain challenge", "Invent it, solve it, tuck it away for a friend.", "Brain Gym", 60),
    ("Send a message to an old friend", "One line, no pressure — just \"thinking of you\".", "Social", 10),
    ("Check in with someone you care about", "A soft \"how are you, really?\" goes a long way.", "Social", 10),
    ("Call a friend", "A short call is often better than a long text.", "Social", 20),
    ("Call a family member", "The kind of call that ends with you both smiling.", "Social", 20),
    ("Have a short phone conversation", "Small catch-up, real voice, real presence.", "Social", 15),
    ("Send someone a thank-you message", "Specific beats generic — name the thing.", "Social", 5),
    ("Tell someone you appreciate them", "Out loud, in text — either way, they'll remember it.", "Social", 5),
    ("Compliment someone sincerely", "Not the appearance. The effort, the taste, the courage.", "Social", 5),
    ("Ask someone how their day went", "And actually stay for the answer.", "Social", 10),
    ("Ask a friend about something they enjoy", "Let their favourite thing be the whole conversation.", "Social", 15),
    ("Share something interesting with a friend", "The article, the fact, the small thing that made you think.", "Social", 10),
    ("Send someone a funny memory", "The photo, the moment, the inside joke.", "Social", 5),
    ("Share a favorite song", "One song, one message, one small warmth.", "Social", 5),
    ("Recommend a book to someone", "Say why. The why is the part they'll remember.", "Social", 10),
    ("Recommend a movie to someone", "Not the popular pick — the one that stayed with you.", "Social", 10),
    ("Share an interesting article", "With a sentence about why it caught you.", "Social", 5),
    ("Have a device-free conversation", "Phones face down, eyes up — see how it changes.", "Social", 30),
    ("Have tea with someone", "The tea is the excuse; the company is the point.", "Social", 30),
    ("Eat a meal with someone", "No phones on the table. Real chairs, real talk.", "Social", 45),
    ("Take a walk with a friend", "Side by side beats face to face for some conversations.", "Social", 30),
    ("Take a walk with a family member", "The old, easy company you sometimes forget to book.", "Social", 30),
    ("Play a board game", "Rules, laughter, the occasional argument — all part of it.", "Social", 45),
    ("Play a card game", "One deck, one table, one hour, plenty of stories.", "Social", 30),
    ("Play a quick game with a friend", "One short round — winner buys the next tea.", "Social", 20),
    ("Solve a puzzle with someone", "Two heads, one small jigsaw or riddle.", "Social", 30),
    ("Learn something from a friend", "Ask them to teach you the thing they love.", "Social", 20),
    ("Teach someone something you know", "The small skill you never realised was a gift.", "Social", 20),
    ("Ask someone for their opinion", "An honest one — not just the reassuring one.", "Social", 15),
    ("Have a meaningful conversation", "The kind that leaves you thinking on the way home.", "Social", 30),
    ("Talk about a favorite childhood memory", "Yours or theirs — both make good stories.", "Social", 20),
    ("Ask a family member about their childhood", "You'll hear a story you didn't know you needed.", "Social", 30),
    ("Learn about someone's hobby", "Let them be the expert for a while.", "Social", 20),
    ("Discuss a movie you both watched", "Even a disagreement is a good conversation.", "Social", 20),
    ("Discuss a book you both read", "Compare favourite lines, favourite people, favourite endings.", "Social", 30),
    ("Exchange interesting facts", "Ping-pong of small learnings.", "Social", 15),
    ("Brainstorm an idea with someone", "Someone else's brain is a good sounding board.", "Social", 20),
    ("Work on a small task together", "Doing beats talking about doing.", "Social", 30),
    ("Help someone with a simple task", "Small favours are quiet love.", "Social", 20),
    ("Offer to help someone", "Even the offer changes the day a little.", "Social", 10),
    ("Thank someone who helped you", "The specific ones stay with people for years.", "Social", 5),
    ("Introduce yourself to someone new", "One warm hello can widen a whole week.", "Social", 10),
    ("Start a conversation with a classmate", "You've seen them every day — start a real one.", "Social", 10),
    ("Talk to someone you rarely speak with", "The quiet friend, the distant cousin — reach out.", "Social", 15),
    ("Meet a friend for a short break", "Even fifteen minutes together counts.", "Social", 30),
    ("Spend quality time with family", "Nothing to solve — just be around each other.", "Social", 60),
    ("Plan a future activity with a friend", "Something to look forward to together.", "Social", 20),
    ("Plan a group activity", "Pick a date, send the message, get it on the calendar.", "Social", 30),
    ("Send encouragement to someone", "Someone out there needs today's kind message.", "Social", 5),
    ("Make someone laugh", "The old joke, the fresh meme, the honest silliness.", "Social", 10),
    ("Have a conversation without checking your phone", "The whole conversation. Both of you. Present.", "Social", 20),
    ("Organize your backpack", "Empty it out, keep only what earns its spot back.", "Everyday Life", 15),
    ("Clean your study table", "Wipe it, clear it, reset it for tomorrow.", "Everyday Life", 15),
    ("Organize your desk drawer", "One drawer, one honest sort.", "Everyday Life", 15),
    ("Sort your stationery", "Pens that work in one place, dead ones in the bin.", "Everyday Life", 10),
    ("Clean your keyboard", "Turn it upside down, brush, wipe — feel the difference.", "Everyday Life", 10),
    ("Clean your laptop screen", "A soft cloth, a gentle pass.", "Everyday Life", 5),
    ("Organize your digital files", "Folders, subfolders, one clear structure.", "Everyday Life", 30),
    ("Rename messy files", "\"final_final_v3\" doesn't have to live forever.", "Everyday Life", 15),
    ("Clean your downloads folder", "It has more than you think. Keep three, delete the rest.", "Everyday Life", 15),
    ("Organize your phone apps", "By use, by mood, by folder — however you actually think.", "Everyday Life", 20),
    ("Delete unused phone apps", "Keep only the ones that earned this month.", "Everyday Life", 10),
    ("Clear old screenshots", "They pile up. Ten minutes and they're gone.", "Everyday Life", 10),
    ("Organize your photos", "Albums, favourites, delete the seventeen near-duplicates.", "Everyday Life", 45),
    ("Back up important files", "Cloud or drive — future you will thank present you.", "Everyday Life", 20),
    ("Sort your bookmarks", "Group them, prune them, let the useful ones surface.", "Everyday Life", 15),
    ("Clean your email inbox", "Archive, delete, done — one honest pass.", "Everyday Life", 30),
    ("Unsubscribe from unwanted emails", "Every unsub is a quieter tomorrow.", "Everyday Life", 20),
    ("Reply to pending messages", "The ones you've been meaning to answer.", "Everyday Life", 20),
    ("Make a simple grocery list", "What you actually need, not what you think you might.", "Everyday Life", 10),
    ("Plan tomorrow's outfit", "One decision fewer for morning-you.", "Everyday Life", 5),
    ("Prepare your bag for tomorrow", "Everything you need, nothing you don't.", "Everyday Life", 10),
    ("Prepare your study materials", "Book, notes, pen — set them out so morning is smooth.", "Everyday Life", 15),
    ("Pack something you will need tomorrow", "The lunch box, the water bottle, the charger.", "Everyday Life", 5),
    ("Make your bed", "One small finished thing, first thing.", "Everyday Life", 5),
    ("Fold clean clothes", "A small pile, folded well, is a quiet win.", "Everyday Life", 15),
    ("Organize your wardrobe", "By colour, by season, by how often you actually reach.", "Everyday Life", 60),
    ("Sort clothes you no longer use", "One bag for keeping, one for donating.", "Everyday Life", 30),
    ("Organize your bookshelf", "By colour, by height, by story — however it feels right.", "Everyday Life", 20),
    ("Arrange your shoes", "Line them up. Small order, big calm.", "Everyday Life", 10),
    ("Clean one small area", "A shelf, a windowsill, a single corner.", "Everyday Life", 15),
    ("Water your plants", "A short round of quiet care.", "Everyday Life", 5),
    ("Feed a pet", "Their small daily ritual is a nice one to keep.", "Everyday Life", 5),
    ("Help with a household task", "Dishes, laundry, groceries — one thing, honestly done.", "Everyday Life", 20),
    ("Wash your water bottle", "Warm water, a proper scrub, honestly.", "Everyday Life", 5),
    ("Clean your reusable bottle", "The one that carries every day deserves a proper clean.", "Everyday Life", 5),
    ("Refill your essentials", "Water, snacks, tissues — the boring, useful ones.", "Everyday Life", 10),
    ("Check your calendar", "See what tomorrow actually looks like.", "Everyday Life", 5),
    ("Review tomorrow's schedule", "So morning-you can breathe.", "Everyday Life", 10),
    ("Make a short errands list", "Three items, in order, done.", "Everyday Life", 5),
    ("Plan your route for tomorrow", "Where, when, in what order — a small map for the day.", "Everyday Life", 10),
    ("Write down important reminders", "Get them off your mind and onto the page.", "Everyday Life", 5),
    ("Sort your notes", "Group them, label them, keep only what still helps.", "Everyday Life", 20),
    ("Organize your notebooks", "One notebook per subject beats one for everything.", "Everyday Life", 20),
    ("Finish one small pending task", "The one you keep almost doing.", "Everyday Life", 15),
    ("Complete one tiny household task", "A small chore quietly finished.", "Everyday Life", 10),
    ("Fix one small thing you've been ignoring", "The loose screw, the missing button, the tangled cable.", "Everyday Life", 15),
    ("Prepare something for tomorrow", "Lunch, notes, bag — one useful bit of prep.", "Everyday Life", 15),
    ("Set up a comfortable study space", "Chair, light, water, breathing room.", "Everyday Life", 15),
    ("Reset your room for the evening", "Lights soft, phone away, room at ease.", "Everyday Life", 20),
    ("Spend fifteen minutes making life easier", "Any small act your future self would thank you for.", "Everyday Life", 15),
    ("Write about something you learned today", "Even the tiny lesson counts. Write it before it fades.", "Personal Growth", 10),
    ("Reflect on a recent accomplishment", "Look back at it kindly, not modestly.", "Personal Growth", 15),
    ("Write down three strengths", "Real ones — the ones friends would name for you.", "Personal Growth", 10),
    ("Identify something you want to improve", "One thing, gently, without judgment.", "Personal Growth", 10),
    ("Write about something you are proud of", "The moment you almost forgot you deserved to be proud of.", "Personal Growth", 15),
    ("Think about what motivates you", "The thing under the thing. Follow it inward.", "Personal Growth", 20),
    ("Write down what matters to you", "Not what should. What does.", "Personal Growth", 15),
    ("Reflect on your current priorities", "Are you spending time on them? Honest answers only.", "Personal Growth", 20),
    ("Write about your ideal day", "From waking to sleeping — describe the whole shape.", "Personal Growth", 20),
    ("Describe your future self", "One year, five years — write like you already know them.", "Personal Growth", 20),
    ("Write a letter to your future self", "One page, one honest voice, one year from now.", "Personal Growth", 30),
    ("Write a note to your past self", "The one thing you'd want them to know.", "Personal Growth", 15),
    ("Think about a goal you care about", "Not everyone's goal. Yours.", "Personal Growth", 15),
    ("Break one goal into smaller steps", "The big thing becomes a small first thing.", "Personal Growth", 20),
    ("Choose one goal for this month", "One is more powerful than five.", "Personal Growth", 15),
    ("Write down one thing you want to try", "Small, silly, or serious — write it down anyway.", "Personal Growth", 5),
    ("Make a list of things you want to learn", "Long, loose, no order. Just curiosity on paper.", "Personal Growth", 15),
    ("Choose one skill to practice", "The one you keep circling back to.", "Personal Growth", 5),
    ("Practice a skill for twenty minutes", "Regular small practice beats occasional big pushes.", "Personal Growth", 20),
    ("Learn something outside your comfort zone", "A gentle stretch is still a stretch.", "Personal Growth", 30),
    ("Try something you have never done", "Small firsts still count as firsts.", "Personal Growth", 30),
    ("Do something slightly challenging", "Not scary — just a little bigger than easy.", "Personal Growth", 20),
    ("Identify one limiting assumption", "One belief you carry without checking.", "Personal Growth", 15),
    ("Question one habit you have", "Ask honestly whether it's still serving you.", "Personal Growth", 15),
    ("Reflect on how you spend your time", "One week, one honest look.", "Personal Growth", 20),
    ("Review what went well this week", "Even the small wins deserve counting.", "Personal Growth", 15),
    ("Review what did not go well", "Look with curiosity, not with a stick.", "Personal Growth", 15),
    ("Write one lesson from a mistake", "The lesson is the whole point of the mistake.", "Personal Growth", 15),
    ("Think of a problem you overcame", "You have more evidence than you think.", "Personal Growth", 20),
    ("Write down three things you handled well", "Recent ones. Specific ones.", "Personal Growth", 10),
    ("Identify something you can simplify", "One thing in your life that could be lighter.", "Personal Growth", 10),
    ("Choose one small habit to build", "Small enough that missing a day doesn't matter.", "Personal Growth", 10),
    ("Choose one habit to reduce", "Not remove — just reduce, kindly.", "Personal Growth", 10),
    ("Design a better morning routine", "Three moves that make the day begin softer.", "Personal Growth", 20),
    ("Design a better evening routine", "Something that helps you land, not scroll.", "Personal Growth", 20),
    ("Plan a personal reset session", "Space, quiet, notebook, honest thinking.", "Personal Growth", 45),
    ("Make a personal bucket list", "The dreams you keep quietly in the back of your head.", "Personal Growth", 30),
    ("Write down ten things you enjoy", "Simple ones. The kind that don't need occasions.", "Personal Growth", 10),
    ("List things that make you curious", "Curiosity is a compass — write down the readings.", "Personal Growth", 10),
    ("Explore a new interest", "Follow the thread you keep glancing at.", "Personal Growth", 30),
    ("Create a personal learning plan", "A gentle map of what and how, for the next while.", "Personal Growth", 45),
    ("Update your personal goals", "Life shifts. So can they.", "Personal Growth", 20),
    ("Review your progress this month", "Look for movement, not perfection.", "Personal Growth", 20),
    ("Write down something you want to remember", "The small truth you keep almost forgetting.", "Personal Growth", 5),
    ("Reflect on an important decision", "Slow it down. Turn it around a few times.", "Personal Growth", 20),
    ("Imagine three possibilities for your future", "Three different paths, all real.", "Personal Growth", 30),
    ("Write about what success means to you", "In your own words, not the borrowed ones.", "Personal Growth", 30),
    ("Write about what a good life means to you", "The quiet definition, not the loud one.", "Personal Growth", 30),
    ("Spend thirty minutes learning about yourself", "Ask better questions than you usually do.", "Personal Growth", 30),
    ("Ask yourself what you want to do with your little time", "The whole point of Little While, in one gentle question.", "Personal Growth", 60),
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


def google_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)


@api.get("/auth/google/status")
async def google_status():
    return {"configured": google_configured()}


@api.get("/auth/google")
async def google_start():
    if not google_configured():
        return JSONResponse(status_code=503, content={"detail": "Google sign-in is not configured yet. Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI to enable it."})
    state = secrets.token_urlsafe(32)
    oauth = OAuth2Session(client_id=GOOGLE_CLIENT_ID, redirect_uri=GOOGLE_REDIRECT_URI, scope=GOOGLE_SCOPES)
    authorization_url, _ = oauth.authorization_url(GOOGLE_AUTHORIZATION_URL, state=state, access_type="online", include_granted_scopes="true", prompt="select_account")
    response = RedirectResponse(authorization_url, status_code=307)
    response.set_cookie(GOOGLE_STATE_COOKIE, state, max_age=600, httponly=True, secure=True, samesite="lax", path="/api/auth/google")
    return response


@api.get("/auth/google/callback")
async def google_callback(request: Request):
    if not google_configured():
        return JSONResponse(status_code=503, content={"detail": "Google sign-in is not configured."})
    query = request.query_params
    if query.get("error"):
        return JSONResponse(status_code=400, content={"detail": "Google sign-in was cancelled or denied."})
    returned_state = query.get("state") or ""
    stored_state = request.cookies.get(GOOGLE_STATE_COOKIE) or ""
    if not returned_state or not stored_state or not hmac.compare_digest(returned_state, stored_state):
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired Google OAuth state."})
    code = query.get("code")
    if not code:
        return JSONResponse(status_code=400, content={"detail": "Google did not return an authorization code."})
    try:
        oauth = OAuth2Session(client_id=GOOGLE_CLIENT_ID, redirect_uri=GOOGLE_REDIRECT_URI, state=stored_state)
        token = oauth.fetch_token(token_url=GOOGLE_TOKEN_URL, code=code, client_secret=GOOGLE_CLIENT_SECRET, include_client_id=True, timeout=15)
        raw_id_token = token.get("id_token")
        if not raw_id_token:
            raise ValueError("no id_token in Google response")
        id_info = google_id_token.verify_oauth2_token(raw_id_token, google_requests.Request(), audience=GOOGLE_CLIENT_ID)
        if id_info.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}:
            raise ValueError("unexpected issuer")
        if id_info.get("email_verified") is not True:
            raise ValueError("email not verified")
        email = (id_info.get("email") or "").strip().lower()
        if not email or "@" not in email:
            raise ValueError("no valid email in Google token")
        display_name = (id_info.get("name") or email.split("@", 1)[0]).strip()[:60] or "Friend"
    except Exception as exc:
        logger.warning("Google OAuth callback failed: %s", type(exc).__name__)
        return JSONResponse(status_code=401, content={"detail": "Google sign-in could not be completed."})
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        user = {"id": str(uuid.uuid4()), "email": email, "password_hash": "", "display_name": display_name,
                "timezone": "UTC", "theme": "light", "created_at": iso(now()), "auth_provider": "google"}
        try:
            await db.users.insert_one(user)
        except Exception:
            user = await db.users.find_one({"email": email}, {"_id": 0})
        if user:
            await seed_user(user["id"])
    if not user:
        return JSONResponse(status_code=500, content={"detail": "Could not create your account."})
    await db.login_attempts.delete_one({"identifier": email})
    response = RedirectResponse(url=FRONTEND_POST_LOGIN_URL, status_code=303)
    set_auth(response, user["id"])
    response.delete_cookie(GOOGLE_STATE_COOKIE, path="/api/auth/google")
    return response


@api.patch("/profile")
async def update_profile(data: ProfileIn, user=Depends(current_user)):
    await db.users.update_one({"id": user["id"]}, {"$set": data.model_dump()})
    return public_user({**user, **data.model_dump()})


@api.get("/activities")
async def activities(user=Depends(current_user)):
    return await db.activities.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", 1).to_list(2000)


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