import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import Useraccount, Session, Profile, Like, Match, Message, Report, Block

app = FastAPI(title="Spark Dating API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------- Utilities -----------------------
import hashlib

def hash_password(password: str, salt: Optional[str] = None):
    if not salt:
        salt = secrets.token_hex(16)
    pwd = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, pwd.hex()


def make_token() -> str:
    return secrets.token_urlsafe(32)


def now_utc():
    return datetime.now(timezone.utc)


def oid(obj):
    from bson import ObjectId
    return ObjectId(obj)


def sanitize(doc):
    if not doc:
        return doc
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    return doc

# ----------------------- Auth -----------------------
class RegisterBody(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1].strip()
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session.get("expires_at") and session["expires_at"] < now_utc():
        raise HTTPException(status_code=401, detail="Session expired")
    user = db["useraccount"].find_one({"_id": session["user_id"]}) if isinstance(session["user_id"], type(db["useraccount"].find_one({}) and {})) else None
    # The above is unreliable; fetch by ObjectId string
    try:
        user = db["useraccount"].find_one({"_id": oid(session["user_id"])})
    except Exception:
        user = db["useraccount"].find_one({"_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = str(user["_id"])
    return {"user": user, "session": session}

@app.post("/auth/register", response_model=AuthResponse)
def register(body: RegisterBody, request: Request):
    existing = db["useraccount"].find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    salt, pwd_hash = hash_password(body.password)
    ua = Useraccount(email=body.email.lower(), password_hash=pwd_hash, password_salt=salt, name=body.name)
    user_id = create_document("useraccount", ua)

    # Create empty profile
    prof = Profile(user_id=str(user_id), display_name=body.name)
    create_document("profile", prof)

    token = make_token()
    expires = now_utc() + timedelta(days=30)
    sess = Session(user_id=str(user_id), token=token, user_agent=request.headers.get("user-agent"), ip=request.client.host if request.client else None, expires_at=expires)
    create_document("session", sess)
    return {"token": token}

@app.post("/auth/login", response_model=AuthResponse)
def login(body: LoginBody, request: Request):
    user = db["useraccount"].find_one({"email": body.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    salt = user.get("password_salt")
    _, candidate_hash = hash_password(body.password, salt)
    if candidate_hash != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token()
    expires = now_utc() + timedelta(days=30)
    sess = Session(user_id=str(user["_id"]), token=token, user_agent=request.headers.get("user-agent"), ip=request.client.host if request.client else None, expires_at=expires)
    create_document("session", sess)
    return {"token": token}

@app.get("/me")
def me(ctx=Depends(get_current_user)):
    user = ctx["user"]
    profile = db["profile"].find_one({"user_id": user["id"]})
    return {"user": sanitize(user), "profile": sanitize(profile)}

# ----------------------- Profile -----------------------
class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    birthdate: Optional[str] = None
    gender: Optional[str] = None
    looking_for: Optional[List[str]] = None
    bio: Optional[str] = None
    job_title: Optional[str] = None
    company: Optional[str] = None
    education: Optional[str] = None
    interests: Optional[List[str]] = None
    photos: Optional[List[str]] = None
    location_lat: Optional[float] = None
    location_lng: Optional[float] = None
    pref_min_age: Optional[int] = None
    pref_max_age: Optional[int] = None
    pref_max_distance_km: Optional[int] = None
    pref_show: Optional[str] = None

@app.get("/profiles/me")
def get_my_profile(ctx=Depends(get_current_user)):
    p = db["profile"].find_one({"user_id": ctx["user"]["id"]})
    return sanitize(p)

@app.put("/profiles/me")
def update_my_profile(body: ProfileUpdate, ctx=Depends(get_current_user)):
    p = db["profile"].find_one({"user_id": ctx["user"]["id"]})
    if not p:
        raise HTTPException(status_code=404, detail="Profile not found")
    update = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    update["updated_at"] = now_utc()
    db["profile"].update_one({"_id": p["_id"]}, {"$set": update})
    p = db["profile"].find_one({"_id": p["_id"]})
    return sanitize(p)

# ----------------------- Feed & Swipes -----------------------
class SwipeBody(BaseModel):
    target_user_id: str
    action: str  # like, dislike, superlike

@app.get("/feed")
def get_feed(limit: int = 20, ctx=Depends(get_current_user)):
    user_id = ctx["user"]["id"]
    my_profile = db["profile"].find_one({"user_id": user_id}) or {}

    # Exclude already swiped and blocked
    liked_targets = set([d["target_user_id"] for d in db["like"].find({"user_id": user_id})])
    disliked_me = set([d["blocker_id"] for d in db["block"].find({"blocked_user_id": user_id})])
    i_blocked = set([d["blocked_user_id"] for d in db["block"].find({"blocker_id": user_id})])

    gender_filter = []
    pref_show = (my_profile or {}).get("pref_show", "everyone")
    if pref_show == "women":
        gender_filter = ["woman"]
    elif pref_show == "men":
        gender_filter = ["man"]

    query = {}
    if gender_filter:
        query["gender"] = {"$in": gender_filter}

    candidates = []
    for doc in db["profile"].find(query).limit(200):
        uid = doc.get("user_id")
        if not uid or uid == user_id:
            continue
        if uid in liked_targets or uid in i_blocked or uid in disliked_me:
            continue
        candidates.append(sanitize(doc))
        if len(candidates) >= limit:
            break
    return {"profiles": candidates}

@app.post("/swipe")
def swipe(body: SwipeBody, ctx=Depends(get_current_user)):
    user_id = ctx["user"]["id"]
    if body.action not in ["like", "dislike", "superlike"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    like_doc = Like(user_id=user_id, target_user_id=body.target_user_id, action=body.action)
    create_document("like", like_doc)

    match_created = False
    match_id = None

    if body.action in ("like", "superlike"):
        # Check if target liked me
        mutual = db["like"].find_one({"user_id": body.target_user_id, "target_user_id": user_id, "action": {"$in": ["like", "superlike"]}})
        if mutual:
            # Ensure match doesn't already exist
            existing = db["match"].find_one({"user_ids": {"$all": [user_id, body.target_user_id]}})
            if not existing:
                m = Match(user_ids=[user_id, body.target_user_id], last_message_at=None)
                match_id = create_document("match", m)
                match_created = True
            else:
                match_id = str(existing["_id"])
    return {"match_created": match_created, "match_id": match_id}

# ----------------------- Matches & Messaging -----------------------
@app.get("/matches")
def list_matches(ctx=Depends(get_current_user)):
    user_id = ctx["user"]["id"]
    matches = []
    for m in db["match"].find({"user_ids": user_id}).sort("_id", -1).limit(100):
        other_id = [u for u in m.get("user_ids", []) if u != user_id][0]
        other_prof = db["profile"].find_one({"user_id": other_id})
        m_doc = sanitize(m)
        m_doc["other_profile"] = sanitize(other_prof) if other_prof else None
        matches.append(m_doc)
    return {"matches": matches}

class SendMessageBody(BaseModel):
    content: str

@app.get("/matches/{match_id}/messages")
def get_messages(match_id: str, ctx=Depends(get_current_user)):
    # ensure user in match
    m = db["match"].find_one({"_id": oid(match_id)})
    if not m or ctx["user"]["id"] not in m.get("user_ids", []):
        raise HTTPException(status_code=404, detail="Match not found")
    msgs = [sanitize(x) for x in db["message"].find({"match_id": match_id}).sort("_id", 1).limit(500)]
    return {"messages": msgs}

@app.post("/matches/{match_id}/messages")
def send_message(match_id: str, body: SendMessageBody, ctx=Depends(get_current_user)):
    m = db["match"].find_one({"_id": oid(match_id)})
    if not m or ctx["user"]["id"] not in m.get("user_ids", []):
        raise HTTPException(status_code=404, detail="Match not found")
    msg = Message(match_id=match_id, sender_id=ctx["user"]["id"], content=body.content, sent_at=now_utc())
    create_document("message", msg)
    db["match"].update_one({"_id": m["_id"]}, {"$set": {"last_message_at": now_utc()}})
    return {"ok": True}

# ----------------------- Safety -----------------------
class ReportBody(BaseModel):
    reported_user_id: str
    reason: str
    details: Optional[str] = None

@app.post("/report")
def report_user(body: ReportBody, ctx=Depends(get_current_user)):
    r = Report(reporter_id=ctx["user"]["id"], reported_user_id=body.reported_user_id, reason=body.reason, details=body.details)
    create_document("report", r)
    return {"ok": True}

class BlockBody(BaseModel):
    blocked_user_id: str

@app.post("/block")
def block_user(body: BlockBody, ctx=Depends(get_current_user)):
    b = Block(blocker_id=ctx["user"]["id"], blocked_user_id=body.blocked_user_id)
    create_document("block", b)
    return {"ok": True}

# ----------------------- Health -----------------------
@app.get("/")
def read_root():
    return {"message": "Spark API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
