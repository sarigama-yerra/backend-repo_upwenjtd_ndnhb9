"""
Database Schemas for Spark (Bumble-like) Dating App

Each Pydantic model below represents a MongoDB collection. The collection
name is the lowercase of the class name.

Key collections:
- Useraccount: credentials + basic identity
- Session: auth sessions (simple bearer tokens)
- Profile: rich dating profile and discovery preferences
- Like: swipe actions (like, dislike, superlike)
- Match: mutual likes result in a match
- Message: chat messages between matched users
- Report: safety reports
- Block: block relations
"""

from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
from datetime import datetime

# Auth & Accounts
class Useraccount(BaseModel):
    email: EmailStr
    password_hash: str
    password_salt: str
    name: str
    created_at: Optional[datetime] = None

class Session(BaseModel):
    user_id: str
    token: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    expires_at: Optional[datetime] = None

# Profile & Discovery
class Profile(BaseModel):
    user_id: str
    display_name: str
    birthdate: Optional[str] = None
    gender: Optional[Literal["woman","man","non-binary","other"]] = None
    looking_for: Optional[List[Literal["women","men","everyone"]]] = None
    bio: Optional[str] = None
    job_title: Optional[str] = None
    company: Optional[str] = None
    education: Optional[str] = None
    interests: Optional[List[str]] = None
    photos: Optional[List[str]] = None  # URLs for MVP
    location_lat: Optional[float] = None
    location_lng: Optional[float] = None

    # Discovery preferences
    pref_min_age: Optional[int] = 18
    pref_max_age: Optional[int] = 99
    pref_max_distance_km: Optional[int] = 50
    pref_show: Optional[Literal["women","men","everyone"]] = "everyone"

# Swipes
class Like(BaseModel):
    user_id: str  # actor
    target_user_id: str
    action: Literal["like","dislike","superlike"]

# Matches
class Match(BaseModel):
    user_ids: List[str]  # [user_a, user_b]
    last_message_at: Optional[datetime] = None

# Messages
class Message(BaseModel):
    match_id: str
    sender_id: str
    content: str
    sent_at: Optional[datetime] = None

# Safety
class Report(BaseModel):
    reporter_id: str
    reported_user_id: str
    reason: str
    details: Optional[str] = None

class Block(BaseModel):
    blocker_id: str
    blocked_user_id: str
