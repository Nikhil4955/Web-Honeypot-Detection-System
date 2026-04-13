import os
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from bson import ObjectId
from utils.auth_utils import hash_password, verify_password

async def register_user(db, email: str, password: str, name: str = "User"):
    email = email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    password_hash = hash_password(password)
    user_doc = {
        "email": email,
        "password_hash": password_hash,
        "name": name,
        "role": "user",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    result = await db.users.insert_one(user_doc)
    return {
        "_id": str(result.inserted_id),
        "email": email,
        "name": name,
        "role": "user",
        "created_at": user_doc["created_at"]
    }

async def login_user(db, email: str, password: str, ip: str):
    email = email.lower()
    identifier = f"{ip}:{email}"
    
    # Check brute force lockout
    attempt_doc = await db.login_attempts.find_one({"identifier": identifier})
    if attempt_doc and attempt_doc.get("locked_until"):
        if attempt_doc["locked_until"] > datetime.now(timezone.utc):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
    
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(password, user["password_hash"]):
        # Increment failed attempts
        failed_count = attempt_doc["failed_count"] + 1 if attempt_doc else 1
        locked_until = None
        if failed_count >= 5:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$set": {"failed_count": failed_count, "locked_until": locked_until, "last_attempt": datetime.now(timezone.utc)}},
            upsert=True
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Clear failed attempts on successful login
    await db.login_attempts.delete_one({"identifier": identifier})
    
    user["_id"] = str(user["_id"])
    user.pop("password_hash")
    return user

async def seed_admin(db):
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@soin.dev")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        hashed = hash_password(admin_password)
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hashed,
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password)}}
        )
    
    # Write credentials to file
    os.makedirs("/app/memory", exist_ok=True)
    with open("/app/memory/test_credentials.md", "w") as f:
        f.write("# Test Credentials\n\n")
        f.write("## Admin Account\n")
        f.write(f"- Email: {admin_email}\n")
        f.write(f"- Password: {admin_password}\n")
        f.write(f"- Role: admin\n\n")
        f.write("## Auth Endpoints\n")
        f.write("/api/auth/register\n")
        f.write("/api/auth/login\n")
        f.write("/api/auth/logout\n")
        f.write("/api/auth/me\n")
        f.write("/api/auth/refresh\n")
