import os
import secrets
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from database import db, create_document, get_documents
from schemas import Admin
from passlib.hash import bcrypt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
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
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# ----------------- Admin one-time registration & login -----------------
class AdminRegisterIn(BaseModel):
    full_name: str = Field(...)
    username: str = Field(..., min_length=3)
    email: EmailStr
    password: str = Field(..., min_length=6)

class AdminLoginIn(BaseModel):
    username: str
    password: str

class AuthResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    token: Optional[str] = None


def _admin_exists() -> bool:
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    return db["admin"].count_documents({}) > 0 or os.getenv("ADMIN_CREATED", "false").lower() == "true"


@app.get("/admin/status")
def admin_status():
    return {"admin_created": _admin_exists()}


@app.post("/admin/register", response_model=AuthResponse)
def admin_register(payload: AdminRegisterIn):
    if _admin_exists():
        raise HTTPException(status_code=403, detail="Admin already created")

    # Enforce unique username/email
    if db["admin"].find_one({"$or": [{"username": payload.username}, {"email": payload.email}] }):
        raise HTTPException(status_code=400, detail="Username or email already in use")

    password_hash = bcrypt.hash(payload.password)
    admin_doc = Admin(
        full_name=payload.full_name,
        username=payload.username,
        email=payload.email,
        password_hash=password_hash,
        is_active=True,
    ).model_dump()

    db["admin"].insert_one(admin_doc)

    # Optional: set an env flag for current process lifetime
    os.environ["ADMIN_CREATED"] = "true"

    # Create a session token and store it
    token = secrets.token_urlsafe(32)
    db["admin"].update_one({"username": payload.username}, {"$set": {"current_token": token}})

    return AuthResponse(success=True, message="Admin created", token=token)


@app.post("/auth/login", response_model=AuthResponse)
def admin_login(payload: AdminLoginIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    admin = db["admin"].find_one({"username": payload.username})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not bcrypt.verify(payload.password, admin.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    db["admin"].update_one({"_id": admin["_id"]}, {"$set": {"current_token": token}})

    return AuthResponse(success=True, token=token)


# --------------- Simple token protection for admin-only routes ----------
class SubscriberIn(BaseModel):
    name: Optional[str] = None
    email: EmailStr

class SubscriberOut(BaseModel):
    id: str
    name: Optional[str] = None
    email: EmailStr


def get_current_admin(authorization: Optional[str] = Header(default=None)):
    """Validate Bearer token stored against the admin document."""
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    admin = db["admin"].find_one({"current_token": token})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid token")
    return admin


@app.post("/subscribers")
def add_subscriber(payload: SubscriberIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    # Basic uniqueness by email
    existing = db["subscribers"].find_one({"email": payload.email})
    if existing:
        # idempotent behavior
        return {"success": True}
    create_document("subscribers", {"name": payload.name, "email": payload.email})
    return {"success": True}


@app.get("/subscribers")
def list_subscribers(admin = Depends(get_current_admin)):
    docs = get_documents("subscribers")
    # Normalize ObjectId to str
    out = []
    for d in docs:
        out.append({
            "id": str(d.get("_id")),
            "name": d.get("name"),
            "email": d.get("email")
        })
    return {"items": out}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
