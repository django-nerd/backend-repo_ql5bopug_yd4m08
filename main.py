import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Header, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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
    # RESET_ADMIN=true temporarily disables the created state to allow recovery
    reset_override = os.getenv("RESET_ADMIN", "false").lower() == "true"
    if reset_override:
        return False
    exists = db["admin"].count_documents({}) > 0 or os.getenv("ADMIN_CREATED", "false").lower() == "true"
    return exists


@app.get("/admin/status")
def admin_status():
    return {"admin_created": _admin_exists()}


@app.post("/admin/register", response_model=AuthResponse)
def admin_register(payload: AdminRegisterIn):
    # If admin already exists and no reset override, block further registrations
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

    # Mark created for current process lifetime
    os.environ["ADMIN_CREATED"] = "true"

    # Do NOT auto-login; guide user to login page
    return AuthResponse(success=True, message="Admin created. Please log in.")


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


# ----------------- Password reset flow for single admin -----------------
class ForgotPasswordIn(BaseModel):
    email: EmailStr

class ResetVerifyOut(BaseModel):
    valid: bool
    message: Optional[str] = None

class ResetPasswordIn(BaseModel):
    token: str
    new_password: str = Field(..., min_length=6)

RESET_TOKEN_TTL_MINUTES = 15


def _get_single_admin():
    admin = db["admin"].find_one({})
    return admin


@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    admin = _get_single_admin()
    if not admin or admin.get("email") != payload.email:
        raise HTTPException(status_code=404, detail="No account found with this email.")

    raw_token = secrets.token_urlsafe(32)
    token_hash = bcrypt.hash(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
    db["admin"].update_one({"_id": admin["_id"]}, {"$set": {"reset_token_hash": token_hash, "reset_token_expires": expires_at}})

    # Simulate sending email: In production, integrate with an email service
    reset_base = os.getenv("FRONTEND_URL") or os.getenv("PUBLIC_FRONTEND_URL") or ""
    reset_link = f"{reset_base}/new-password?token={raw_token}" if reset_base else f"/new-password?token={raw_token}"

    print("[PixFlow] Password reset link (dev log):", reset_link)

    return {"success": True, "message": "If the email exists, a reset link has been sent.", "hint": (reset_link if os.getenv("EMAIL_DEBUG", "false").lower()=="true" else None)}


@app.get("/auth/reset/verify", response_model=ResetVerifyOut)
def verify_reset_token(token: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    admin = _get_single_admin()
    if not admin:
        return ResetVerifyOut(valid=False, message="No admin account exists")
    token_hash = admin.get("reset_token_hash")
    expires = admin.get("reset_token_expires")
    if not token_hash or not expires:
        return ResetVerifyOut(valid=False, message="Invalid or expired token")
    try:
        # Ensure expires is datetime
        if isinstance(expires, str):
            # best-effort parse
            expires = datetime.fromisoformat(expires)
    except Exception:
        return ResetVerifyOut(valid=False, message="Invalid or expired token")
    if datetime.now(timezone.utc) > expires.replace(tzinfo=timezone.utc):
        return ResetVerifyOut(valid=False, message="Token expired")
    if not bcrypt.verify(token, token_hash):
        return ResetVerifyOut(valid=False, message="Invalid token")
    return ResetVerifyOut(valid=True)


@app.post("/auth/reset")
def reset_password(payload: ResetPasswordIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    admin = _get_single_admin()
    if not admin:
        raise HTTPException(status_code=404, detail="No admin account exists")

    token_hash = admin.get("reset_token_hash")
    expires = admin.get("reset_token_expires")
    if not token_hash or not expires:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if isinstance(expires, str):
        try:
            expires = datetime.fromisoformat(expires)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

    if datetime.now(timezone.utc) > expires.replace(tzinfo=timezone.utc):
        # cleanup
        db["admin"].update_one({"_id": admin["_id"]}, {"$unset": {"reset_token_hash": "", "reset_token_expires": ""}})
        raise HTTPException(status_code=400, detail="Token expired")

    if not bcrypt.verify(payload.token, token_hash):
        raise HTTPException(status_code=400, detail="Invalid token")

    new_hash = bcrypt.hash(payload.new_password)
    db["admin"].update_one(
        {"_id": admin["_id"]},
        {
            "$set": {"password_hash": new_hash},
            "$unset": {"reset_token_hash": "", "reset_token_expires": "", "current_token": ""}
        }
    )

    return {"success": True, "message": "Password reset successful. Please log in."}


# -------- Developer-only fallback reset mode (no email) ---------------
@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_form():
    if os.getenv("RESET_MODE", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")
    html = """
    <html><head><title>PixFlow — Developer Reset</title>
    <style>body{font-family:system-ui, -apple-system, Segoe UI, Roboto; background:#f6fbff; display:flex; align-items:center; justify-content:center; height:100vh;}
    .card{background:white; padding:24px; border-radius:16px; box-shadow:0 10px 30px rgba(56,189,248,.2);} .btn{background:linear-gradient(90deg,#0ea5e9,#14b8a6); color:white; padding:10px 14px; border:none; border-radius:999px}
    input{padding:10px 12px; border-radius:10px; border:1px solid #e5e7eb; width:100%;}
    </style></head><body>
    <div class=\"card\">
      <h2>PixFlow — Developer Password Reset</h2>
      <p style=\"color:#334155;font-size:14px;\">RESET_MODE is enabled. Set a new admin password below.</p>
      <form method=\"post\" action=\"/reset-password\">
        <input type=\"password\" name=\"new_password\" placeholder=\"New Password\" required minlength=\"6\" />
        <br/><br/>
        <button class=\"btn\" type=\"submit\">Set New Password</button>
      </form>
    </div>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password_apply(new_password: str = Form(...)):
    if os.getenv("RESET_MODE", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")
    admin = _get_single_admin()
    if not admin:
        raise HTTPException(status_code=404, detail="No admin account exists")
    new_hash = bcrypt.hash(new_password)
    db["admin"].update_one({"_id": admin["_id"]}, {"$set": {"password_hash": new_hash}, "$unset": {"reset_token_hash": "", "reset_token_expires": "", "current_token": ""}})
    return HTMLResponse("<html><body style='font-family:system-ui; display:flex; align-items:center; justify-content:center; height:100vh; background:#f6fbff'><div style='background:white;padding:24px;border-radius:16px;box-shadow:0 10px 30px rgba(56,189,248,.2)'><h3>Password updated.</h3><p>You can now <a href='/' style='color:#0ea5e9'>return to the app</a> and log in.</p></div></body></html>")


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
