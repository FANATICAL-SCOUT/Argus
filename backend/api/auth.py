"""Auth routes: GET/POST /login, GET /logout, GET/POST /register."""
from __future__ import annotations

import hashlib
import json
import secrets

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from backend.config.settings import Settings

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers: file-backed user store
# ---------------------------------------------------------------------------

_USERS_FILE = Settings.DATA_DIR / "users.json"


def _load_users() -> list[dict]:
    if _USERS_FILE.exists():
        try:
            return json.loads(_USERS_FILE.read_text()).get("users", [])
        except Exception:
            return []
    return []


def _save_users(users: list[dict]) -> None:
    Settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    _USERS_FILE.write_text(json.dumps({"users": users}, indent=2))


def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _check_credentials(username: str, password: str) -> bool:
    """Check hardcoded admin first, then file-backed users."""
    admin_ok = (
        secrets.compare_digest(username.strip(), Settings.AUTH_USERNAME)
        and secrets.compare_digest(password, Settings.AUTH_PASSWORD)
    )
    if admin_ok:
        return True
    pw_hash = _hash_pw(password)
    for u in _load_users():
        if secrets.compare_digest(username.strip(), u.get("username", "")) and \
           secrets.compare_digest(pw_hash, u.get("password_hash", "")):
            return True
    return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return request.app.state.templates.TemplateResponse(
        request, "login.html", {"error": error},
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if _check_credentials(username, password):
        request.session["user"] = username.strip()
        return RedirectResponse(url="/", status_code=303)

    return request.app.state.templates.TemplateResponse(
        request, "login.html",
        {"error": "Invalid username or password."},
        status_code=401,
    )


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = "", success: str = ""):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return request.app.state.templates.TemplateResponse(
        request, "signup.html", {"error": error, "success": success},
    )


@router.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    username = username.strip()

    if len(username) < 3:
        return request.app.state.templates.TemplateResponse(
            request, "signup.html",
            {"error": "Username must be at least 3 characters.", "success": ""},
            status_code=400,
        )
    if len(password) < 6:
        return request.app.state.templates.TemplateResponse(
            request, "signup.html",
            {"error": "Password must be at least 6 characters.", "success": ""},
            status_code=400,
        )
    if not secrets.compare_digest(password, confirm_password):
        return request.app.state.templates.TemplateResponse(
            request, "signup.html",
            {"error": "Passwords do not match.", "success": ""},
            status_code=400,
        )

    # Reject if username already taken (admin or existing file user)
    if username == Settings.AUTH_USERNAME:
        return request.app.state.templates.TemplateResponse(
            request, "signup.html",
            {"error": "Username already taken.", "success": ""},
            status_code=400,
        )
    users = _load_users()
    if any(u["username"] == username for u in users):
        return request.app.state.templates.TemplateResponse(
            request, "signup.html",
            {"error": "Username already taken.", "success": ""},
            status_code=400,
        )

    users.append({"username": username, "password_hash": _hash_pw(password)})
    _save_users(users)

    return request.app.state.templates.TemplateResponse(
        request, "signup.html",
        {"error": "", "success": f"Account '{username}' created! You can now sign in."},
    )


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
