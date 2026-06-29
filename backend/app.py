"""FastAPI application factory for the pscan dashboard."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from backend.config.settings import Settings

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

# Paths that do NOT require authentication
_PUBLIC_PREFIXES = ("/login", "/register", "/static")


class _AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in _PUBLIC_PREFIXES):
            return await call_next(request)
        if not request.session.get("user"):
            return RedirectResponse(url="/login", status_code=302)
        return await call_next(request)


def _fmt_dt(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%b %d, %Y %H:%M")
    except Exception:
        return value


def _fmt_dur(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def create_app() -> FastAPI:
    app = FastAPI(title="pscan", version="2.0.0", docs_url=None, redoc_url=None)

    # Auth middleware (SessionMiddleware must wrap AuthMiddleware — add in reverse)
    app.add_middleware(_AuthMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=Settings.SECRET_KEY, max_age=86400)

    app.mount(
        "/static",
        StaticFiles(directory=str(_FRONTEND_DIR / "static")),
        name="static",
    )

    tmpl = Jinja2Templates(directory=str(_FRONTEND_DIR / "templates"))
    tmpl.env.filters["dt"] = _fmt_dt
    tmpl.env.filters["dur"] = _fmt_dur
    app.state.templates = tmpl

    from backend.api import (
        auth, dashboard, scan, history, reports,
        stubs, scan_api, topology, controller, help_page,
    )

    app.include_router(auth.router)        # /login, /logout (public)
    app.include_router(scan_api.router)    # /api/scan*
    app.include_router(topology.router)    # /api/topology* + /topology
    app.include_router(dashboard.router)
    app.include_router(scan.router)
    app.include_router(history.router)
    app.include_router(reports.router)
    app.include_router(controller.router)
    app.include_router(help_page.router)
    app.include_router(stubs.router)

    @app.exception_handler(404)
    async def _404(request: Request, exc):
        return tmpl.TemplateResponse(request, "errors/404.html", status_code=404)

    @app.exception_handler(500)
    async def _500(request: Request, exc):
        return tmpl.TemplateResponse(request, "errors/500.html", status_code=500)

    return app


app = create_app()
