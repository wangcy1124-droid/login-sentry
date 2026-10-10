import os
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.queries import router
from app.db.repositories import utc_now


def create_app(database: Optional[str] = None, clock=utc_now) -> FastAPI:
    application = FastAPI(title="Login Sentry", version="0.1.0")
    application.state.database = database if database is not None else os.environ.get(
        'LOGIN_SENTRY_DATABASE', 'data/login-sentry.sqlite3')
    application.state.clock = clock
    root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(root / 'templates'))
    application.mount('/static', StaticFiles(directory=str(root / 'static')), name='static')
    application.include_router(router)

    @application.get('/api/health')
    def health() -> Dict[str, str]:
        return {"status": "ok", "service": "login-sentry"}

    @application.get('/', response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse(request=request, name='dashboard.html')

    return application


app = create_app()
