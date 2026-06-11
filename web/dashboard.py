# web/dashboard.py
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from core.database import Database

app = FastAPI(title="Masscan Monitor Dashboard")

# Templates relative to project root
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

# Global database instance (set in main.py)
_db_instance = None

def set_db(db: Database):
    global _db_instance
    _db_instance = db

async def get_db() -> Database:
    if _db_instance is None:
        raise RuntimeError("Database not initialized")
    return _db_instance

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Database = Depends(get_db)):
    recent = await db.get_recent(limit=100)
    stats = await db.get_stats()
    
    # ИСПРАВЛЕНО: используем именованные аргументы (требование Starlette >= 0.28)
    return templates.TemplateResponse(
        name="index.html",
        request=request,
        context={
            "recent": recent,
            "stats": stats,
            "total": stats.get("total", 0),
            "unnotified": stats.get("unnotified", 0),
            "services": stats.get("services", {}),
        }
    )

@app.get("/api/findings")
async def api_findings(db: Database = Depends(get_db), limit: int = 100):
    return await db.get_recent(limit=limit)

@app.get("/api/stats")
async def api_stats(db: Database = Depends(get_db)):
    return await db.get_stats()
