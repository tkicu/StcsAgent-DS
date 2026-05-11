import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Session, sessionmaker, relationship, declarative_base


# ---------- Database ----------
DATABASE_URL = "sqlite:///./easm.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------- Models ----------
class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    type = Column(String, default="domain")
    value = Column(String, nullable=False)
    discovery_date = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="active")
    tags = Column(String, default="")
    notes = Column(Text, default="")
    risk_score = Column(Float, default=0.0)
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete")
    tasks = relationship("Task", back_populates="asset", cascade="all, delete")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    title = Column(String, nullable=False)
    severity = Column(String, default="medium")
    description = Column(Text, default="")
    cve = Column(String, default="")
    discovered_date = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="open")
    asset = relationship("Asset", back_populates="vulnerabilities")
    tasks = relationship("Task", back_populates="vulnerability", cascade="all, delete")

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    assigned_to = Column(String, default="unassigned")
    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    due_date = Column(DateTime, nullable=True)
    status = Column(String, default="pending")
    asset = relationship("Asset", back_populates="tasks")
    vulnerability = relationship("Vulnerability", back_populates="tasks")

Base.metadata.create_all(bind=engine)

# ---------- Pydantic schemas ----------
class AssetCreate(BaseModel):
    name: str
    type: str = "domain"
    value: str
    tags: str = ""
    notes: str = ""

class AssetUpdate(BaseModel):
    status: Optional[str] = None
    tags: Optional[str] = None
    notes: Optional[str] = None

class VulnerabilityCreate(BaseModel):
    asset_id: int
    title: str
    severity: str = "medium"
    description: str = ""
    cve: str = ""

class VulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None

class TaskCreate(BaseModel):
    asset_id: int
    vuln_id: Optional[int] = None
    title: str
    description: str = ""
    assigned_to: str = "unassigned"
    due_date: Optional[str] = None

class TaskUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None

# ---------- FastAPI app ----------
app = FastAPI(title="EASM Lifecycle Agent")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- Agent logic ----------
def agent_update_asset_risk(asset_id: int, db: Session):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return
    vulns = db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).all()
    if not vulns:
        asset.risk_score = 0.0
    else:
        weight_map = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        total = sum(weight_map.get(v.severity, 0) for v in vulns)
        asset.risk_score = min(100, total)
    db.commit()

def agent_create_remediation_task(vuln_id: int, db: Session):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln or vuln.severity not in ("critical", "high"):
        return
    existing = db.query(Task).filter(Task.vuln_id == vuln_id, Task.title == f"Fix: {vuln.title}").first()
    if existing:
        return
    task = Task(
        asset_id=vuln.asset_id,
        vuln_id=vuln.id,
        title=f"Fix: {vuln.title}",
        description=vuln.description or "Auto-generated high-priority remediation task",
        assigned_to="Security Team",
        due_date=datetime.datetime.utcnow() + datetime.timedelta(days=7),
        status="pending"
    )
    db.add(task)
    db.commit()

# ---------- Page routes ----------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    total_assets = db.query(Asset).count()
    total_vulns = db.query(Vulnerability).count()
    open_vulns = db.query(Vulnerability).filter(Vulnerability.status == "open").count()
    total_tasks = db.query(Task).count()
    pending_tasks = db.query(Task).filter(Task.status == "pending").count()
    risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in db.query(Vulnerability).all():
        if v.severity in risk_levels:
            risk_levels[v.severity] += 1
    top_risk_assets = db.query(Asset).order_by(Asset.risk_score.desc()).limit(5).all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_assets": total_assets,
        "total_vulns": total_vulns,
        "open_vulns": open_vulns,
        "total_tasks": total_tasks,
        "pending_tasks": pending_tasks,
        "risk_levels": risk_levels,
        "top_risk_assets": top_risk_assets
    })

@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return templates.TemplateResponse("assets.html", {"request": request, "assets": assets})

@app.get("/vulnerabilities", response_class=HTMLResponse)
def vulns_page(request: Request, db: Session = Depends(get_db)):
    vulns = db.query(Vulnerability).all()
    assets = db.query(Asset).all()
    return templates.TemplateResponse("vulnerabilities.html", {"request": request, "vulnerabilities": vulns, "assets": assets})

@app.get("/tasks", response_class=HTMLResponse)
def tasks_page(request: Request, db: Session = Depends(get_db)):
    tasks = db.query(Task).all()
    assets = db.query(Asset).all()
    return templates.TemplateResponse("tasks.html", {"request": request, "tasks": tasks, "assets": assets})

# ---------- API routes ----------
@app.post("/api/assets")
def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    db_asset = Asset(**asset.dict(), risk_score=0.0, status="active")
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset

@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: int, update: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if update.status is not None:
        asset.status = update.status
    if update.tags is not None:
        asset.tags = update.tags
    if update.notes is not None:
        asset.notes = update.notes
    db.commit()
    return {"ok": True}

@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    db.commit()
    return {"ok": True}

@app.post("/api/vulnerabilities")
def create_vulnerability(vuln: VulnerabilityCreate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    db_vuln = Vulnerability(**vuln.dict(), status="open")
    db.add(db_vuln)
    db.commit()
    db.refresh(db_vuln)
    agent_update_asset_risk(vuln.asset_id, db)
    agent_create_remediation_task(db_vuln.id, db)
    return db_vuln

@app.put("/api/vulnerabilities/{vuln_id}")
def update_vulnerability(vuln_id: int, update: VulnerabilityUpdate, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    if update.status is not None:
        vuln.status = update.status
    if update.severity is not None:
        vuln.severity = update.severity
    db.commit()
    agent_update_asset_risk(vuln.asset_id, db)
    return {"ok": True}

@app.delete("/api/vulnerabilities/{vuln_id}")
def delete_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    asset_id = vuln.asset_id
    db.delete(vuln)
    db.commit()
    agent_update_asset_risk(asset_id, db)
    return {"ok": True}

@app.post("/api/tasks")
def create_task(task: TaskCreate, db: Session = Depends(get_db)):
    if task.due_date:
        due_date = datetime.datetime.strptime(task.due_date, "%Y-%m-%d")
    else:
        due_date = None
    db_task = Task(
        asset_id=task.asset_id,
        vuln_id=task.vuln_id,
        title=task.title,
        description=task.description,
        assigned_to=task.assigned_to,
        due_date=due_date
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.put("/api/tasks/{task_id}")
def update_task(task_id: int, update: TaskUpdate, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "Task not found")
    if update.status is not None:
        task.status = update.status
    if update.assigned_to is not None:
        task.assigned_to = update.assigned_to
    db.commit()
    return {"ok": True}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "Task not found")
    db.delete(task)
    db.commit()
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
