import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import settings
from .core.database import Base, SessionLocal, engine
from .core.security import hash_password
from .ml import predict as ml
from .models import User
from .routers import admin, auth, history, predict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fakeapp")


def seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == "admin").first():
            db.add(User(email=settings.ADMIN_EMAIL, full_name="System Administrator",
                       hashed_password=hash_password(settings.ADMIN_PASSWORD), role="admin"))
            db.commit()
            log.info("Seeded admin account: %s", settings.ADMIN_EMAIL)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    seed_admin()
    try:
        ml.load()
        log.info("Model loaded: %s", ml.model_info()["model_name"])
    except Exception as e:
        log.warning("Model not loaded (%s). Train one before serving predictions.", e)
    yield


app = FastAPI(
    title=settings.APP_NAME, version=settings.VERSION,
    description="ML + NLP powered detection of fake and malicious mobile applications.",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS,
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(auth.router)
app.include_router(predict.router)
app.include_router(history.router)
app.include_router(admin.router)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Something went wrong on our side. Try again."})


@app.get("/api/health")
def health():
    return {"status": "ok", "version": settings.VERSION, "model_loaded": ml.is_ready()}
