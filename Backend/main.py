from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware 
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from database.utility.init_db import create_tables
from database.utility.protectRoute import get_current_user
from database.schema.user import UserOutput
from router.auth import authRouter
from router.scan import scanRouter
from security.limiter import limiter
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from typing import Annotated
from dotenv import load_dotenv
import json
import os
import hmac
import hashlib
import logging
import requests 
import psutil

load_dotenv("../.env")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables() # initialising the database at the start
    yield # separation

def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content= "Rate limit exceeded, please try again later."
    )

app = FastAPI(lifespan=lifespan)
origins = os.getenv("ALLOWED_ORIGINS").split(",")
app.add_middleware(CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)
app.include_router(router=authRouter, tags={"auth"}, prefix="/auth")
app.include_router(router=scanRouter, prefix="/scanner",tags=["scan"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/protected")
def read_protected(user : UserOutput = Depends(get_current_user)):
    return {"data" : user}

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if signature.startswith("sha256="):
        signature = signature.split("=")[1]
    return hmac.compare_digest(expected, signature)

def setup_logging():
    logger = logging.getLogger("WebhookMonitor")
    logging.basicConfig(level=logging.INFO)
    return logger

def check_external_service() -> bool:
    try:
        response = requests.get("http://127.0.0.1:8000", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException as err:
        print(err)
        return False

def get_performance_metrics() -> dict:
    return {
        "cpu performance" : psutil.cpu_percent(1),
        "memory percentage" : psutil.virtual_memory().percent,
    }

@app.get("/")
def read_root() -> dict:
    return {"message" : "server is running"}

@app.get("/health")
def health() -> JSONResponse:
    external_ok = check_external_service()
    metrics = get_performance_metrics()
    return JSONResponse(
        content = {
            "status": "healthy" if external_ok else "unhealthy",
            "external_service": external_ok,
            "metrics": metrics,
        },

        status_code=200 if external_ok else 503,
    )

@app.post("/webhook")
async def webhook_listener(request: Request,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    event_type: str | None = Header(default=None, alias="X-Github-Event"),
):
    monitor = setup_logging()
    body = await request.body()
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")

    if not webhook_secret:
        monitor.error("Webhook secret is not configured on server")
        raise HTTPException(status_code=500, detail="secrets folder not configured")
    monitor.debug("Webhook secret is configured")
    if not x_hub_signature_256:
        monitor.error("Missing signature")
        raise HTTPException(status_code=401, detail="Missing signature")
    if not verify_signature(body, x_hub_signature_256, webhook_secret):
        monitor.warning("Failed authentication")
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status=400, detail="Invalid JSON payload")

    action = payload.get("action", "unknown")
    monitor.info("Received event %s of the action %s", event_type, action)

    return {"status" : "received"}