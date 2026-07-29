from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import json
import os
import hmac
import hashlib
import logging
import requests 
import psutil

load_dotenv("../.env")
app = FastAPI()



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