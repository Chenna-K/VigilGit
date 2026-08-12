from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import logging
import requests 
import psutil
from .scanner import DiffScanner
app = FastAPI()

# single scanner instance
scanner = DiffScanner()


class ScannerRequest(BaseModel):
    diff: str


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
async def webhook_listener(request: Request):
    monitor = setup_logging()
    headers = dict(request.headers)
    payload =  await request.json()
    monitor.info("Received webhook with headers: %s", headers)
    monitor.info("Received webhook data: %s", payload)
    return {"status" : "received"}


@app.post("/scanner")
async def scanner_endpoint(payload: ScannerRequest):
    """Accepts a JSON body with a `diff` string and returns found secrets."""
    findings = scanner.scan_diff(payload.diff)
    return JSONResponse(content={"findings": findings}, status_code=200)