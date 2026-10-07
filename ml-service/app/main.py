"""CyberShield ML service (FastAPI)."""
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
import xgboost
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from app import predictors
from app.schemas import (
    HealthResponse,
    NetworkRequest,
    NetworkResponse,
    Prediction,
    TextRequest,
    UrlRequest,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s"
)

log = logging.getLogger("cybershield.ml")

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False
)


def require_api_key(
    provided: str | None = Security(api_key_header)
) -> None:
    expected = os.getenv("ML_API_KEY", "")

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Server misconfigured: ML_API_KEY is not set."
        )

    if (
        not provided
        or not secrets.compare_digest(
            provided.encode(),
            expected.encode()
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    predictors.store.load()
    log.info("Mode: %s", predictors.store.mode())
    yield


app = FastAPI(
    title="CyberShield ML Service",
    description="URL, message and network-traffic threat detection.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
def root() -> dict:
    return {
        "service": "CyberShield ML service",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse)
def health() -> dict:
    return {
        "status": "ok",
        "mode": predictors.store.mode(),
        "models": predictors.store.status(),
        "versions": {
            "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }


@app.post(
    "/predict/url",
    response_model=Prediction,
    dependencies=[Depends(require_api_key)]
)
def predict_url(body: UrlRequest) -> dict:
    return predictors.predict_url(body.url)


@app.post(
    "/predict/text",
    response_model=Prediction,
    dependencies=[Depends(require_api_key)]
)
def predict_text(body: TextRequest) -> dict:
    return predictors.predict_text(body.text)


@app.post(
    "/predict/network",
    response_model=NetworkResponse,
    dependencies=[Depends(require_api_key)]
)
def predict_network(body: NetworkRequest) -> dict:
    try:
        return predictors.predict_network(body.rows)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        ) from exc


@app.get(
    "/metrics",
    dependencies=[Depends(require_api_key)]
)
def metrics() -> dict:
    data = predictors.load_metrics()

    if data is None:
        raise HTTPException(
            status_code=404,
            detail="metrics.json not found in the model directory."
        )

    return data
