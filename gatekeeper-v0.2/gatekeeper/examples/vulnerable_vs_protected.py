"""Misma app, con y sin Gatekeeper.

    pip install gatekeeper-asgi fastapi uvicorn
    uvicorn examples.vulnerable_vs_protected:protected --port 8001
    uvicorn examples.vulnerable_vs_protected:vulnerable --port 8000

Prueba:  curl "localhost:8001/search?q=1%20UNION%20SELECT%20password%20FROM%20users"
"""
from fastapi import FastAPI

from gatekeeper import Config, GatekeeperMiddleware


def build() -> FastAPI:
    app = FastAPI()

    @app.get("/search")
    def search(q: str = ""):
        return {"query": q}

    return app


vulnerable = build()
protected = build()
protected.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=60))
