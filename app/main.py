from fastapi import FastAPI

app = FastAPI(title="Login Sentry", version="0.1.0")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "login-sentry"}
