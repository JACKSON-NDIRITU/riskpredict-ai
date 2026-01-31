from fastapi import FastAPI
from app.routers import ingest, alerts, health

app = FastAPI()

# Include routers
app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(health.router)

# Optional: simple root route
@app.get("/")
def root():
    return {"message": "Real-Time Cyber Threat Detection System is running"}
