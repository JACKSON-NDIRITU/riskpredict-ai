from fastapi import APIRouter

router = APIRouter(prefix="/alerts")

@router.get("/")
def get_alerts():
    return []
