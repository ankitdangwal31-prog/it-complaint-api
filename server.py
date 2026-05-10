from fastapi import FastAPI, APIRouter

app = FastAPI()

api_router = APIRouter()

@api_router.get("/")
async def root():
    return {"message": "IT Complaint API is running"}

app.include_router(api_router)