

from fastapi import FastAPI
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import bcrypt


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 10080))
ADMIN_EMAIL = os.environ['ADMIN_EMAIL']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']

api_router = APIRouter(prefix="/api")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ======================= MODELS =======================
Role = Literal["admin", "engineer", "outlet_staff"]
Category = Literal["POS Issue", "Internet Issue", "Printer Issue", "CCTV Issue", "Other"]
Priority = Literal["Low", "Medium", "High", "Critical"]
Status = Literal["Open", "In Progress", "Resolved", "Closed"]


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str
    role: Role = "outlet_staff"
    whatsapp: Optional[str] = None
    outlet_name: Optional[str] = None


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: Role
    whatsapp: Optional[str] = None
    outlet_name: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class ComplaintCreate(BaseModel):
    outlet_name: str
    category: Category
    priority: Priority = "Medium"
    title: str
    description: str
    whatsapp_contact: Optional[str] = None
    image_base64: Optional[str] = None  # data URI or raw base64


class ComplaintUpdate(BaseModel):
    status: Optional[Status] = None
    priority: Optional[Priority] = None
    assigned_engineer_id: Optional[str] = None
    resolution_notes: Optional[str] = None


class ComplaintOut(BaseModel):
    id: str
    outlet_name: str
    category: Category
    priority: Priority
    status: Status
    title: str
    description: str
    whatsapp_contact: Optional[str] = None
    image_base64: Optional[str] = None
    created_by_id: str
    created_by_name: str
    assigned_engineer_id: Optional[str] = None
    assigned_engineer_name: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: str
    updated_at: str


class DashboardStats(BaseModel):
    total: int
    open: int
    in_progress: int
    resolved: int
    closed: int
    by_category: dict
    by_priority: dict
    recent: List[ComplaintOut]


# ======================= HELPERS =======================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def user_doc_to_out(doc: dict) -> UserOut:
    return UserOut(
        id=doc["id"],
        email=doc["email"],
        full_name=doc["full_name"],
        role=doc["role"],
        whatsapp=doc.get("whatsapp"),
        outlet_name=doc.get("outlet_name"),
    )


def complaint_doc_to_out(doc: dict) -> ComplaintOut:
    return ComplaintOut(
        id=doc["id"],
        outlet_name=doc["outlet_name"],
        category=doc["category"],
        priority=doc["priority"],
        status=doc["status"],
        title=doc["title"],
        description=doc["description"],
        whatsapp_contact=doc.get("whatsapp_contact"),
        image_base64=doc.get("image_base64"),
        created_by_id=doc["created_by_id"],
        created_by_name=doc["created_by_name"],
        assigned_engineer_id=doc.get("assigned_engineer_id"),
        assigned_engineer_name=doc.get("assigned_engineer_name"),
        resolution_notes=doc.get("resolution_notes"),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
    )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    cred_exc = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise cred_exc
    except jwt.PyJWTError:
        raise cred_exc
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise cred_exc
    return user


def require_roles(*allowed: str):
    async def checker(user: dict = Depends(get_current_user)):
        if user["role"] not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


# ======================= ROUTES: AUTH =======================
@api_router.post("/auth/register", response_model=UserOut)
async def register(payload: UserCreate, current=Depends(get_current_user)):
    # only admin can create users with non-default roles
    if payload.role != "outlet_staff" and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create privileged users")
    existing = await db.users.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "full_name": payload.full_name,
        "role": payload.role,
        "whatsapp": payload.whatsapp,
        "outlet_name": payload.outlet_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc)
    return user_doc_to_out(doc)


@api_router.post("/auth/signup", response_model=TokenOut)
async def signup(payload: UserCreate):
    """Public self-signup (always creates outlet_staff)."""
    existing = await db.users.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "full_name": payload.full_name,
        "role": "outlet_staff",
        "whatsapp": payload.whatsapp,
        "outlet_name": payload.outlet_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc)
    token = create_access_token({"sub": user_id, "role": doc["role"]})
    return TokenOut(access_token=token, user=user_doc_to_out(doc))


@api_router.post("/auth/login", response_model=TokenOut)
async def login(payload: LoginIn):
    user = await db.users.find_one({"email": payload.email.lower()}, {"_id": 0})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["id"], "role": user["role"]})
    return TokenOut(access_token=token, user=user_doc_to_out(user))


@api_router.get("/auth/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return user_doc_to_out(user)


@api_router.get("/users/engineers", response_model=List[UserOut])
async def list_engineers(user=Depends(get_current_user)):
    engs = await db.users.find({"role": "engineer"}, {"_id": 0}).to_list(500)
    return [user_doc_to_out(e) for e in engs]


@api_router.get("/users", response_model=List[UserOut])
async def list_users(user=Depends(require_roles("admin"))):
    users = await db.users.find({}, {"_id": 0}).to_list(1000)
    return [user_doc_to_out(u) for u in users]


# ======================= ROUTES: COMPLAINTS =======================
@api_router.post("/complaints", response_model=ComplaintOut)
async def create_complaint(payload: ComplaintCreate, user=Depends(get_current_user)):
    cid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": cid,
        "outlet_name": payload.outlet_name,
        "category": payload.category,
        "priority": payload.priority,
        "status": "Open",
        "title": payload.title,
        "description": payload.description,
        "whatsapp_contact": payload.whatsapp_contact or user.get("whatsapp"),
        "image_base64": payload.image_base64,
        "created_by_id": user["id"],
        "created_by_name": user["full_name"],
        "assigned_engineer_id": None,
        "assigned_engineer_name": None,
        "resolution_notes": None,
        "created_at": now,
        "updated_at": now,
    }
    await db.complaints.insert_one(doc)
    return complaint_doc_to_out(doc)


@api_router.get("/complaints", response_model=List[ComplaintOut])
async def list_complaints(
    status_filter: Optional[str] = None,
    category: Optional[str] = None,
    priority: Optional[str] = None,
    scope: Optional[str] = None,  # mine | assigned | all
    user=Depends(get_current_user),
):
    query = {}
    if status_filter:
        if status_filter == "open":
            query["status"] = {"$in": ["Open", "In Progress"]}
        elif status_filter == "closed":
            query["status"] = {"$in": ["Resolved", "Closed"]}
        else:
            query["status"] = status_filter
    if category:
        query["category"] = category
    if priority:
        query["priority"] = priority

    if scope == "mine" or (user["role"] == "outlet_staff" and scope != "all"):
        query["created_by_id"] = user["id"]
    elif scope == "assigned" or (user["role"] == "engineer" and scope != "all"):
        query["assigned_engineer_id"] = user["id"]

    docs = await db.complaints.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)
    return [complaint_doc_to_out(d) for d in docs]


@api_router.get("/complaints/{complaint_id}", response_model=ComplaintOut)
async def get_complaint(complaint_id: str, user=Depends(get_current_user)):
    doc = await db.complaints.find_one({"id": complaint_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Complaint not found")
    return complaint_doc_to_out(doc)


@api_router.patch("/complaints/{complaint_id}", response_model=ComplaintOut)
async def update_complaint(complaint_id: str, payload: ComplaintUpdate, user=Depends(get_current_user)):
    doc = await db.complaints.find_one({"id": complaint_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Complaint not found")

    role = user["role"]
    updates: dict = {}

    if payload.assigned_engineer_id is not None:
        if role != "admin":
            raise HTTPException(status_code=403, detail="Only admin can assign engineers")
        eng = await db.users.find_one({"id": payload.assigned_engineer_id, "role": "engineer"}, {"_id": 0})
        if not eng:
            raise HTTPException(status_code=400, detail="Engineer not found")
        updates["assigned_engineer_id"] = eng["id"]
        updates["assigned_engineer_name"] = eng["full_name"]
        if doc["status"] == "Open":
            updates["status"] = "In Progress"

    if payload.priority is not None:
        if role not in ("admin", "engineer"):
            raise HTTPException(status_code=403, detail="Cannot change priority")
        updates["priority"] = payload.priority

    if payload.status is not None:
        if role == "outlet_staff":
            # outlet staff can only close their own resolved complaints
            if doc["created_by_id"] != user["id"]:
                raise HTTPException(status_code=403, detail="Forbidden")
            if payload.status != "Closed":
                raise HTTPException(status_code=403, detail="Outlet staff can only close")
        updates["status"] = payload.status

    if payload.resolution_notes is not None:
        if role not in ("admin", "engineer"):
            raise HTTPException(status_code=403, detail="Cannot add resolution notes")
        updates["resolution_notes"] = payload.resolution_notes

    if not updates:
        return complaint_doc_to_out(doc)

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.complaints.update_one({"id": complaint_id}, {"$set": updates})
    new_doc = await db.complaints.find_one({"id": complaint_id}, {"_id": 0})
    return complaint_doc_to_out(new_doc)


@api_router.delete("/complaints/{complaint_id}")
async def delete_complaint(complaint_id: str, user=Depends(require_roles("admin"))):
    res = await db.complaints.delete_one({"id": complaint_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": True}


# ======================= ROUTES: DASHBOARD =======================
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats(user=Depends(get_current_user)):
    base_query = {}
    if user["role"] == "outlet_staff":
        base_query["created_by_id"] = user["id"]
    elif user["role"] == "engineer":
        base_query["assigned_engineer_id"] = user["id"]

    docs = await db.complaints.find(base_query, {"_id": 0}).to_list(2000)

    total = len(docs)
    open_count = sum(1 for d in docs if d["status"] == "Open")
    in_progress = sum(1 for d in docs if d["status"] == "In Progress")
    resolved = sum(1 for d in docs if d["status"] == "Resolved")
    closed = sum(1 for d in docs if d["status"] == "Closed")

    by_category: dict = {}
    by_priority: dict = {}
    for d in docs:
        by_category[d["category"]] = by_category.get(d["category"], 0) + 1
        by_priority[d["priority"]] = by_priority.get(d["priority"], 0) + 1

    recent_docs = sorted(docs, key=lambda x: x["created_at"], reverse=True)[:5]
    recent = [complaint_doc_to_out(d) for d in recent_docs]

    return DashboardStats(
        total=total,
        open=open_count,
        in_progress=in_progress,
        resolved=resolved,
        closed=closed,
        by_category=by_category,
        by_priority=by_priority,
        recent=recent,
    )


@api_router.get("/")
async def root():
    return {"message": "IT Complaint API", "status": "ok"}


# ======================= STARTUP =======================
async def seed_data():
    # Seed admin
    admin = await db.users.find_one({"email": ADMIN_EMAIL.lower()})
    if not admin:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": ADMIN_EMAIL.lower(),
            "password_hash": hash_password(ADMIN_PASSWORD),
            "full_name": "Admin User",
            "role": "admin",
            "whatsapp": "+919999900000",
            "outlet_name": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"Seeded admin: {ADMIN_EMAIL}")

    # Seed engineers
    engineers = [
        ("engineer1@restaurant.com", "Engineer@123", "Rahul Sharma", "+919876543210"),
        ("engineer2@restaurant.com", "Engineer@123", "Priya Patel", "+919876543211"),
    ]
    for email, pwd, name, wa in engineers:
        e = await db.users.find_one({"email": email})
        if not e:
            await db.users.insert_one({
                "id": str(uuid.uuid4()),
                "email": email,
                "password_hash": hash_password(pwd),
                "full_name": name,
                "role": "engineer",
                "whatsapp": wa,
                "outlet_name": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    # Seed outlet staff demo
    outlets = [
        ("outlet1@restaurant.com", "Outlet@123", "Marina Cafe Manager", "Marina Cafe", "+919812345678"),
        ("outlet2@restaurant.com", "Outlet@123", "Downtown Bistro Manager", "Downtown Bistro", "+919812345679"),
    ]
    for email, pwd, name, outlet, wa in outlets:
        o = await db.users.find_one({"email": email})
        if not o:
            await db.users.insert_one({
                "id": str(uuid.uuid4()),
                "email": email,
                "password_hash": hash_password(pwd),
                "full_name": name,
                "role": "outlet_staff",
                "whatsapp": wa,
                "outlet_name": outlet,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    # Seed sample complaints if empty
    count = await db.complaints.count_documents({})
    if count == 0:
        outlet1 = await db.users.find_one({"email": "outlet1@restaurant.com"})
        outlet2 = await db.users.find_one({"email": "outlet2@restaurant.com"})
        eng1 = await db.users.find_one({"email": "engineer1@restaurant.com"})
        if outlet1 and outlet2 and eng1:
            now = datetime.now(timezone.utc)
            samples = [
                {
                    "outlet_name": "Marina Cafe", "category": "POS Issue", "priority": "High",
                    "status": "Open", "title": "POS terminal not booting",
                    "description": "Main billing POS won't power on after morning startup.",
                    "creator": outlet1, "engineer": None,
                },
                {
                    "outlet_name": "Marina Cafe", "category": "Internet Issue", "priority": "Critical",
                    "status": "In Progress", "title": "Internet down at outlet",
                    "description": "No internet since 9 AM, affecting card payments.",
                    "creator": outlet1, "engineer": eng1,
                },
                {
                    "outlet_name": "Downtown Bistro", "category": "Printer Issue", "priority": "Medium",
                    "status": "Resolved", "title": "Kitchen printer offline",
                    "description": "Receipt printer in kitchen disconnects intermittently.",
                    "creator": outlet2, "engineer": eng1,
                    "resolution": "Replaced USB cable and updated drivers."
                },
                {
                    "outlet_name": "Downtown Bistro", "category": "CCTV Issue", "priority": "Low",
                    "status": "Closed", "title": "CCTV camera 3 blurry",
                    "description": "Camera near entrance has dirty lens.",
                    "creator": outlet2, "engineer": eng1,
                    "resolution": "Lens cleaned and refocused."
                },
            ]
            for i, s in enumerate(samples):
                created = (now - timedelta(hours=i * 6)).isoformat()
                await db.complaints.insert_one({
                    "id": str(uuid.uuid4()),
                    "outlet_name": s["outlet_name"],
                    "category": s["category"],
                    "priority": s["priority"],
                    "status": s["status"],
                    "title": s["title"],
                    "description": s["description"],
                    "whatsapp_contact": s["creator"]["whatsapp"],
                    "image_base64": None,
                    "created_by_id": s["creator"]["id"],
                    "created_by_name": s["creator"]["full_name"],
                    "assigned_engineer_id": s["engineer"]["id"] if s["engineer"] else None,
                    "assigned_engineer_name": s["engineer"]["full_name"] if s["engineer"] else None,
                    "resolution_notes": s.get("resolution"),
                    "created_at": created,
                    "updated_at": created,
                })
            logger.info("Seeded sample complaints")


@app.on_event("startup")
async def on_startup():
    await seed_data()


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
