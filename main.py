from datetime import datetime, timedelta
import os
import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from jose import jwt
from pydantic import BaseModel, EmailStr
from supabase_client import supabase

load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = 30
ALGORITHM = "HS256"

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to Pathway!"}

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

def create_access_token(data):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/auth/register")
def register_user(user: UserCreate):
    existing_user = supabase.table("Users").select("*").eq("email", user.email).execute()

    if existing_user.data:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    response = supabase.table("Users").insert({
        "name": user.name,
        "email": user.email,
        "password": hashed_password
    }).execute()

    if "error" in response and response.error is not None:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {response.error.message}")

    return {"message": "User registered successfully"}

@app.post("/auth/login")
def login_user(user:UserLogin):
    existing_user = supabase.table("Users").select("*").eq("email", user.email).single().execute()

    if not existing_user.data:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    stored_password = existing_user.data["password"]
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

