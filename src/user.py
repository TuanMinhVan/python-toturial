from fastapi import HTTPException, Depends
from pymongo import MongoClient
from bson.objectid import ObjectId
from pydantic import ValidationError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from google.oauth2 import id_token
from google.auth.transport import requests

from .model.user import User

SECRET_KEY = "f4e7e7b1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = MongoClient("mongodb://localhost:27017/")
db = client["test"]
collection = db["test"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = collection.find_one({"email": email}, {"password": 0})
    if user is None:
        raise credentials_exception
    return user

def get_list_users(skip: int = 0, limit: int = 10, current_user: dict = Depends(get_current_user)):
    users = collection.find({"_id":{"$ne":ObjectId(current_user['_id'])}},{'password':0}).skip(skip).limit(limit)
    total = collection.count_documents({"_id":{"$ne":ObjectId(current_user['_id'])}})
    user_list = []
    for user in users:
        user['_id'] = str(user['_id'])
        user_list.append(user)
    return {"users": user_list, "skip": skip, "limit": limit, "total": total}

def create_user(data: dict):
    try:
        user = User(**data)
        
        # Check if a user with the same email already exists
        if collection.find_one({"email": user.email}):
            raise HTTPException(status_code=400, detail="Email already registered")
        
        user.password = get_password_hash(user.password)
        result = collection.insert_one(user.model_dump())
        return {"id": str(result.inserted_id), "message": "User created successfully"}
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def get_user(user_id: str, current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        _id = ObjectId(user_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = collection.find_one({"_id": _id, "password": 0})
    
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    user['_id'] = str(user['_id'])
    return {"user": user}

async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def login(data: dict):
    email = data.get('email')
    password = data.get('password')
    user = collection.find_one({"email": email})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    user['_id'] = str(user['_id'])
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user": user}

def login_google(token: str):
    try:
        idInfo = id_token.verify_oauth2_token(token, requests.Request())
        email = idInfo['email']
        user = collection.find_one({"email": email})
        if not user:
            user_data = {
                "email": email,
                "firstName": idInfo.get("given_name", ""),
                "lastName": idInfo.get("family_name", ""),
                "password": get_password_hash("default@Password123") 
            }
            user = User(**user_data)
            result = collection.insert_one(user.model_dump())
            user['_id'] = str(result.inserted_id)
        else:
            user['_id'] = str(user['_id'])
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"]}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "user": user}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Google token")

def register(data: dict):
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    
    import re
    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,24}$'
    )
    if not password_pattern.match(password):
        raise HTTPException(status_code=400, detail="Password must be 8-24 characters long, contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol")
    
    existing_user = collection.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(password)
    new_user = {
        "email": email,
        "password": hashed_password
    }
    
    result = collection.insert_one(new_user)
    if result.inserted_id:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": new_user["email"]}, expires_delta=access_token_expires
        )
        new_user['_id'] = str(result.inserted_id)
        new_user.pop("password", None)
        return {"user": new_user, "access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=500, detail="Registration failed")

def read_users_me(current_user: dict = Depends(get_current_user)):
    current_user['_id'] = str(current_user['_id'])
    return current_user

def update_users_me(data: dict, current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    _id = ObjectId(current_user['_id'])
    
    user = collection.find_one({"_id": _id}, {"password": 0})

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent updating email and password
    data.pop("email", None)
    data.pop("password", None)
    
    update_data = {k: v for k, v in data.items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    
    # Check if update data is the same as current data
    if all(user.get(k) == v for k, v in update_data.items()):
        user['_id'] = str(user['_id'])
        return {"user": user}
    
    filter = {"_id": _id}
    update = {"$set": update_data}

    result = collection.update_one(filter, update)

    if result.modified_count == 0:
        raise HTTPException(status_code=500, detail="Update data failed")
    
    updated_user = collection.find_one({"_id": _id})
    updated_user['_id'] = str(updated_user['_id'])
    return {"user": updated_user}
