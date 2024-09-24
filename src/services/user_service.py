from datetime import datetime
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
import jwt
from pymongo import MongoClient
from bson.objectid import ObjectId
from fastapi import Depends, HTTPException
from src.config import ALGORITHM, DATABASE_URL, SECRET_KEY

client = MongoClient(DATABASE_URL)
db = client["test"]
collection = db["test"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_list_users(skip: int, limit: int, current_user: dict):
    users = collection.find({"_id":{"$ne":ObjectId(current_user['_id'])}},{'password':0}).skip(skip).limit(limit)
    total = collection.count_documents({"_id":{"$ne":ObjectId(current_user['_id'])}})
    user_list = []
    for user in users:
        user['_id'] = str(user['_id'])
        user_list.append(user)
    return {"users": user_list, "skip": skip, "limit": limit, "total": total}
    

def create_user(data: dict):
    # Check if user already exists
    existing_user = collection.find_one({"email": data.get("email")})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Insert new user into the collection
    result = collection.insert_one(data)
    
    # Return the created user with its ID
    created_user = collection.find_one({"_id": result.inserted_id},{'password':0})
    return created_user

def get_user(user_id: str, current_user: dict):
    # Ensure the user is authenticated
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = get_user_by_id(user_id)
    
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Signature has expired")
    except JWTError:
        raise credentials_exception
    user = collection.find_one({"email": email}, {"password": 0})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
    





def get_user_by_email(email, hide_password=True):
    user = collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if hide_password:
        user.pop("password", None)
    return user




def get_user_by_id(user_id: str):
    user = collection.find_one({"_id": ObjectId(user_id)},{"password":0})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user['_id'] = str(user['_id'])
    return user