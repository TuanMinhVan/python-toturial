from fastapi.security import OAuth2PasswordBearer
from pymongo import MongoClient
from bson.objectid import ObjectId
from fastapi import Depends, HTTPException,status
from src.models.user import User
from src.config import DATABASE_URL

client = MongoClient(DATABASE_URL)
db = client["test"]
collection = db["users"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_list_users(skip: int, limit: int, current_user: User):
    userNotEqual = {"$ne":ObjectId(current_user.id)}
    users = collection.find({"_id":userNotEqual}).skip(skip).limit(limit)
    total = collection.count_documents({"_id":userNotEqual})
    user_list = [User(**user, password=None) for user in users]
    return {"users": user_list, "skip": skip, "limit": limit, "total": total}
   
    

def create_user(data: dict) -> User:
    # Check if user already exists
    existing_user = collection.find_one({"email": data.get("email")})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Insert new user into the collection
    result = collection.insert_one(data)
    
    # Return the created user with its ID
    created_user = collection.find_one({"_id": result.inserted_id},{'password':0})
    return created_user

def get_user(user_id: str, current_user: User) -> User:
    # Ensure the user is authenticated
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    user = get_user_by_id(user_id)
    
    return user




def get_user_by_email(email:str, hide_password:bool=True) -> User:
    user = collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if hide_password:
        user.pop("password", None)
    return User(**user)




def get_user_by_id(user_id: str) -> User:
    user = collection.find_one({"_id": ObjectId(user_id)},{"password":0})
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user['_id'] = str(user['_id'])
    return user