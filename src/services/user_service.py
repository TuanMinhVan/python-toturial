from fastapi.security import OAuth2PasswordBearer
from pymongo import MongoClient
from bson.objectid import ObjectId
from fastapi import HTTPException,status
from src.models.user import ResponseBase, User
from src.config import DATABASE_URL

client = MongoClient(DATABASE_URL)
db = client["test"]
collection = db["users"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_list_users(skip: int, limit: int, current_user: User):
    userNotEqual = {"$ne":ObjectId(current_user.id)}
    users = collection.find({"_id":userNotEqual}).skip(skip).limit(limit)
    total = collection.count_documents({"_id":userNotEqual})
    user_list = [User(**user, password=None).ignore_password() for user in users]
    return ResponseBase(
        status=200,
        message="Get list users successful",
        data={
            "users": user_list,
            "skip": skip,
            "limit": limit,
            "total": total
        }
    )
    
    

def create_user(data: dict) -> bool:
    # Check if user already exists
    existing_user = collection.find_one({"email": data.get("email")})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    # Insert new user into the collection
    result = collection.insert_one(data)
    if result.inserted_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Create user failed"
        )
    return True

def get_user(user_id: str | None = None, current_user: User | None = None   ) -> ResponseBase:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated"
        )
    
    # Get user by id if user_id is not None
    if user_id is None:
        user_id = current_user.id

    # If user_id is None, return 404
    if user_id is None:
        return ResponseBase(status=404, message="User not found")    
    
    # Get user by id
    user = get_user_by_id(user_id)

    # Return user
    return ResponseBase(
        status=200, 
        message="Get user successful", 
        data=user.ignore_password()
    )




def get_user_by_email(email: str) -> User:
    user = collection.find_one({"email": email})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return User(**user)




def get_user_by_id(user_id: str) -> User :
    user = collection.find_one({"_id":user_id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return User(**user)




def delete_user(email: str):
    result = collection.delete_one({"email": email})
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return ResponseBase(
        status=200,
        message="Delete user successful"
    )