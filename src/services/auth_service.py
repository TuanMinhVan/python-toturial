import re
from fastapi import HTTPException
from jose import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from src.services.user_service import create_user, get_user_by_email
from src.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

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



def login(data: dict):
    email = data.get("email")
    password = data.get("password")
    
    user = get_user_by_email(email, False)
    
    if not user:
        return {"error": "User not found"}
    
    if not verify_password(password, user["password"]):
        return {"error": "Incorrect password"}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    user['_id'] = str(user['_id'])
    user.pop("password", None)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user": user}

def register(data: dict):
    email = data.get("email")
    password = data.get("password")

    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,24}$'
    )
    if not password_pattern.match(password):
        raise HTTPException(status_code=400, detail="Password must be 8-24 characters long, contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol")
    

    new_user = {
        "email": email,
        "password": get_password_hash(password),
    }

    created_user =  create_user(new_user)

    created_user['_id'] = str(created_user['_id'])
    created_user.pop("password", None)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(
        data={"sub": created_user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user": created_user}






def logout(data: dict):
    return {"message": "Logout successful"}