import re
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from src.models.user import UserLogin, UserRegister, User
from src.services.user_service import create_user, get_user_by_email
from src.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password:str, hashed_password:str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password:str):
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



def login(data: UserLogin):
    email = data.email
    password = data.password
    
    user = get_user_by_email(email, False)
    if not user:
        return {"error": "User not found"}
    
    if not verify_password(password, user.password):
        return {"error": "Incorrect password"}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    user.password  = None
    return {"access_token": access_token, "token_type": "bearer", "user": user}

def register(data: UserRegister):
    email = data.email
    password = data.password

    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,24}$'
    )
    if not password_pattern.match(password):
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be 8-24 characters long, contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol"
            )
    

    new_user = {
        "email": email,
        "password": get_password_hash(password),
    }

    created_user =  create_user(new_user)

    user = get_user_by_email(email, True)


    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)


    access_token = create_access_token(
        data={"sub": created_user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "user": user}




def logout(token: str = Depends(oauth2_scheme)):
    return {"message": "Logout successful"+token}




async def get_current_user(token: str = Depends(oauth2_scheme)) -> User: 
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature has expired")
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(email, False)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
    

