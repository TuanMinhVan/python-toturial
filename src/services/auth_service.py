import re
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt, ExpiredSignatureError
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from src.models.user import ResponseBase, UserLogin, UserRegister, User
from src.services.user_service import create_user, delete_user, get_user_by_email
from src.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password:str, hashed_password:str|None):

    if hashed_password is None:
        return False

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

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def login(data: UserLogin):
    email = data.email
    password = data.password
    
    try:
        user = get_user_by_email(email)
    except HTTPException as e:
        return ResponseBase(status=e.status_code, message=e.detail)
    if not user:
        return ResponseBase(status=404, message="User not found")
    if not verify_password(password, user.password):
        return ResponseBase(status=401, message="Incorrect password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=7)

    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user.email}, expires_delta=refresh_token_expires
    )
    return ResponseBase(
        status=200,
        message="Login successful",
        data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.ignore_password()
        }
    )

def register(data: UserRegister):
    email = data.email
    password = data.password

    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,24}$'
    )
    if not password_pattern.match(password):
        return ResponseBase(
            status=400,
            message="Password must be 8-24 characters long, contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol"
        )
    

    new_user = {
        "email": email,
        "password": get_password_hash(password),
    }


    

    try:
        result = create_user(new_user)
     
        if not result:
            return ResponseBase(status=400, message="Create user failed")
        

        # Get user by email if create user successful
        user = get_user_by_email(email)

        print("Register result", user)

    except HTTPException as e:
        return ResponseBase(status=e.status_code, message=e.detail)


    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    refresh_token_expires = timedelta(days=7)

    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(
        data={"sub": user.email}, expires_delta=refresh_token_expires
    )

    return ResponseBase(
        status=200,
        message="Register successful",
        data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.ignore_password()
        }
    )



def logout(token: dict = Depends(oauth2_scheme)):
    
    return {"message": "Logout successful "+str(token)}




async def get_current_user(token: str = Depends(oauth2_scheme)) -> User: 

    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str|None = payload.get("sub")



        if email is None:
            raise credentials_exception
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature has expired")
    

    except JWTError:
        raise credentials_exception
    

    user = get_user_by_email(email)


    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    

    return user;



def refresh_access_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        email: str|None = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired")
    

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    new_access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)


    return ResponseBase(
        status=200, 
        message="Refresh token successful", 
        data={"access_token": new_access_token, "token_type": "bearer"}
    )






def delete_user_by_email(data: dict):
    email = data.get("email")
    if email is None:
        raise HTTPException(status_code=400, detail="Email is required")
    delete_user(email)
    return ResponseBase(status=200, message="Delete user successful")
