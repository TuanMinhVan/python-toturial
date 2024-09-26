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

# Initialize password context with bcrypt algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify password
def verify_password(plain_password:str, hashed_password:str|None):
    if hashed_password is None:
        return False
    return pwd_context.verify(plain_password, hashed_password)

# Function to hash password
def get_password_hash(password:str):
    return pwd_context.hash(password)

# Function to create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to create refresh token
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to handle user login
def login(data: UserLogin):
    email = data.email
    password = data.password
    # Attempt to retrieve the user by email
    try:
        user = get_user_by_email(email)
    except HTTPException as e:
        # Return an error response if an HTTPException occurs
        return ResponseBase(status=e.status_code, message=e.detail)
    
    # Check if the user was not found
    if not user:
        return ResponseBase(status=404, message="User not found")
    
    # Verify the provided password against the stored hashed password
    if not verify_password(password, user.password):
        return ResponseBase(status=401, message="Incorrect password")
    
    # Set the expiration time for the access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Set the expiration time for the refresh token
    refresh_token_expires = timedelta(days=7)

    # Create the access token with the user's email and expiration time
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    # Create the refresh token with the user's email and expiration time
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

# Function to handle user registration
def register(data: UserRegister):
    email = data.email
    password = data.password

    # Define the password pattern to ensure it meets the required criteria
    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,24}$'
    )
    # Check if the password matches the pattern
    if not password_pattern.match(password):
        return ResponseBase(
            status=400,
            message="Password must be 8-24 characters long, contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol"
        )
    
    # Create a new user dictionary with the email and hashed password
    new_user = {
        "email": email,
        "password": get_password_hash(password),
    }

    try:
        # Attempt to create the user
        result = create_user(new_user)
        if not result:
            return ResponseBase(status=400, message="Create user failed")
        
        # Retrieve the newly created user by email
        user = get_user_by_email(email)
        print("Register result", user)

    except HTTPException as e:
        return ResponseBase(status=e.status_code, message=e.detail)

    # Set the expiration time for the access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Set the expiration time for the refresh token
    refresh_token_expires = timedelta(days=7)

    # Create the access token with the user's email and expiration time
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    # Create the refresh token with the user's email and expiration time
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

# Function to handle user logout
def logout(token: dict = Depends(oauth2_scheme)):
    return {"message": "Logout successful "+str(token)}

# Function to get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User: 
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token to get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str|None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature has expired")
    except JWTError:
        raise credentials_exception

    # Retrieve the user by email from the payload
    user = get_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# Function to refresh access token using refresh token
def refresh_access_token(refresh_token: str):
    try:
        # Decode the refresh token to get the payload
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str|None = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Set the expiration time for the new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)

    return ResponseBase(
        status=200, 
        message="Refresh token successful", 
        data={"access_token": new_access_token, "token_type": "bearer"}
    )

# Function to delete user by email
def delete_user_by_email(data: dict):
    email = data.get("email")
    if email is None:
        raise HTTPException(status_code=400, detail="Email is required")
    # Attempt to delete the user by email
    deleted_count = delete_user(email)

    # Check if the user was not found
    if deleted_count == 0:
        return ResponseBase(status=404, message="User not found")
    
    return ResponseBase(status=200, message="Delete user successful")