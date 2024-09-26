from fastapi import APIRouter, Depends
from src.models.user import UserLogin, UserRegister
from src.services.auth_service import  delete_user_by_email, login, logout, refresh_access_token, register, oauth2_scheme

router = APIRouter()


@router.post('/login')
def login_endpoint(data: UserLogin):
    return login(data)

@router.post("/register")
def register_endpoint(data: UserRegister):
    return register(data)



@router.post("/logout")
def logout_endpoint(token: dict = Depends(oauth2_scheme)):
    return logout(token)


@router.post("/refresh-token")
def refresh_token_endpoint(refresh_token: str):
    return refresh_access_token(refresh_token)

@router.delete("/delete-user")
def delete_user_endpoint(data: dict):
    return delete_user_by_email(data)
