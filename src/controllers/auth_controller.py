from fastapi import APIRouter, Depends
from src.models.user import UserLogin, UserRegister
from src.services.auth_service import  get_current_user, login, logout, register,oauth2_scheme

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

