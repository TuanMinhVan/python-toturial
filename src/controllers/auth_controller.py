from fastapi import APIRouter
from src.services.auth_service import  login, logout, register

router = APIRouter()


@router.post('/login')
def login_endpoint(data: dict):
    return login(data)

@router.post("/register")
def register_endpoint(data: dict):
    return register(data)



@router.post("/logout")
def logout_endpoint(data: dict):
    return logout(data)

