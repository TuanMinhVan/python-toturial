from fastapi import APIRouter, Depends
from src.models.user import User
from src.services.auth_service import get_current_user
from src.services.user_service import get_list_users, get_user

router = APIRouter(prefix="/users", tags=["users"])





@router.get("/")
def get_list_users_endpoint(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user)):
    return get_list_users(skip, limit, current_user)

@router.get("/me")
def get_current_user_endpoint(current_user: User = Depends(get_current_user)):
    return get_user(current_user.id, current_user)


@router.get("/{user_id}")
def get_user_endpoint(user_id: str, current_user: User = Depends(get_current_user)):
    return get_user(user_id, current_user)

