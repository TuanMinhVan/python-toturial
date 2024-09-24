from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordRequestForm
from .user import (
    get_list_users,
    create_user,
    get_user,
    login_for_access_token,
    login,
    register,
    read_users_me,
    get_current_user,
    update_users_me,
)

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello World", "status": "ok"}

@app.get("/users")
def get_list_users_endpoint(skip: int = 0, limit: int = 10, current_user: dict = Depends(get_current_user)):
    return get_list_users(skip, limit, current_user)

@app.post("/users")
def create_user_endpoint(data: dict):
    return create_user(data)

@app.get("/users/{user_id}")
def get_user_endpoint(user_id: str, current_user: dict = Depends(get_current_user)):
    return get_user(user_id, current_user)

@app.post("/token")
async def login_for_access_token_endpoint(form_data: OAuth2PasswordRequestForm = Depends()):
    return await login_for_access_token(form_data)

@app.post('/login')
def login_endpoint(data: dict):
    return login(data)

@app.post("/register")
def register_endpoint(data: dict):
    return register(data)

@app.get("/my-info")
def read_users_me_endpoint(current_user: dict = Depends(get_current_user)):
    return read_users_me(current_user)

@app.put("/update-my-info")
def update_users_me_endpoint(data: dict, current_user: dict = Depends(get_current_user)):
    return update_users_me(data, current_user)
