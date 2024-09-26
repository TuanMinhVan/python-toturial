from bson.objectid import ObjectId
from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class User(BaseModel):
    id: Optional[str] = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    email: EmailStr
    password: str | None = None
    firstName: str | None = None
    lastName: str | None = None
    age: Optional[int] = Field(None, gt=0)
    gender: str | None = None
    phone: str | None = None
    username: str | None = None
    birthDate: str | None = None
    image: str | None = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

    def ignore_password(self):
        user_info = self.model_dump()
        user_info.pop('password', None)
        return user_info
    

    def __init__(self, **data):
        if '_id' in data and isinstance(data['_id'], ObjectId):
            data['id'] = str(data['_id'])
            del data['_id']
        super().__init__(**data)
        


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRegister(BaseModel):
    email: EmailStr
    password: str


class ResponseBase(BaseModel):
    status: int
    message: str
    data: dict|None = None

