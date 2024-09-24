from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class User(BaseModel):
    id: Optional[str] = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    email: EmailStr
    password: str|None = None
    firstName: str|None = None
    lastName: str|None = None
    maidenName: str|None = None
    age: Optional[int] = Field(None, gt=0)
    gender: str|None = None
    phone: str|None = None
    username: str|None = None
    birthDate: str|None = None
    image: str|None = None
    bloodGroup: str|None = None
    height: Optional[float] = 0
    weight: Optional[float] = 0
    eyeColor: str|None = None
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}



class UserLogin(BaseModel):
    email: EmailStr
    password: str




class UserRegister(BaseModel):
    email: EmailStr
    password: str