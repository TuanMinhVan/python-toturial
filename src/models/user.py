from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class User(BaseModel):
    id: str = Field(..., alias="_id")
    firstName: str
    lastName: str
    maidenName: Optional[str] = None
    age: int = Field(..., gt=0)
    gender: str
    email: EmailStr
    phone: str
    username: str
    password: str
    birthDate: str
    image: Optional[str] = None
    bloodGroup: Optional[str] = None
    height: Optional[float] = None
    weight: Optional[float] = None
    eyeColor: Optional[str] = None
