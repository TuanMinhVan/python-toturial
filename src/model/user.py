from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class User(BaseModel):
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

    class Config:
        json_schema_extra = {
            "example": {
                "firstName": "John",
                "lastName": "Doe",
                "maidenName": "Smith",
                "age": 30,
                "gender": "male",
                "email": "johndoe@example.com",
                "phone": "+1234567890",
                "username": "john Hoe",
                "password": "password123",
                "birthDate": "1990-01-01",
                "image": "http://example.com/image.jpg",
                "bloodGroup": "A+",
                "height": 180.5,
                "weight": 75.0,
                "eyeColor": "blue"
            }
        }