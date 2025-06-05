from pydantic import BaseModel
from typing import Optional

class UserRegisterRequest(BaseModel):
    name: str
    email: str
    document_number: str
    password: str
    role: Optional[str] = 'visitor'

    class Config:
        from_attributes = True
        

class UserLoginRequest(BaseModel):
    email: str
    password: str


