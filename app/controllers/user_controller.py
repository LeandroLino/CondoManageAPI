from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.user_service import UserService
from app.schemas.user import UserRegisterRequest , UserLoginRequest

from app.core.config import settings

user_router = APIRouter(prefix="/user")

@user_router.post("/register")
def register_user(user: UserRegisterRequest, db: Session = Depends(get_db), response: Response = None):
    result = UserService.register_user(user.name, user.email, user.document_number, user.password, db, user.role, response)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result}

@user_router.post("/login")
def login_user(user: UserLoginRequest, db: Session = Depends(get_db), response: Response = None):
    result = UserService.login_user(user.email, user.password, db, response)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result}