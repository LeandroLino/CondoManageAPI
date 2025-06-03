from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.user_service import UserService
from app.schemas.user import UserRegisterRequest , UserLoginRequest

from app.core.config import settings

user_router = APIRouter(prefix="/user")

@user_router.post("/register")
def register_user(user: UserRegisterRequest, db: Session = Depends(get_db)):
    result = UserService.register_user(user.name, user.email, user.document_number, user.password, user.role, db)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result["token"]}

@user_router.post("/login")
def register_user(user: UserLoginRequest, db: Session = Depends(get_db)):
    result = UserService.login_user(user.email, user.password, db)
    print(result)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result["token"]}
