from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.syndic_service import SyndicService
from app.schemas.user import UserRegisterRequest , UserLoginRequest

from app.core.config import settings

syndic_router = APIRouter(prefix="/syndic")

@syndic_router.post("/register")
def register_syndic(user: UserRegisterRequest, db: Session = Depends(get_db), response: Response = None):
    result = SyndicService.register_syndic(user.name, user.email, user.document_number, user.password, db, response)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result}

@syndic_router.post("/login")
def login_syndic(user: UserLoginRequest, db: Session = Depends(get_db), response: Response = None):
    result = SyndicService.login_syndic(user.email, user.password, db, response)
    if "error" in result:
        return {"result": "Failed", "message": result["error"], 'token': None}
    return {'token': result}