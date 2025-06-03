import bcrypt
import jwt
from datetime import datetime, timedelta
from app.models.user import UserModel
from sqlalchemy.orm import Session
from app.core.config import settings

class UserService:
    @staticmethod
    def register_user(name: str, email: str, document_number: str, password: str, role: str = 'visitor', db: Session = None):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user = UserModel(
            name=name,
            email=email,
            document_number=document_number,
            password_hash=hashed_password,
            role=role
        )

        if not user.is_valid_document():
            return {"error": "Documento inválido."}

        existing_user = db.query(UserModel).filter((UserModel.email == email) | (UserModel.document_number == document_number)).first()
        if existing_user:
            return {"error": "Email ou documento já cadastrados."}

        db.add(user)
        db.commit()
        db.refresh(user)

        token = UserService.generate_jwt_token(user.id, user.role)

        return token

    @staticmethod
    def login_user(email: str, password: str, db: Session):
        # Buscar o usuário pelo email
        user = db.query(UserModel).filter(UserModel.email == email).first()
        
        # Verificar se o usuário existe
        if not user:
            return {"error": "Usuário não encontrado."}
        
        # Verificar se a senha fornecida é válida
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return {"error": "Senha incorreta."}
        
        # Gerar um token JWT
        token = UserService.generate_jwt_token(user.id, user.role)
        
        # Retornar o token de autenticação
        return {"message": "Login bem-sucedido", "token": token}
    
    @staticmethod
    def generate_jwt_token(user_id: int, role) -> str:
        role_value = role.value if hasattr(role, 'value') else role
        expiration_time = datetime.utcnow() + timedelta(hours=1)
        payload = {
            "user_id": user_id,
            "role": role_value,
            "exp": expiration_time
        }
        
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        return token
