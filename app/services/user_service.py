import bcrypt
import jwt
from datetime import datetime, timedelta
from app.models.user import UserModel
from sqlalchemy.orm import Session
from app.core.config import settings
from fastapi import Depends, Response, HTTPException
from fastapi.exceptions import HTTPException
from jwt import ExpiredSignatureError, DecodeError

def verify_refresh_token(refresh_token: str = Depends()):
    try:
        # Decodificando o refresh token
        payload = jwt.decode(refresh_token, settings.jwt_secret_key, algorithms=["HS256"])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado.")
    except DecodeError:
        raise HTTPException(status_code=401, detail="Refresh token inválido.")
class UserService:
    @staticmethod
    def register_user(name: str, email: str, document_number: str, password: str, db: Session = None, role: str = 'visitor', response: Response = None):
        # Hash da senha antes de armazená-la
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Verificação de duplicidade de email ou número de documento
        existing_user = db.query(UserModel).filter((UserModel.email == email) | (UserModel.document_number == document_number)).first()
        if existing_user:
            return {"error": "Email ou documento já cadastrados."}

        # Criação do objeto de usuário
        user = UserModel(
            name=name,
            email=email,
            document_number=document_number,
            password_hash=hashed_password,  # Certifique-se de salvar o hash da senha
            role=role  # Agora o role é passado corretamente
        )

        # Validação do número do documento
        if not user.is_valid_document():
            return {"error": "Documento inválido."}

        # Adicionando e comitando no banco de dados
        db.add(user)
        db.commit()
        db.refresh(user)

        access_token = UserService.generate_jwt_token(user.id, user.role)
        
        refresh_token = UserService.generate_refresh_token(user.id)

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,  # Protege contra XSS
            secure=True,  # Assegura que só seja transmitido por HTTPS
            samesite="Strict",  # Protege contra CSRF
            max_age=30 * 24 * 60 * 60  # Expira em 30 dias
        )
        # Gerar o token JWT

        # Retorna o ID do usuário registrado e o token
        return {"token": access_token}

    @staticmethod
    def login_user(email: str, password: str, db: Session, response: Response):
        # Buscar o usuário pelo email
        user = db.query(UserModel).filter(UserModel.email == email).first()
        
        # Verificar se o usuário existe
        if not user:
            return {"error": "Usuário não encontrado."}
        
        # Verificar se a senha fornecida é válida
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return {"error": "Senha incorreta."}
        
        # Gerar o token JWT (access token)
        access_token = UserService.generate_jwt_token(user.id, user.role)
        
        # Gerar o refresh token de longa duração
        refresh_token = UserService.generate_refresh_token(user.id)

        # Armazenando o refresh token em um cookie HttpOnly
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,  # Protege contra XSS
            secure=True,  # Assegura que só seja transmitido por HTTPS
            samesite="Strict",  # Protege contra CSRF
            max_age=30 * 24 * 60 * 60  # Expira em 30 dias
        )
        
        # Retorna o access token diretamente na resposta
        return {"access_token": access_token}
    
    @staticmethod
    def generate_jwt_token(user_id: int, role) -> str:
        role_value = role.value if hasattr(role, 'value') else role
        expiration_time = datetime.utcnow() + timedelta(hours=1)  # Expiração do access token em 1 hora
        payload = {
            "user_id": user_id,
            "role": role_value,
            "exp": expiration_time
        }
        
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        return token

    @staticmethod
    def generate_refresh_token(user_id: int) -> str:
        expiration_time = datetime.utcnow() + timedelta(days=30)  # Expira em 30 dias
        payload = {
            "user_id": user_id,
            "exp": expiration_time
        }
        
        # Gerando o refresh token
        refresh_token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        return refresh_token

    @staticmethod
    def refresh_access_token(response: Response, db: Session, refresh_token: str = Depends(verify_refresh_token)):
        # O refresh_token é verificado e extraído da função verify_refresh_token
        
        # Buscar o usuário do banco usando o user_id do refresh token
        user = db.query(UserModel).filter(UserModel.id == refresh_token["user_id"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado.")

        # Gerar um novo access token
        access_token = UserService.generate_jwt_token(user.id, user.role)
        
        return {"access_token": access_token}

