import bcrypt
import jwt
from datetime import datetime, timedelta
from app.models.syndic import SyndicModel
from sqlalchemy.orm import Session
from app.core.config import settings
from fastapi import Depends, Response, HTTPException
from jwt import ExpiredSignatureError, DecodeError
from datetime import datetime, timedelta, timezone

def verify_refresh_token(refresh_token: str = Depends()):
    try:
        # Decodifica o refresh token
        payload = jwt.decode(refresh_token, settings.jwt_secret_key, algorithms=["HS256"])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado.")
    except DecodeError:
        raise HTTPException(status_code=401, detail="Refresh token inválido.")

class SyndicService:
    
    @staticmethod
    def register_syndic(name: str, email: str, document_number: str, password: str, db: Session, response: Response):
        # Criação do hash da senha
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Verificação para não haver duplicidade de e-mail ou documento
        existing_user = db.query(SyndicModel).filter(
            (SyndicModel.email == email) | (SyndicModel.document_number == document_number)
        ).first()
        if existing_user:
            return {"error": "Email ou documento já cadastrados."}

        # Criação do usuário com a role fixa como "syndic"
        user = SyndicModel(
            name=name,
            email=email,
            document_number=document_number,
            password_hash=hashed_password,
            role='syndic'
        )
        
        # Validação do documento (supondo que o método is_valid_document() existe em SyndicModel)
        if not user.is_valid_document():
            return {"error": "Documento inválido."}

        # Adiciona o usuário no banco de dados e realiza o commit
        db.add(user)
        db.commit()
        db.refresh(user)

        # Geração dos tokens de acesso (access) e de atualização (refresh)
        access_token = SyndicService.generate_jwt_token(user.id, user.role)
        refresh_token = SyndicService.generate_refresh_token(user.id)

        # Armazena o refresh token em um cookie HttpOnly para segurança
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,      # Protege contra ataques XSS
            secure=True,        # Garante a transmissão por HTTPS
            samesite="Strict",  # Previne ataques CSRF
            max_age=30 * 24 * 60 * 60  # Token com validade de 30 dias
        )
        
        return access_token

    @staticmethod
    def login_syndic(email: str, password: str, db: Session, response: Response):
        # Busca o usuário pelo e-mail
        user = db.query(SyndicModel).filter(SyndicModel.email == email).first()
        if not user:
            return {"error": "Usuário não encontrado."}

        # Verifica a senha fornecida
        if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            return {"error": "Senha incorreta."}
        
        # Garante que o usuário possui a role "syndic"
        if user.role != "syndic":
            return {"error": "Acesso não autorizado para este tipo de usuário."}

        access_token = SyndicService.generate_jwt_token(user.id, user.role)
        refresh_token = SyndicService.generate_refresh_token(user.id)

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=30 * 24 * 60 * 60
        )
        
        return access_token

    @staticmethod
    def generate_jwt_token(user_id: int, role) -> str:
        # Caso role seja um atributo com valor, extrai-o; caso contrário, utiliza a role diretamente
        role_value = role.value if hasattr(role, "value") else role
        expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)  # Token com validade de 1 hora
        payload = {
            "user_id": user_id,
            "role": role_value,
            "exp": expiration_time,
        }
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        return token

    @staticmethod
    def generate_refresh_token(user_id: int) -> str:
        expiration_time = datetime.now(timezone.utc) + timedelta(days=30)  # Refresh token com validade de 30 dias
        payload = {
            "user_id": user_id,
            "exp": expiration_time,
        }
        refresh_token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        return refresh_token

    @staticmethod
    def refresh_access_token(response: Response, db: Session, refresh_token: str = Depends(verify_refresh_token)):
        # Busca o usuário com base no user_id presente no refresh token
        user = db.query(SyndicModel).filter(SyndicModel.id == refresh_token["user_id"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado.")
        
        # Verifica se o usuário possui a role "syndic"
        if user.role != "syndic":
            raise HTTPException(status_code=401, detail="Acesso não autorizado.")
        
        access_token = SyndicService.generate_jwt_token(user.id, user.role)
        return {"access_token": access_token}
