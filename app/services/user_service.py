import bcrypt
import jwt
from datetime import datetime, timedelta
from app.models.user import UserModel
from sqlalchemy.orm import Session
from app.core.config import settings

class UserService:
    @staticmethod
    def register_user(name: str, email: str, document_number: str, password: str, role: str = 'visitor', db: Session = None):
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

        # Gerar o token JWT
        token = UserService.generate_jwt_token(user.id, user.role)

        # Retorna o ID do usuário registrado e o token
        return {"message": "Usuário registrado com sucesso", "user_id": user.id, "token": token}

    @staticmethod
    def login_user(email: str, password: str, db: Session):
        # Buscar o usuário pelo email
        user = db.query(UserModel).filter(UserModel.email == email).first()
        
        # Verificar se o usuário existe
        if not user:
            return {"error": "Usuário não encontrado."}
        print("Testando: ", user.password_hash)
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
