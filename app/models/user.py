from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import validates
from app.database.connection import Base
import re
import bcrypt
import enum

# Definindo o Enum para as roles
class RoleEnum(enum.Enum):
    resident = 'resident'
    visitor = 'visitor'
    doorman = 'doorman'

class UserModel(Base):
    __tablename__ = "users"
   
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)  
    email = Column(String, unique=True, index=True)  
    document_number = Column(String, unique=True, index=True)
    password_hash = Column(String)  
    created_at = Column(DateTime, default=func.now())
    role = Column(Enum(RoleEnum), default=RoleEnum.visitor, nullable=False)

    def is_valid_document(self):
        """Valida CPF ou CNPJ"""
        if len(self.document_number) == 11:
            return self._validate_cpf(self.document_number)
        elif len(self.document_number) == 14:
            return self._validate_cnpj(self.document_number)
        return False

    def _validate_cpf(self, cpf: str):
        """Valida o CPF"""
        cpf = re.sub(r'\D', '', cpf)
        if len(cpf) != 11:
            return False
        return True

    def _validate_cnpj(self, cnpj: str):
        """Valida o CNPJ"""
        cnpj = re.sub(r'\D', '', cnpj)
        if len(cnpj) != 14:
            return False
        return True

    def set_password(self, password: str):
        """Função para fazer o hash da senha antes de salvar no banco"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Função para verificar se a senha fornecida corresponde ao hash armazenado"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
