import pytest
import jwt
from app.services.user_service import UserService
from unittest.mock import patch
from datetime import datetime, timedelta

# Teste unitário para a função de gerar o token JWT
def test_generate_jwt_token():
    """Testar a geração do token JWT"""
    user_id = 1
    role = "visitor"

    # Usando o patch para mockar settings.jwt_secret_key
    with patch('app.core.config.settings.jwt_secret_key', 'secret_test_key'):
        # Gerar o token
        token = UserService.generate_jwt_token(user_id, role)
        
        # Verificar se o token não está vazio
        assert token is not None
        assert isinstance(token, str)  # O token deve ser uma string

        # Validar o conteúdo do payload (deve conter user_id, role e expiração)
        decoded_token = jwt.decode(token, 'secret_test_key', algorithms=["HS256"])
        assert decoded_token["user_id"] == user_id
        assert decoded_token["role"] == role
        assert datetime.utcnow() < datetime.utcfromtimestamp(decoded_token["exp"])

