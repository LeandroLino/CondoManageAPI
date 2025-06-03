import pytest
from app.schemas.user import UserRegisterRequest, UserLoginRequest
from app.models.user import UserModel
from fastapi.testclient import TestClient

def test_register_user(client: TestClient, db_session):
    """Testar o endpoint de registro do usuário"""
    
    # Dados válidos para registro
    user_data = {
        "name": "Test User",
        "email": "testuser@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }

    response = client.post("/user/register", json=user_data)
    
    # Verifica se o status é 200 e se o token é retornado
    assert response.status_code == 200
    data = response.json()
    assert "token" in data  # O token deve estar na resposta

    # Verifica se o usuário foi realmente adicionado ao banco de dados
    user_in_db = db_session.query(UserModel).filter_by(email=user_data["email"]).first()
    assert user_in_db is not None

def test_register_user_duplicate_email(client: TestClient):
    """Testar se o registro falha quando o email já existe"""
    
    # Dados válidos para registro
    user_data = {
        "name": "Test User",
        "email": "testuser@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }

    # Primeiro registro
    client.post("/user/register", json=user_data)

    # Tentativa de registro com o mesmo email
    response = client.post("/user/register", json=user_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Email ou documento já cadastrados." in data["message"]

def test_login_user(client: TestClient, db_session):
    """Testar o login de um usuário com credenciais válidas"""
    
    # Criar um usuário de teste diretamente no banco
    user_data = {
        "name": "Test User",
        "email": "loginuser@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }
    client.post("/user/register", json=user_data)

    db_session.commit()

    # Dados de login
    login_data = {
        "email": user_data["email"],
        "password": user_data["password"]
    }

    response = client.post("/user/login", json=login_data)
    
    # Verifica se o login foi bem-sucedido e se o token foi gerado
    assert response.status_code == 200
    data = response.json()
    assert "token" in data  # O token JWT deve estar na resposta

def test_login_user_invalid_password(client: TestClient, db_session):
    """Testar login com senha incorreta"""
    user_data = {
        "name": "Test User",
        "email": "loginuser@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }
    client.post("/user/register", json=user_data)

    # Dados de login com senha incorreta
    login_data = {
        "email": "loginuser@example.com",
        "password": "wrongpassword"
    }

    response = client.post("/user/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Senha incorreta." in data["message"]

def test_login_user_not_found(client: TestClient):
    """Testar login com email não registrado"""
    
    # Dados de login com email não registrado
    login_data = {
        "email": "nonexistentuser@example.com",
        "password": "any_password"
    }

    response = client.post("/user/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Usuário não encontrado." in data["message"]
