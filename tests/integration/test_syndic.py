from app.models.syndic import SyndicModel
from fastapi.testclient import TestClient

def test_register_syndic(client: TestClient, db_session):
    """Testar o endpoint de registro do usuário"""
    
    # Dados válidos para registro
    syndic_data = {
        "name": "Test syndic",
        "email": "testsyndic@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }

    response = client.post("/syndic/register", json=syndic_data)
    
    # Verifica se o status é 200 e se o token é retornado
    assert response.status_code == 200
    data = response.json()
    assert "token" in data  # O token deve estar na resposta

    # Verifica se o usuário foi realmente adicionado ao banco de dados
    syndic_in_db = db_session.query(SyndicModel).filter_by(email=syndic_data["email"]).first()
    assert syndic_in_db is not None

    # Verifica se o cookie refresh_token está presente na resposta
    assert "refresh_token" in response.cookies  # O cookie 'refresh_token' deve estar presente
    refresh_token = response.cookies["refresh_token"]
    assert refresh_token is not None  # O valor do cookie não deve ser None

def test_register_syndic_duplicate_email(client: TestClient):
    """Testar se o registro falha quando o email já existe"""
    
    # Dados válidos para registro
    syndic_data = {
        "name": "Test syndic",
        "email": "testsyndic@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }

    # Primeiro registro
    client.post("/syndic/register", json=syndic_data)

    # Tentativa de registro com o mesmo email
    response = client.post("/syndic/register", json=syndic_data)
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Email ou documento já cadastrados." in data["message"]

def test_login_syndic(client: TestClient, db_session):
    """Testar o login de um usuário com credenciais válidas"""
    
    # Criar um usuário de teste diretamente no banco
    syndic_data = {
        "name": "Test syndic",
        "email": "loginsyndic@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }
    client.post("/syndic/register", json=syndic_data)

    db_session.commit()

    # Dados de login
    login_data = {
        "email": syndic_data["email"],
        "password": syndic_data["password"]
    }

    response = client.post("/syndic/login", json=login_data)
    
    # Verifica se o login foi bem-sucedido e se o token foi gerado
    assert response.status_code == 200
    data = response.json()
    assert "token" in data  # O token JWT deve estar na resposta

    # Verifica se o cookie refresh_token está presente na resposta
    assert "refresh_token" in response.cookies  # O cookie 'refresh_token' deve estar presente
    refresh_token = response.cookies["refresh_token"]
    assert refresh_token is not None  # O valor do cookie não deve ser None

def test_login_syndic_invalid_password(client: TestClient, db_session):
    """Testar login com senha incorreta"""
    syndic_data = {
        "name": "Test syndic",
        "email": "loginsyndic@example.com",
        "document_number": "72253316000104",
        "password": "testpassword123",
        "role": "visitor"
    }
    client.post("/syndic/register", json=syndic_data)

    # Dados de login com senha incorreta
    login_data = {
        "email": "loginsyndic@example.com",
        "password": "wrongpassword"
    }

    response = client.post("/syndic/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Senha incorreta." in data["message"]

def test_login_syndic_not_found(client: TestClient):
    """Testar login com email não registrado"""
    
    # Dados de login com email não registrado
    login_data = {
        "email": "nonexistentsyndic@example.com",
        "password": "any_password"
    }

    response = client.post("/syndic/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["result"] == "Failed"
    assert "Usuário não encontrado." in data["message"]
