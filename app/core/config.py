from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    database_url: str
    api_version: str = "1.0.0"
    debug: bool = True
    testing: bool = False
    jwt_secret_key: str  # Defina a chave secreta para JWT

    class Config:
        env_file = ".env"  # O arquivo .env será lido para as variáveis de ambiente
        env_file_encoding = 'utf-8'

    def get_database_url(self):
        """Retorna URL do banco baseada no ambiente"""
        if self.testing:
            return "sqlite:///./test.db"
        return self.database_url

# Instancia a configuração
settings = Settings()
