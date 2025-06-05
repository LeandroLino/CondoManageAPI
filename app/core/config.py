from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )
    
    database_url: str
    api_version: str = "1.0.0"
    debug: bool = True
    testing: bool = False
    jwt_secret_key: str

    def get_database_url(self):
        """Retorna URL do banco baseada no ambiente"""
        if self.testing:
            return "sqlite:///./test.db"
        return self.database_url

# Instancia a configuração
settings = Settings()
