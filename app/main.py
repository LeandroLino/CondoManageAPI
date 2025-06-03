from fastapi import FastAPI
from app.controllers.api_controller import router
from app.controllers.user_controller import user_router
from app.database.connection import engine, Base
from app.core.config import settings

# Criar tabelas no banco
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FastAPI + PostgreSQL Project",
    description="Projeto simples com contador de chamadas",
    version=settings.api_version,
)

# Incluir rotas
app.include_router(router)
app.include_router(user_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
