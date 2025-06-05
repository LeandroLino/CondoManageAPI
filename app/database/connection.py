import time
import logging
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

logger = logging.getLogger(__name__)

def create_database_engine():
    """Cria engine baseada no ambiente"""
    # Se for teste, usar SQLite simples
    if settings.testing or os.getenv("TESTING"):
        engine = create_engine(
            "sqlite:///./test.db",
            connect_args={"check_same_thread": False}
        )
        return engine
    
    # Para produção, usar PostgreSQL com retry
    max_retries = 15
    retry_interval = 3
    
    for attempt in range(max_retries):
        try:
            engine = create_engine(
                settings.database_url,
                pool_pre_ping=True,
                pool_recycle=300,
                connect_args={"connect_timeout": 10}
            )
            
            # Testar conexão real
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            
            logger.info(f"✅ Conexão com banco estabelecida! (tentativa {attempt + 1})")
            return engine
            
        except Exception as e:
            logger.warning(f"❌ Tentativa {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_interval)
            else:
                logger.error("💥 Falha total na conexão com banco!")
                raise

engine = create_database_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()