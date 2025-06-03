#!/bin/bash

echo "🧪 Configurando ambiente de testes..."

# Definir variável de ambiente para testes
export TESTING=1

# Criar ambiente virtual se não existir
if [ ! -d "venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python3 -m venv venv
fi

# Ativar ambiente virtual
echo "🔧 Ativando ambiente virtual..."
source venv/bin/activate

# Instalar dependências
echo "📥 Instalando dependências..."
pip install -r requirements.txt

# Limpar cache e arquivos de teste antigos
echo "🧹 Limpando cache..."
find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
rm -f test.db 2>/dev/null || true

# Executar testes
echo "🚀 Executando testes..."
TESTING=1 python3 -m pytest tests/ -v --tb=short

echo ""
echo "✅ Testes concluídos!"

# Limpar arquivo de teste
rm -f test.db 2>/dev/null || true

# Desativar ambiente virtual
deactivate