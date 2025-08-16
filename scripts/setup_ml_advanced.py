#!/usr/bin/env python3
"""
Script de Setup do Sistema ML Avançado.
Instala dependências e configura o ambiente.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header():
    """Imprime cabeçalho do setup."""
    print("=" * 60)
    print("🧠 SETUP DO SISTEMA ML AVANÇADO - OMNI WRITER")
    print("=" * 60)
    print()

def check_python_version():
    """Verifica versão do Python."""
    print("🐍 Verificando versão do Python...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ é necessário")
        print(f"   Versão atual: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
    return True

def install_dependencies():
    """Instala dependências ML."""
    print("\n📦 Instalando dependências ML...")
    
    try:
        # Caminho para requirements_ml.txt
        requirements_path = Path(__file__).parent.parent / "requirements_ml.txt"
        
        if not requirements_path.exists():
            print("❌ Arquivo requirements_ml.txt não encontrado")
            return False
        
        # Instala dependências
        print("   Instalando sentence-transformers, scikit-learn, nltk...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_path)
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Dependências instaladas com sucesso")
            return True
        else:
            print(f"❌ Erro na instalação: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Erro: {e}")
        return False

def download_nltk_data():
    """Baixa dados necessários do NLTK."""
    print("\n📚 Baixando dados do NLTK...")
    
    try:
        import nltk
        
        # Dados necessários
        nltk_data = [
            'punkt',
            'stopwords', 
            'wordnet',
            'averaged_perceptron_tagger'
        ]
        
        for data in nltk_data:
            print(f"   Baixando {data}...")
            nltk.download(data, quiet=True)
        
        print("✅ Dados NLTK baixados com sucesso")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao baixar dados NLTK: {e}")
        return False

def test_ml_imports():
    """Testa importação das bibliotecas ML."""
    print("\n🧪 Testando importações ML...")
    
    try:
        # Testa imports principais
        import sentence_transformers
        print("✅ sentence-transformers - OK")
        
        import sklearn
        print("✅ scikit-learn - OK")
        
        import nltk
        print("✅ nltk - OK")
        
        import numpy as np
        print("✅ numpy - OK")
        
        import pandas as pd
        print("✅ pandas - OK")
        
        return True
        
    except ImportError as e:
        print(f"❌ Erro de importação: {e}")
        return False

def test_ml_system():
    """Testa o sistema ML."""
    print("\n🚀 Testando sistema ML...")
    
    try:
        # Adiciona o diretório raiz ao path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        # Testa importação do módulo ML
        from omni_writer.ml_advanced import ContentOptimizer
        
        # Inicializa otimizador
        optimizer = ContentOptimizer()
        print("✅ ContentOptimizer inicializado - OK")
        
        # Testa análise simples
        test_content = "This is a test content for ML system."
        analysis = optimizer.analyze_content(test_content)
        
        if analysis:
            print("✅ Análise de conteúdo - OK")
            print(f"   Score: {analysis.metrics.overall_score:.2f}")
        else:
            print("❌ Falha na análise de conteúdo")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste do sistema: {e}")
        return False

def create_directories():
    """Cria diretórios necessários."""
    print("\n📁 Criando diretórios...")
    
    try:
        # Diretórios necessários
        directories = [
            "logs",
            "data/ml",
            "models"
        ]
        
        for directory in directories:
            dir_path = Path(__file__).parent.parent / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"✅ {directory} - OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar diretórios: {e}")
        return False

def check_gpu():
    """Verifica disponibilidade de GPU."""
    print("\n🖥️ Verificando GPU...")
    
    try:
        import torch
        
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            print(f"✅ GPU disponível: {gpu_name}")
            return True
        else:
            print("ℹ️ GPU não disponível - usando CPU")
            return True
            
    except ImportError:
        print("ℹ️ PyTorch não instalado - usando CPU")
        return True

def show_next_steps():
    """Mostra próximos passos."""
    print("\n" + "=" * 60)
    print("🎉 SETUP CONCLUÍDO COM SUCESSO!")
    print("=" * 60)
    print()
    print("📋 Próximos passos:")
    print()
    print("1. 🧪 Execute os testes:")
    print("   python scripts/test_ml_advanced.py")
    print()
    print("2. 🚀 Use o sistema ML:")
    print("   from omni_writer.ml_advanced import quick_optimize, quick_generate")
    print()
    print("3. 📊 Monitore performance:")
    print("   # Ver estatísticas no código")
    print()
    print("4. ⚙️ Configure parâmetros:")
    print("   # Edite omni_writer/ml_advanced/config.json")
    print()
    print("📚 Documentação completa:")
    print("   omni_writer/ml_advanced/README.md")
    print()

def main():
    """Função principal do setup."""
    print_header()
    
    # Lista de verificações
    checks = [
        ("Versão do Python", check_python_version),
        ("Instalação de dependências", install_dependencies),
        ("Dados NLTK", download_nltk_data),
        ("Importações ML", test_ml_imports),
        ("Sistema ML", test_ml_system),
        ("Diretórios", create_directories),
        ("GPU", check_gpu)
    ]
    
    results = []
    
    for check_name, check_func in checks:
        try:
            success = check_func()
            results.append((check_name, success))
        except Exception as e:
            print(f"❌ Erro em {check_name}: {e}")
            results.append((check_name, False))
    
    # Relatório final
    print("\n" + "=" * 60)
    print("📋 RELATÓRIO DO SETUP")
    print("=" * 60)
    
    passed = 0
    for check_name, success in results:
        status = "✅ PASSOU" if success else "❌ FALHOU"
        print(f"{check_name:25} : {status}")
        if success:
            passed += 1
    
    print(f"\n📊 Resultado: {passed}/{len(results)} verificações passaram")
    
    if passed == len(results):
        show_next_steps()
        return True
    elif passed >= len(results) * 0.8:
        print("\n⚠️ Setup parcialmente concluído. Algumas funcionalidades podem não funcionar.")
        show_next_steps()
        return True
    else:
        print("\n❌ Setup falhou. Verifique os erros acima.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 