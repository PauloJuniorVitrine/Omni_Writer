#!/usr/bin/env python3
"""
Script de Validação - Token Rotation System
===========================================

Valida o sistema de rotação automática de tokens.
Verifica configurações, conectividade e funcionalidades.

Prompt: Script de validação para rotação de tokens
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:00:00Z
"""

import os
import sys
import logging
from datetime import datetime, timedelta
import json

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def setup_logging():
    """Configura logging para validação."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [validation] %(message)s',
        handlers=[
            logging.FileHandler('logs/exec_trace/token_rotation_validation.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def validate_imports():
    """Valida se todas as dependências estão disponíveis."""
    logger = logging.getLogger(__name__)
    
    required_modules = [
        'apscheduler',
        'sqlalchemy',
        'shared.token_rotation',
        'shared.token_repository'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            logger.info(f"✅ Módulo {module} disponível")
        except ImportError as e:
            logger.error(f"❌ Módulo {module} não disponível: {e}")
            missing_modules.append(module)
    
    return len(missing_modules) == 0

def validate_database_connection():
    """Valida conexão com banco de dados."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.token_repository import Session, init_db
        
        # Testa conexão
        session = Session()
        session.execute("SELECT 1")
        session.close()
        
        # Inicializa tabelas se necessário
        init_db()
        
        logger.info("✅ Conexão com banco de dados OK")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na conexão com banco: {e}")
        return False

def validate_token_rotation_service():
    """Valida o serviço de rotação de tokens."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.token_rotation import TokenRotationService, ROTATION_INTERVAL_DAYS, FORCE_EXPIRATION_DAYS
        
        # Testa criação do serviço
        service = TokenRotationService()
        
        # Testa obtenção de estatísticas
        stats = service.get_rotation_stats()
        
        logger.info(f"✅ Serviço de rotação criado com sucesso")
        logger.info(f"📊 Estatísticas: {json.dumps(stats, indent=2)}")
        logger.info(f"⚙️ Configurações: Rotação={ROTATION_INTERVAL_DAYS}d, Expiração={FORCE_EXPIRATION_DAYS}d")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no serviço de rotação: {e}")
        return False

def validate_scheduler():
    """Valida o agendador de tarefas."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.token_rotation import TokenRotationService
        
        service = TokenRotationService()
        
        # Testa configuração do scheduler
        assert service.scheduler is not None
        assert hasattr(service.scheduler, 'add_job')
        assert hasattr(service.scheduler, 'start')
        assert hasattr(service.scheduler, 'shutdown')
        
        logger.info("✅ Agendador configurado corretamente")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no agendador: {e}")
        return False

def validate_logging():
    """Valida sistema de logging."""
    logger = logging.getLogger(__name__)
    
    try:
        import logging
        
        # Verifica se o logger de rotação existe
        rotation_logger = logging.getLogger("token_rotation")
        
        assert rotation_logger.level == logging.INFO
        assert len(rotation_logger.handlers) > 0
        
        # Testa escrita de log
        test_message = f"Teste de logging - {datetime.utcnow().isoformat()}"
        rotation_logger.info(test_message)
        
        logger.info("✅ Sistema de logging funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de logging: {e}")
        return False

def validate_environment_variables():
    """Valida variáveis de ambiente necessárias."""
    logger = logging.getLogger(__name__)
    
    required_vars = [
        'POSTGRES_URL',
        'TOKEN_ROTATION_DAYS',
        'TOKEN_FORCE_EXPIRATION_DAYS'
    ]
    
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
            logger.warning(f"⚠️ Variável {var} não definida")
        else:
            logger.info(f"✅ Variável {var} definida: {os.getenv(var)}")
    
    return len(missing_vars) == 0

def validate_file_structure():
    """Valida estrutura de arquivos necessária."""
    logger = logging.getLogger(__name__)
    
    required_files = [
        'shared/token_rotation.py',
        'shared/token_repository.py',
        'logs/exec_trace/'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
            logger.error(f"❌ Arquivo/diretório não encontrado: {file_path}")
        else:
            logger.info(f"✅ Arquivo/diretório encontrado: {file_path}")
    
    return len(missing_files) == 0

def run_validation():
    """Executa todas as validações."""
    logger = setup_logging()
    
    logger.info("🚀 Iniciando validação do sistema de rotação de tokens")
    logger.info("=" * 60)
    
    validations = [
        ("Estrutura de arquivos", validate_file_structure),
        ("Variáveis de ambiente", validate_environment_variables),
        ("Importações", validate_imports),
        ("Conexão com banco", validate_database_connection),
        ("Serviço de rotação", validate_token_rotation_service),
        ("Agendador", validate_scheduler),
        ("Sistema de logging", validate_logging)
    ]
    
    results = []
    
    for name, validation_func in validations:
        logger.info(f"\n🔍 Validando: {name}")
        try:
            result = validation_func()
            results.append((name, result))
            if result:
                logger.info(f"✅ {name}: OK")
            else:
                logger.error(f"❌ {name}: FALHOU")
        except Exception as e:
            logger.error(f"❌ {name}: ERRO - {e}")
            results.append((name, False))
    
    # Resumo final
    logger.info("\n" + "=" * 60)
    logger.info("📋 RESUMO DA VALIDAÇÃO")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status} - {name}")
    
    logger.info(f"\n📊 Resultado: {passed}/{total} validações passaram")
    
    if passed == total:
        logger.info("🎉 TODAS AS VALIDAÇÕES PASSARAM!")
        return True
    else:
        logger.error("⚠️ ALGUMAS VALIDAÇÕES FALHARAM!")
        return False

if __name__ == "__main__":
    success = run_validation()
    sys.exit(0 if success else 1) 