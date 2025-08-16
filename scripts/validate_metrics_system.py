#!/usr/bin/env python3
"""
Script de Validação - Metrics System
====================================

Valida o sistema de métricas Prometheus/Grafana.
Verifica métricas, alertas e dashboard.

Prompt: Script de validação para sistema de métricas
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:50:00Z
"""

import os
import sys
import logging
import requests
import json
from datetime import datetime
import time

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def setup_logging():
    """Configura logging para validação."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [validation] %(message)s',
        handlers=[
            logging.FileHandler('logs/exec_trace/metrics_validation.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def validate_imports():
    """Valida se todas as dependências estão disponíveis."""
    logger = logging.getLogger(__name__)
    
    required_modules = [
        'shared.metrics_system',
        'prometheus_client'
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

def validate_metrics_system():
    """Valida o sistema de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.metrics_system import MetricsSystem, metrics_system
        
        # Testa criação do sistema
        system = MetricsSystem()
        
        # Testa métricas básicas
        system.record_article_generation('gpt-4', 'completed', 'user123', 2.5)
        system.record_request('POST', '/generate', 200, 1.2)
        system.record_token_usage('gpt-4', 'user123', 'success')
        
        logger.info(f"✅ Sistema de métricas criado com sucesso")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de métricas: {e}")
        return False

def validate_metrics_endpoint():
    """Valida endpoint de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        # Testa endpoint de métricas
        response = requests.get('http://localhost:5000/metrics', timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            logger.info(f"✅ Endpoint de métricas funcionando")
            logger.info(f"📊 Dados recebidos: {json.dumps(data, indent=2)}")
            return True
        else:
            logger.error(f"❌ Endpoint de métricas retornou status {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Erro ao acessar endpoint de métricas: {e}")
        return False

def validate_dashboard():
    """Valida dashboard de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        # Testa dashboard
        response = requests.get('http://localhost:5000/dashboard', timeout=5)
        
        if response.status_code == 200:
            logger.info(f"✅ Dashboard funcionando")
            return True
        else:
            logger.error(f"❌ Dashboard retornou status {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Erro ao acessar dashboard: {e}")
        return False

def validate_prometheus_metrics():
    """Valida métricas Prometheus."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.metrics_system import metrics_system
        
        # Testa geração de métricas Prometheus
        metrics_data = metrics_system.get_metrics()
        
        if metrics_data and len(metrics_data) > 0:
            logger.info(f"✅ Métricas Prometheus geradas com sucesso")
            logger.info(f"📊 Tamanho das métricas: {len(metrics_data)} bytes")
            return True
        else:
            logger.error(f"❌ Métricas Prometheus vazias")
            return False
            
    except Exception as e:
        logger.error(f"❌ Erro ao gerar métricas Prometheus: {e}")
        return False

def validate_metrics_summary():
    """Valida resumo de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.metrics_system import get_metrics_summary
        
        # Testa resumo de métricas
        summary = get_metrics_summary()
        
        if summary and isinstance(summary, dict):
            logger.info(f"✅ Resumo de métricas gerado com sucesso")
            logger.info(f"📊 Estrutura: {list(summary.keys())}")
            return True
        else:
            logger.error(f"❌ Resumo de métricas inválido")
            return False
            
    except Exception as e:
        logger.error(f"❌ Erro ao gerar resumo de métricas: {e}")
        return False

def validate_alert_system():
    """Valida sistema de alertas."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.metrics_system import metrics_system
        
        # Simula condições de alerta
        metrics_system.error_rate.set(0.05)  # 5% de erro
        metrics_system.avg_latency.set(6.0)   # 6s de latência
        
        # Força verificação de alertas
        metrics_system._check_alerts()
        
        logger.info(f"✅ Sistema de alertas funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de alertas: {e}")
        return False

def validate_metrics_recording():
    """Valida gravação de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.metrics_system import (
            record_article_generation,
            record_request,
            record_token_usage,
            record_error
        )
        
        # Testa gravação de diferentes tipos de métricas
        record_article_generation('gpt-4', 'completed', 'user123', 2.5)
        record_request('POST', '/generate', 200, 1.2)
        record_token_usage('gpt-4', 'user123', 'success')
        record_error('api_error', '/generate', 'user123')
        
        logger.info(f"✅ Gravação de métricas funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na gravação de métricas: {e}")
        return False

def validate_metrics_port():
    """Valida porta de métricas."""
    logger = logging.getLogger(__name__)
    
    try:
        import socket
        
        # Testa se a porta de métricas está disponível
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 9090))
        sock.close()
        
        if result == 0:
            logger.info(f"✅ Porta de métricas (9090) disponível")
            return True
        else:
            logger.warning(f"⚠️ Porta de métricas (9090) não disponível")
            return False
            
    except Exception as e:
        logger.error(f"❌ Erro ao verificar porta de métricas: {e}")
        return False

def validate_file_structure():
    """Valida estrutura de arquivos necessária."""
    logger = logging.getLogger(__name__)
    
    required_files = [
        'shared/metrics_system.py',
        'templates/metrics_dashboard.html',
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

def validate_logging():
    """Valida sistema de logging."""
    logger = logging.getLogger(__name__)
    
    try:
        import logging
        
        # Verifica se o logger de metrics system existe
        metrics_logger = logging.getLogger("metrics_system")
        
        assert metrics_logger.level == logging.INFO
        assert len(metrics_logger.handlers) > 0
        
        # Testa escrita de log
        test_message = f"Teste de logging - {datetime.utcnow().isoformat()}"
        metrics_logger.info(test_message)
        
        logger.info("✅ Sistema de logging funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de logging: {e}")
        return False

def run_validation():
    """Executa todas as validações."""
    logger = setup_logging()
    
    logger.info("🚀 Iniciando validação do sistema de métricas")
    logger.info("=" * 60)
    
    validations = [
        ("Estrutura de arquivos", validate_file_structure),
        ("Importações", validate_imports),
        ("Sistema de métricas", validate_metrics_system),
        ("Endpoint de métricas", validate_metrics_endpoint),
        ("Dashboard", validate_dashboard),
        ("Métricas Prometheus", validate_prometheus_metrics),
        ("Resumo de métricas", validate_metrics_summary),
        ("Sistema de alertas", validate_alert_system),
        ("Gravação de métricas", validate_metrics_recording),
        ("Porta de métricas", validate_metrics_port),
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