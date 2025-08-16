#!/usr/bin/env python3
"""
Script de Validação - Security Headers System
=============================================

Valida o sistema de headers de segurança hardenizados.
Verifica CSP, Permissions-Policy, Referrer-Policy e proteções.

Prompt: Script de validação para headers de segurança
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:45:00Z
"""

import os
import sys
import logging
import requests
from datetime import datetime
import json

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def setup_logging():
    """Configura logging para validação."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [validation] %(message)s',
        handlers=[
            logging.FileHandler('logs/exec_trace/security_headers_validation.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def validate_imports():
    """Valida se todas as dependências estão disponíveis."""
    logger = logging.getLogger(__name__)
    
    required_modules = [
        'shared.security_headers',
        'werkzeug.datastructures'
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

def validate_security_headers_service():
    """Valida o serviço de headers de segurança."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager, get_security_headers
        
        # Testa criação do serviço
        manager = SecurityHeadersManager()
        
        # Testa obtenção de headers
        headers = get_security_headers()
        
        logger.info(f"✅ Serviço de headers de segurança criado com sucesso")
        logger.info(f"📊 Headers gerados: {len(headers)}")
        logger.info(f"🔒 Headers principais: {list(headers.keys())[:5]}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no serviço de headers de segurança: {e}")
        return False

def validate_csp_policy():
    """Valida política CSP."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager
        
        manager = SecurityHeadersManager()
        
        # Testa CSP com nonce
        nonce = "test_nonce_validation"
        csp_policy = manager.get_csp_policy(nonce)
        
        # Verifica diretivas importantes
        required_directives = [
            'default-src',
            'script-src',
            'object-src',
            'frame-ancestors'
        ]
        
        for directive in required_directives:
            if directive not in csp_policy:
                logger.error(f"❌ Diretiva CSP ausente: {directive}")
                return False
        
        # Verifica nonce
        if f"'nonce-{nonce}'" not in csp_policy:
            logger.error(f"❌ Nonce não encontrado na política CSP")
            return False
        
        logger.info("✅ Política CSP válida")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação CSP: {e}")
        return False

def validate_permissions_policy():
    """Valida Permissions-Policy."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager
        
        manager = SecurityHeadersManager()
        
        # Testa Permissions-Policy
        permissions_policy = manager.get_permissions_policy()
        
        # Verifica permissões importantes
        required_permissions = [
            'camera',
            'microphone',
            'geolocation',
            'payment'
        ]
        
        for permission in required_permissions:
            if f"{permission}=" not in permissions_policy:
                logger.error(f"❌ Permissão ausente: {permission}")
                return False
        
        logger.info("✅ Permissions-Policy válido")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação Permissions-Policy: {e}")
        return False

def validate_referrer_policy():
    """Valida Referrer-Policy."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager
        
        manager = SecurityHeadersManager()
        
        # Testa Referrer-Policy
        referrer_policy = manager.get_referrer_policy()
        
        expected_policy = "strict-origin-when-cross-origin"
        if referrer_policy != expected_policy:
            logger.error(f"❌ Referrer-Policy incorreto: {referrer_policy}")
            return False
        
        logger.info("✅ Referrer-Policy válido")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação Referrer-Policy: {e}")
        return False

def validate_all_headers():
    """Valida todos os headers de segurança."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import get_security_headers, validate_security_headers
        
        # Obtém todos os headers
        headers = get_security_headers()
        
        # Valida headers
        validation_result = validate_security_headers(headers)
        
        if not validation_result['valid']:
            logger.error(f"❌ Headers inválidos: {validation_result['missing_headers']}")
            return False
        
        # Verifica headers específicos
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for header_name, expected_value in required_headers.items():
            if header_name not in headers:
                logger.error(f"❌ Header ausente: {header_name}")
                return False
            
            if headers[header_name] != expected_value:
                logger.error(f"❌ Valor incorreto para {header_name}: {headers[header_name]}")
                return False
        
        logger.info("✅ Todos os headers de segurança válidos")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação de headers: {e}")
        return False

def validate_nonce_generation():
    """Valida geração de nonces."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager
        
        manager = SecurityHeadersManager()
        
        # Testa geração de nonces
        nonces = set()
        for _ in range(10):
            nonce = manager.generate_nonce()
            nonces.add(nonce)
        
        if len(nonces) != 10:
            logger.error(f"❌ Nonces não são únicos: {len(nonces)} únicos de 10")
            return False
        
        # Testa formato dos nonces
        for nonce in nonces:
            if len(nonce) < 16:
                logger.error(f"❌ Nonce muito curto: {len(nonce)}")
                return False
        
        logger.info("✅ Geração de nonces válida")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação de nonces: {e}")
        return False

def validate_csp_report_only():
    """Valida política CSP report-only."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import SecurityHeadersManager
        
        manager = SecurityHeadersManager()
        
        # Testa CSP report-only
        csp_report_only = manager.get_csp_report_only_policy()
        
        # Verifica se é mais permissiva que a política normal
        if "'unsafe-inline'" not in csp_report_only:
            logger.error("❌ CSP report-only não inclui 'unsafe-inline'")
            return False
        
        if "'unsafe-eval'" not in csp_report_only:
            logger.error("❌ CSP report-only não inclui 'unsafe-eval'")
            return False
        
        if "report-uri" not in csp_report_only:
            logger.error("❌ CSP report-only não inclui report-uri")
            return False
        
        logger.info("✅ Política CSP report-only válida")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação CSP report-only: {e}")
        return False

def validate_header_values():
    """Valida valores específicos dos headers."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.security_headers import get_security_headers
        
        headers = get_security_headers()
        
        # Verifica valores específicos
        expected_values = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-Download-Options': 'noopen',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'X-DNS-Prefetch-Control': 'off',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for header_name, expected_value in expected_values.items():
            if header_name not in headers:
                logger.error(f"❌ Header ausente: {header_name}")
                return False
            
            if headers[header_name] != expected_value:
                logger.error(f"❌ Valor incorreto para {header_name}: {headers[header_name]}")
                return False
        
        # Verifica headers que devem conter valores específicos
        if 'max-age=63072000' not in headers['Strict-Transport-Security']:
            logger.error("❌ HSTS não contém max-age correto")
            return False
        
        if 'no-store' not in headers['Cache-Control']:
            logger.error("❌ Cache-Control não contém no-store")
            return False
        
        if 'noindex' not in headers['X-Robots-Tag']:
            logger.error("❌ X-Robots-Tag não contém noindex")
            return False
        
        logger.info("✅ Valores dos headers válidos")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação de valores: {e}")
        return False

def validate_logging():
    """Valida sistema de logging."""
    logger = logging.getLogger(__name__)
    
    try:
        import logging
        
        # Verifica se o logger de security headers existe
        headers_logger = logging.getLogger("security_headers")
        
        assert headers_logger.level == logging.INFO
        assert len(headers_logger.handlers) > 0
        
        # Testa escrita de log
        test_message = f"Teste de logging - {datetime.utcnow().isoformat()}"
        headers_logger.info(test_message)
        
        logger.info("✅ Sistema de logging funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de logging: {e}")
        return False

def validate_file_structure():
    """Valida estrutura de arquivos necessária."""
    logger = logging.getLogger(__name__)
    
    required_files = [
        'shared/security_headers.py',
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
    
    logger.info("🚀 Iniciando validação do sistema de headers de segurança")
    logger.info("=" * 60)
    
    validations = [
        ("Estrutura de arquivos", validate_file_structure),
        ("Importações", validate_imports),
        ("Serviço de headers", validate_security_headers_service),
        ("Política CSP", validate_csp_policy),
        ("Permissions-Policy", validate_permissions_policy),
        ("Referrer-Policy", validate_referrer_policy),
        ("Todos os headers", validate_all_headers),
        ("Geração de nonces", validate_nonce_generation),
        ("CSP report-only", validate_csp_report_only),
        ("Valores dos headers", validate_header_values),
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