#!/usr/bin/env python3
"""
Script de Validação - Upload Security System
============================================

Valida o sistema de proteção contra uploads maliciosos.
Verifica configurações, detecção de malware e sanitização.

Prompt: Script de validação para segurança de uploads
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:30:00Z
"""

import os
import sys
import logging
import tempfile
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
            logging.FileHandler('logs/exec_trace/upload_security_validation.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def validate_imports():
    """Valida se todas as dependências estão disponíveis."""
    logger = logging.getLogger(__name__)
    
    required_modules = [
        'magic',
        'bleach',
        'shared.upload_security',
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

def validate_upload_security_service():
    """Valida o serviço de segurança de uploads."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import UploadSecurityValidator, get_upload_stats
        
        # Testa criação do serviço
        validator = UploadSecurityValidator()
        
        # Testa obtenção de estatísticas
        stats = get_upload_stats()
        
        logger.info(f"✅ Serviço de segurança de uploads criado com sucesso")
        logger.info(f"📊 Estatísticas: {json.dumps(stats, indent=2)}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no serviço de segurança de uploads: {e}")
        return False

def validate_file_extension_validation():
    """Valida validação de extensões de arquivo."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import UploadSecurityValidator
        
        validator = UploadSecurityValidator()
        
        # Testa extensões válidas
        valid_extensions = ['test.txt', 'data.csv', 'prompts.txt']
        for ext in valid_extensions:
            is_valid, error = validator._validate_file_extension(ext)
            if not is_valid:
                logger.error(f"❌ Extensão válida rejeitada: {ext}")
                return False
        
        # Testa extensões inválidas
        invalid_extensions = ['test.exe', 'script.js', 'malware.bat']
        for ext in invalid_extensions:
            is_valid, error = validator._validate_file_extension(ext)
            if is_valid:
                logger.error(f"❌ Extensão inválida aceita: {ext}")
                return False
        
        logger.info("✅ Validação de extensões funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação de extensões: {e}")
        return False

def validate_file_size_validation():
    """Valida validação de tamanho de arquivo."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import UploadSecurityValidator, MAX_FILE_SIZE
        from werkzeug.datastructures import FileStorage
        from io import BytesIO
        
        validator = UploadSecurityValidator()
        
        # Testa arquivo pequeno
        small_content = b"Linha 1\nLinha 2\nLinha 3"
        small_file = FileStorage(
            stream=BytesIO(small_content),
            filename="small.txt",
            content_type="text/plain"
        )
        small_file.content_length = len(small_content)
        
        is_valid, error = validator._validate_file_size(small_file)
        if not is_valid:
            logger.error(f"❌ Arquivo pequeno rejeitado: {error}")
            return False
        
        # Testa arquivo grande
        large_content = b"x" * (MAX_FILE_SIZE + 1024)
        large_file = FileStorage(
            stream=BytesIO(large_content),
            filename="large.txt",
            content_type="text/plain"
        )
        large_file.content_length = len(large_content)
        
        is_valid, error = validator._validate_file_size(large_file)
        if is_valid:
            logger.error(f"❌ Arquivo grande aceito")
            return False
        
        logger.info("✅ Validação de tamanho funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na validação de tamanho: {e}")
        return False

def validate_malicious_content_detection():
    """Valida detecção de conteúdo malicioso."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import UploadSecurityValidator
        
        validator = UploadSecurityValidator()
        
        # Testa conteúdo seguro
        safe_content = "Texto normal sem conteúdo malicioso"
        result = validator._detect_malicious_content(safe_content)
        if result is not None:
            logger.error(f"❌ Conteúdo seguro detectado como malicioso: {result}")
            return False
        
        # Testa conteúdo malicioso
        malicious_patterns = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<iframe src='malicious.com'></iframe>",
            "<object data='malware.swf'></object>",
            "onclick=alert('xss')",
            "data:text/html,<script>alert('xss')</script>"
        ]
        
        for pattern in malicious_patterns:
            result = validator._detect_malicious_content(pattern)
            if result is None:
                logger.error(f"❌ Conteúdo malicioso não detectado: {pattern}")
                return False
        
        logger.info("✅ Detecção de conteúdo malicioso funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na detecção de conteúdo malicioso: {e}")
        return False

def validate_content_sanitization():
    """Valida sanitização de conteúdo."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import UploadSecurityValidator
        
        validator = UploadSecurityValidator()
        
        # Testa sanitização de HTML
        html_content = "Texto <b>negrito</b> e <script>malicioso</script>"
        sanitized = validator._sanitize_content(html_content)
        
        if "<b>" in sanitized or "<script>" in sanitized:
            logger.error(f"❌ Tags HTML não removidas: {sanitized}")
            return False
        
        if "negrito" not in sanitized or "malicioso" not in sanitized:
            logger.error(f"❌ Conteúdo válido removido: {sanitized}")
            return False
        
        # Testa sanitização de caracteres de controle
        control_content = "Texto\x00normal\x01com\x02controle"
        sanitized = validator._sanitize_content(control_content)
        
        if "\x00" in sanitized or "\x01" in sanitized or "\x02" in sanitized:
            logger.error(f"❌ Caracteres de controle não removidos")
            return False
        
        logger.info("✅ Sanitização de conteúdo funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na sanitização de conteúdo: {e}")
        return False

def validate_integration():
    """Valida integração completa do sistema."""
    logger = logging.getLogger(__name__)
    
    try:
        from shared.upload_security import validate_upload
        from werkzeug.datastructures import FileStorage
        from io import BytesIO
        
        # Testa upload válido
        valid_content = b"Linha 1\nLinha 2\nLinha 3"
        valid_file = FileStorage(
            stream=BytesIO(valid_content),
            filename="valid.txt",
            content_type="text/plain"
        )
        valid_file.content_length = len(valid_content)
        
        with tempfile.NamedTemporaryFile(mode='w+b', suffix='.txt') as temp_file:
            temp_file.write(valid_content)
            temp_file.seek(0)
            
            is_valid, error, metadata = validate_upload(valid_file, "192.168.1.100")
            
            if not is_valid:
                logger.error(f"❌ Upload válido rejeitado: {error}")
                return False
            
            if metadata['line_count'] != 3:
                logger.error(f"❌ Metadados incorretos: {metadata}")
                return False
        
        # Testa upload malicioso
        malicious_content = b"Texto <script>alert('xss')</script>"
        malicious_file = FileStorage(
            stream=BytesIO(malicious_content),
            filename="malicious.txt",
            content_type="text/plain"
        )
        malicious_file.content_length = len(malicious_content)
        
        is_valid, error, metadata = validate_upload(malicious_file, "192.168.1.100")
        
        if is_valid:
            logger.error(f"❌ Upload malicioso aceito")
            return False
        
        logger.info("✅ Integração completa funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro na integração: {e}")
        return False

def validate_logging():
    """Valida sistema de logging."""
    logger = logging.getLogger(__name__)
    
    try:
        import logging
        
        # Verifica se o logger de upload security existe
        upload_logger = logging.getLogger("upload_security")
        
        assert upload_logger.level == logging.INFO
        assert len(upload_logger.handlers) > 0
        
        # Testa escrita de log
        test_message = f"Teste de logging - {datetime.utcnow().isoformat()}"
        upload_logger.info(test_message)
        
        logger.info("✅ Sistema de logging funcionando")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no sistema de logging: {e}")
        return False

def validate_file_structure():
    """Valida estrutura de arquivos necessária."""
    logger = logging.getLogger(__name__)
    
    required_files = [
        'shared/upload_security.py',
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
    
    logger.info("🚀 Iniciando validação do sistema de segurança de uploads")
    logger.info("=" * 60)
    
    validations = [
        ("Estrutura de arquivos", validate_file_structure),
        ("Importações", validate_imports),
        ("Serviço de segurança", validate_upload_security_service),
        ("Validação de extensões", validate_file_extension_validation),
        ("Validação de tamanho", validate_file_size_validation),
        ("Detecção de conteúdo malicioso", validate_malicious_content_detection),
        ("Sanitização de conteúdo", validate_content_sanitization),
        ("Integração completa", validate_integration),
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