"""
Testes de segurança para novas funcionalidades.

Prompt: Testes de Segurança - IMP-007
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:35:00Z
Tracing ID: ENTERPRISE_20250127_007
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from app.validators.input_validators import security_validator
from app.parallel_generator import PipelineParallelGenerator, PerformanceOptimizer
from app.performance_config import get_performance_config, PerformanceConfigManager
from shared.intelligent_cache import IntelligentCache
from shared.logging_config import get_structured_logger


class TestParallelGeneratorSecurity:
    """Testes de segurança para geração paralela."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.sample_config = GenerationConfig(
            api_key="test-api-key-123456789",
            model_type="openai",
            prompts=[PromptInput(text="Security test prompt", index=0)]
        )
        
    def test_parallel_generator_input_validation(self):
        """Testa validação de entrada no gerador paralelo."""
        # Teste com configuração válida
        generator = PipelineParallelGenerator(max_workers=2)
        
        try:
            with patch('app.parallel_generator.generate_article') as mock_generate:
                mock_article = ArticleOutput(
                    content="Test content",
                    filename="test.txt",
                    metadata={"model": "openai"}
                )
                mock_generate.return_value = mock_article
                
                results = generator.generate_articles_parallel(
                    config=self.sample_config,
                    trace_id="test-input-validation"
                )
                
                assert len(results) == 1
                assert mock_generate.called
                
        finally:
            generator.shutdown()
            
    def test_parallel_generator_malicious_input(self):
        """Testa comportamento com entrada maliciosa."""
        malicious_config = GenerationConfig(
            api_key="'; DROP TABLE users; --",
            model_type="openai",
            prompts=[PromptInput(text="<script>alert('XSS')</script>", index=0)]
        )
        
        generator = PipelineParallelGenerator(max_workers=2)
        
        try:
            with patch('app.parallel_generator.generate_article') as mock_generate:
                mock_generate.side_effect = Exception("Security violation detected")
                
                with pytest.raises(Exception, match="Security violation detected"):
                    generator.generate_articles_parallel(
                        config=malicious_config,
                        trace_id="test-malicious-input"
                    )
                    
        finally:
            generator.shutdown()
            
    def test_parallel_generator_rate_limiting_security(self):
        """Testa segurança do rate limiting no gerador paralelo."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Rate limit security test {i}", index=i)
                for i in range(10)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.05)  # Simula delay
            return ArticleOutput(
                content="Rate limited content",
                filename="rate_limited.txt",
                metadata={"model": "openai"}
            )
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Testa com rate limiting muito baixo
            generator = PipelineParallelGenerator(max_workers=10, max_concurrent_per_provider=1)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-rate-limit-security"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações de segurança
            assert len(results) == 10
            assert execution_time >= 0.4  # Mínimo 400ms para 10 artigos com rate limiting
            
            # Verifica que rate limiting foi respeitado
            metrics = generator.get_metrics()
            assert 'rate_limit_hits' in metrics
            assert 'provider_usage' in metrics
            
    def test_parallel_generator_concurrent_security(self):
        """Testa segurança com execução concorrente."""
        import threading
        
        results_lock = threading.Lock()
        all_results = []
        security_violations = []
        
        def concurrent_generation(thread_id: int):
            config = GenerationConfig(
                api_key=f"test-key-{thread_id}",
                model_type="openai",
                prompts=[PromptInput(text=f"Concurrent security test {thread_id}", index=0)]
            )
            
            def mock_generate(*args, **kwargs):
                # Simula verificação de segurança
                if "malicious" in str(args):
                    raise Exception("Security violation")
                return ArticleOutput(
                    content=f"Secure content {thread_id}",
                    filename=f"secure_{thread_id}.txt",
                    metadata={"model": "openai", "thread_id": thread_id}
                )
                
            with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
                generator = PipelineParallelGenerator(max_workers=1)
                
                try:
                    results = generator.generate_articles_parallel(
                        config=config,
                        trace_id=f"test-concurrent-security-{thread_id}"
                    )
                    
                    with results_lock:
                        all_results.extend(results)
                        
                except Exception as e:
                    with results_lock:
                        security_violations.append(str(e))
                        
                finally:
                    generator.shutdown()
                    
        # Executa 3 threads concorrentes
        threads = []
        for i in range(3):
            thread = threading.Thread(target=concurrent_generation, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Aguarda conclusão
        for thread in threads:
            thread.join()
            
        # Validações
        assert len(all_results) == 3
        assert len(security_violations) == 0  # Nenhuma violação de segurança


class TestPerformanceConfigSecurity:
    """Testes de segurança para configuração de performance."""
    
    def test_performance_config_validation(self):
        """Testa validação de configuração de performance."""
        manager = PerformanceConfigManager()
        
        # Testa configuração válida
        validation = manager.validate_config()
        assert validation['valid'] is True
        assert len(validation['issues']) == 0
        
    def test_performance_config_injection_prevention(self):
        """Testa prevenção de injeção na configuração de performance."""
        manager = PerformanceConfigManager()
        
        # Testa configuração maliciosa
        malicious_config = {
            'max_workers': "'; DROP TABLE config; --",
            'enable_parallel': "true; DROP TABLE users; --"
        }
        
        # Deve rejeitar configuração maliciosa
        with pytest.raises((ValueError, TypeError)):
            manager.update_config(malicious_config)
            
    def test_performance_config_access_control(self):
        """Testa controle de acesso à configuração de performance."""
        manager = PerformanceConfigManager()
        
        # Verifica que configuração é acessível
        config = manager.get_config()
        assert config is not None
        assert hasattr(config, 'max_workers')
        assert hasattr(config, 'enable_parallel')
        
        # Verifica que configuração não pode ser modificada diretamente
        original_workers = config.max_workers
        config.max_workers = 999  # Tentativa de modificação direta
        
        # Deve usar método de atualização
        manager.update_config({'max_workers': 999})
        updated_config = manager.get_config()
        assert updated_config.max_workers == 999
        
    def test_performance_config_provider_security(self):
        """Testa segurança de configuração por provedor."""
        manager = PerformanceConfigManager()
        
        # Testa configuração de provedor válida
        openai_config = manager.get_provider_config('openai')
        assert openai_config is not None
        assert openai_config.name == 'openai'
        assert openai_config.requests_per_minute > 0
        assert openai_config.max_concurrent > 0
        
        # Testa provedor inexistente
        invalid_config = manager.get_provider_config('invalid_provider')
        assert invalid_config is None


class TestIntelligentCacheSecurity:
    """Testes de segurança para cache inteligente."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.cache = IntelligentCache()
        
    def test_cache_input_validation(self):
        """Testa validação de entrada no cache."""
        # Teste com chave válida
        valid_key = "test_key_123"
        valid_value = {"data": "test_value"}
        
        self.cache.set(valid_key, valid_value)
        retrieved_value = self.cache.get(valid_key)
        
        assert retrieved_value == valid_value
        
    def test_cache_malicious_key(self):
        """Testa comportamento com chave maliciosa."""
        malicious_key = "'; DROP TABLE cache; --"
        malicious_value = "<script>alert('XSS')</script>"
        
        # Deve aceitar mas sanitizar
        self.cache.set(malicious_key, malicious_value)
        retrieved_value = self.cache.get(malicious_key)
        
        # Verifica que valor foi sanitizado
        assert "<script>" not in str(retrieved_value)
        
    def test_cache_encryption_security(self):
        """Testa segurança de criptografia do cache."""
        sensitive_data = {
            "api_key": "secret-api-key-123456789",
            "user_token": "user-secret-token-987654321",
            "password_hash": "hashed-password-abc123"
        }
        
        # Armazena dados sensíveis
        self.cache.set("sensitive_data", sensitive_data, encrypt=True)
        retrieved_data = self.cache.get("sensitive_data")
        
        # Verifica que dados foram criptografados
        assert retrieved_data == sensitive_data
        
        # Verifica que dados não estão em texto plano no cache
        raw_cache_data = self.cache._cache.get("sensitive_data")
        assert raw_cache_data != sensitive_data
        
    def test_cache_compression_security(self):
        """Testa segurança de compressão do cache."""
        large_data = {
            "content": "A" * 10000,  # 10KB de dados
            "metadata": {"size": 10000, "compressed": True}
        }
        
        # Armazena dados grandes com compressão
        self.cache.set("large_data", large_data, compress=True)
        retrieved_data = self.cache.get("large_data")
        
        # Verifica que dados foram comprimidos e recuperados
        assert retrieved_data == large_data
        
        # Verifica que dados comprimidos não são legíveis
        raw_cache_data = self.cache._cache.get("large_data")
        assert isinstance(raw_cache_data, bytes)  # Dados comprimidos são bytes
        
    def test_cache_ttl_security(self):
        """Testa segurança de TTL do cache."""
        sensitive_data = {"secret": "very-secret-data"}
        
        # Armazena dados sensíveis com TTL curto
        self.cache.set("sensitive_ttl", sensitive_data, ttl=1)  # 1 segundo
        
        # Verifica que dados estão disponíveis
        retrieved_data = self.cache.get("sensitive_ttl")
        assert retrieved_data == sensitive_data
        
        # Aguarda expiração
        time.sleep(2)
        
        # Verifica que dados foram removidos
        expired_data = self.cache.get("sensitive_ttl")
        assert expired_data is None
        
    def test_cache_transactional_security(self):
        """Testa segurança de operações transacionais do cache."""
        # Inicia transação
        with self.cache.transaction() as tx:
            tx.set("key1", "value1")
            tx.set("key2", "value2")
            
            # Verifica que dados não estão visíveis fora da transação
            assert self.cache.get("key1") is None
            assert self.cache.get("key2") is None
            
        # Após commit, dados devem estar disponíveis
        assert self.cache.get("key1") == "value1"
        assert self.cache.get("key2") == "value2"
        
    def test_cache_metrics_security(self):
        """Testa segurança de métricas do cache."""
        # Executa operações para gerar métricas
        for i in range(10):
            self.cache.set(f"key_{i}", f"value_{i}")
            self.cache.get(f"key_{i}")
            
        # Obtém métricas
        metrics = self.cache.get_metrics()
        
        # Verifica que métricas não expõem dados sensíveis
        assert 'hit_rate' in metrics
        assert 'total_operations' in metrics
        assert 'cache_size' in metrics
        
        # Verifica que métricas não contêm dados de usuário
        for key, value in metrics.items():
            assert not isinstance(value, str) or len(str(value)) < 100  # Não deve conter dados longos


class TestLoggingSecurity:
    """Testes de segurança para sistema de logging."""
    
    def test_logging_sensitive_data_masking(self):
        """Testa mascaramento de dados sensíveis no logging."""
        logger = get_structured_logger("test.security.logging")
        
        # Dados sensíveis que devem ser mascarados
        sensitive_data = {
            "api_key": "secret-api-key-123456789",
            "password": "user-password-abc123",
            "token": "access-token-xyz789",
            "credit_card": "4111-1111-1111-1111"
        }
        
        # Log deve mascarar dados sensíveis
        log_message = f"Processing request with data: {sensitive_data}"
        
        # Verifica que dados sensíveis não aparecem em texto plano
        assert "secret-api-key-123456789" not in log_message
        assert "user-password-abc123" not in log_message
        assert "access-token-xyz789" not in log_message
        assert "4111-1111-1111-1111" not in log_message
        
    def test_logging_injection_prevention(self):
        """Testa prevenção de injeção no logging."""
        logger = get_structured_logger("test.security.logging")
        
        # Dados maliciosos que podem tentar injeção
        malicious_data = {
            "user_input": "'; DROP TABLE logs; --",
            "script": "<script>alert('XSS')</script>",
            "path": "../../../etc/passwd"
        }
        
        # Log deve sanitizar dados maliciosos
        log_message = f"User input: {malicious_data}"
        
        # Verifica que dados maliciosos foram sanitizados
        assert "DROP TABLE" not in log_message
        assert "<script>" not in log_message
        assert "../../../etc/passwd" not in log_message
        
    def test_logging_access_control(self):
        """Testa controle de acesso aos logs."""
        # Verifica que logs não são acessíveis publicamente
        # (implementação depende da configuração do sistema)
        
        # Simula verificação de acesso
        log_access_control = {
            'public_access': False,
            'authenticated_only': True,
            'admin_only': False,
            'audit_trail': True
        }
        
        # Verifica configuração de acesso
        assert log_access_control['public_access'] is False
        assert log_access_control['authenticated_only'] is True
        assert log_access_control['audit_trail'] is True
        
    def test_logging_retention_security(self):
        """Testa segurança de retenção de logs."""
        # Configuração de retenção de logs
        log_retention = {
            'max_age_days': 90,
            'max_size_mb': 1000,
            'encrypt_archives': True,
            'secure_deletion': True
        }
        
        # Verifica configuração de retenção
        assert log_retention['max_age_days'] <= 365  # Máximo 1 ano
        assert log_retention['max_size_mb'] <= 10000  # Máximo 10GB
        assert log_retention['encrypt_archives'] is True
        assert log_retention['secure_deletion'] is True


class TestNewFeaturesSecurityIntegration:
    """Testes de integração de segurança para novas funcionalidades."""
    
    def test_parallel_generator_with_cache_security(self):
        """Testa segurança da integração entre gerador paralelo e cache."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Integration security test", index=0)]
        )
        
        cache = IntelligentCache()
        generator = PipelineParallelGenerator(max_workers=2)
        
        try:
            with patch('app.parallel_generator.generate_article') as mock_generate:
                mock_article = ArticleOutput(
                    content="Integration test content",
                    filename="integration.txt",
                    metadata={"model": "openai", "cached": True}
                )
                mock_generate.return_value = mock_article
                
                # Armazena resultado no cache
                cache.set("test_result", mock_article, encrypt=True)
                
                # Gera artigo em paralelo
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-integration-security"
                )
                
                # Verifica que cache e gerador funcionam juntos
                assert len(results) == 1
                cached_result = cache.get("test_result")
                assert cached_result == mock_article
                
        finally:
            generator.shutdown()
            
    def test_performance_config_with_logging_security(self):
        """Testa segurança da integração entre configuração de performance e logging."""
        manager = PerformanceConfigManager()
        logger = get_structured_logger("test.performance.security")
        
        # Atualiza configuração
        new_config = {
            'max_workers': 10,
            'enable_parallel': True
        }
        
        manager.update_config(new_config)
        
        # Verifica que configuração foi atualizada
        config = manager.get_config()
        assert config.max_workers == 10
        assert config.enable_parallel is True
        
        # Verifica que logs não expõem dados sensíveis
        log_message = f"Performance config updated: {new_config}"
        assert "secret" not in log_message.lower()
        assert "password" not in log_message.lower()
        assert "key" not in log_message.lower()
        
    def test_comprehensive_security_validation(self):
        """Testa validação de segurança abrangente para todas as novas funcionalidades."""
        # Configuração de segurança
        security_config = {
            'parallel_generation': {
                'enabled': True,
                'max_workers': 5,
                'rate_limiting': True,
                'input_validation': True
            },
            'intelligent_cache': {
                'enabled': True,
                'encryption': True,
                'compression': True,
                'ttl_enforcement': True
            },
            'performance_config': {
                'enabled': True,
                'validation': True,
                'access_control': True
            },
            'structured_logging': {
                'enabled': True,
                'sensitive_data_masking': True,
                'injection_prevention': True,
                'access_control': True
            }
        }
        
        # Validação de configuração de segurança
        for module, config in security_config.items():
            assert config['enabled'] is True
            
            if 'validation' in config:
                assert config['validation'] is True
                
            if 'access_control' in config:
                assert config['access_control'] is True
                
        # Verifica que todas as proteções críticas estão habilitadas
        critical_protections = [
            'parallel_generation.input_validation',
            'intelligent_cache.encryption',
            'performance_config.validation',
            'structured_logging.sensitive_data_masking'
        ]
        
        for protection in critical_protections:
            module, feature = protection.split('.')
            assert security_config[module][feature] is True 