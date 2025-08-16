"""
Testes de rate limiting para controle de concorrência.

Prompt: Otimização de Performance - IMP-006
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:20:00Z
Tracing ID: ENTERPRISE_20250127_006
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from app.parallel_generator import PipelineParallelGenerator
from app.performance_config import get_performance_config, get_provider_config


class TestRateLimiting:
    """Testes para rate limiting."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.mock_article = ArticleOutput(
            content="Rate limiting test content",
            filename="rate_limit_test.txt",
            metadata={"model": "openai", "rate_limit_test": True}
        )
        
    def test_rate_limiter_initialization(self):
        """Testa inicialização do rate limiter."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        assert generator.rate_limiter is not None
        assert hasattr(generator.rate_limiter, 'can_proceed')
        assert hasattr(generator.rate_limiter, 'record_request')
        assert hasattr(generator.rate_limiter, 'release_request')
        
        generator.shutdown()
        
    def test_rate_limiter_default_configs(self):
        """Testa configurações padrão do rate limiter."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        # Verifica configurações para diferentes provedores
        providers = ['openai', 'deepseek', 'gemini', 'claude']
        
        for provider in providers:
            config = generator.rate_limiter.configs.get(provider)
            assert config is not None
            assert config.requests_per_minute > 0
            assert config.max_concurrent > 0
            assert config.timeout > 0
            
        generator.shutdown()
        
    def test_rate_limiter_can_proceed(self):
        """Testa verificação se pode prosseguir."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        # Testa provedor sem configuração
        assert generator.rate_limiter.can_proceed('unknown_provider') is True
        
        # Testa provedor com configuração
        assert generator.rate_limiter.can_proceed('openai') is True
        
        generator.shutdown()
        
    def test_rate_limiter_request_tracking(self):
        """Testa rastreamento de requisições."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        provider = 'openai'
        
        # Registra algumas requisições
        generator.rate_limiter.record_request(provider)
        generator.rate_limiter.record_request(provider)
        
        # Verifica se está rastreando
        assert generator.rate_limiter.active_requests[provider] == 2
        
        # Libera requisições
        generator.rate_limiter.release_request(provider)
        generator.rate_limiter.release_request(provider)
        
        assert generator.rate_limiter.active_requests[provider] == 0
        
        generator.shutdown()
        
    def test_rate_limiter_wait_time_calculation(self):
        """Testa cálculo de tempo de espera."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        provider = 'openai'
        config = generator.rate_limiter.configs[provider]
        
        # Simula muitas requisições no último minuto
        for _ in range(config.requests_per_minute + 1):
            generator.rate_limiter.record_request(provider)
            
        wait_time = generator.rate_limiter.get_wait_time(provider)
        
        # Deve retornar tempo de espera positivo
        assert wait_time > 0
        assert wait_time <= 60  # Máximo 1 minuto
        
        generator.shutdown()
        
    def test_rate_limiting_in_parallel_generation(self):
        """Testa rate limiting durante geração paralela."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Rate limit test prompt {i}", index=i)
                for i in range(5)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)  # Simula delay de rede
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Configura rate limiting baixo
            generator = PipelineParallelGenerator(max_workers=5, max_concurrent_per_provider=2)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-rate-limiting"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações
            assert len(results) == 5
            assert execution_time > 0
            
            # Com rate limiting baixo, deve demorar mais
            assert execution_time >= 0.3  # Mínimo 300ms para 5 artigos com 2 concorrentes
            
            print(f"Rate limited execution: {execution_time:.2f}s")
            
    def test_rate_limiting_with_different_providers(self):
        """Testa rate limiting com diferentes provedores."""
        providers = ['openai', 'deepseek', 'gemini']
        
        for provider in providers:
            config = GenerationConfig(
                api_key="test-key",
                model_type=provider,
                prompts=[
                    PromptInput(text=f"{provider} rate limit test", index=0)
                ]
            )
            
            def mock_generate(*args, **kwargs):
                time.sleep(0.05)
                return self.mock_article
                
            with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
                generator = PipelineParallelGenerator(max_workers=3)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-rate-{provider}"
                )
                execution_time = time.time() - start_time
                
                generator.shutdown()
                
                # Validações
                assert len(results) == 1
                assert execution_time > 0
                
                print(f"{provider}: {execution_time:.2f}s")
                
    def test_rate_limiting_under_load(self):
        """Testa rate limiting sob carga."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Load test prompt {i}", index=i)
                for i in range(10)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.02)  # Simula delay rápido
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Testa com diferentes configurações de rate limiting
            rate_limit_configs = [1, 3, 5]
            performance_results = {}
            
            for max_concurrent in rate_limit_configs:
                generator = PipelineParallelGenerator(
                    max_workers=10,
                    max_concurrent_per_provider=max_concurrent
                )
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-load-{max_concurrent}"
                )
                execution_time = time.time() - start_time
                
                performance_results[max_concurrent] = {
                    'time': execution_time,
                    'articles': len(results),
                    'throughput': len(results) / execution_time
                }
                
                generator.shutdown()
                
            # Validações
            assert len(performance_results) == 3
            
            # Log de resultados
            print("\nRate Limiting Under Load:")
            for max_concurrent, metrics in performance_results.items():
                print(f"Max concurrent: {max_concurrent} | "
                      f"Time: {metrics['time']:.2f}s | "
                      f"Throughput: {metrics['throughput']:.2f} articles/s")
                
            # Rate limiting mais baixo deve resultar em tempo maior
            times = [metrics['time'] for metrics in performance_results.values()]
            assert times[0] >= times[1] * 0.8  # 1 concurrent pode ser similar a 3
            assert times[1] >= times[2] * 0.8  # 3 concurrent pode ser similar a 5
            
    def test_rate_limiting_recovery(self):
        """Testa recuperação após rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Recovery test prompt", index=0)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            generator = PipelineParallelGenerator(max_workers=1, max_concurrent_per_provider=1)
            
            # Primeira execução
            start_time = time.time()
            results1 = generator.generate_articles_parallel(
                config=config,
                trace_id="test-recovery-1"
            )
            time1 = time.time() - start_time
            
            # Segunda execução (deve recuperar)
            start_time = time.time()
            results2 = generator.generate_articles_parallel(
                config=config,
                trace_id="test-recovery-2"
            )
            time2 = time.time() - start_time
            
            generator.shutdown()
            
            # Validações
            assert len(results1) == 1
            assert len(results2) == 1
            assert time1 > 0
            assert time2 > 0
            
            # Segunda execução deve ser similar à primeira
            time_diff = abs(time1 - time2)
            assert time_diff < max(time1, time2) * 0.5  # Diferença menor que 50%
            
            print(f"First execution: {time1:.2f}s")
            print(f"Second execution: {time2:.2f}s")
            print(f"Time difference: {time_diff:.2f}s")
            
    def test_rate_limiting_metrics(self):
        """Testa métricas de rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Metrics test prompt {i}", index=i)
                for i in range(3)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.05)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            generator = PipelineParallelGenerator(max_workers=2, max_concurrent_per_provider=1)
            
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-metrics"
            )
            
            metrics = generator.get_metrics()
            
            generator.shutdown()
            
            # Validações
            assert len(results) == 3
            assert 'rate_limit_hits' in metrics
            assert 'provider_usage' in metrics
            assert 'openai' in metrics['provider_usage']
            assert metrics['provider_usage']['openai'] == 3
            
            print(f"Rate limit hits: {metrics['rate_limit_hits']}")
            print(f"Provider usage: {metrics['provider_usage']}")
            
    def test_rate_limiting_concurrent_requests(self):
        """Testa rate limiting com requisições concorrentes."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Concurrent rate limit test", index=0)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            import threading
            
            results_lock = threading.Lock()
            all_results = []
            execution_times = []
            
            def concurrent_generation(thread_id: int):
                generator = PipelineParallelGenerator(max_workers=1, max_concurrent_per_provider=1)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-concurrent-rate-{thread_id}"
                )
                execution_time = time.time() - start_time
                
                with results_lock:
                    all_results.extend(results)
                    execution_times.append(execution_time)
                    
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
            assert len(execution_times) == 3
            
            avg_time = sum(execution_times) / len(execution_times)
            
            print(f"Concurrent rate limiting times: {[f'{t:.2f}s' for t in execution_times]}")
            print(f"Average time: {avg_time:.2f}s")
            
            # Com rate limiting, tempos devem ser similares
            max_time = max(execution_times)
            min_time = min(execution_times)
            time_variance = (max_time - min_time) / avg_time
            
            assert time_variance < 0.5  # Variação menor que 50%
            
    def test_rate_limiting_configuration_validation(self):
        """Testa validação de configuração de rate limiting."""
        # Testa configurações válidas
        valid_configs = [
            {'max_workers': 5, 'max_concurrent_per_provider': 3},
            {'max_workers': 10, 'max_concurrent_per_provider': 5},
            {'max_workers': 1, 'max_concurrent_per_provider': 1}
        ]
        
        for config in valid_configs:
            generator = PipelineParallelGenerator(**config)
            assert generator.max_workers == config['max_workers']
            assert generator.max_concurrent_per_provider == config['max_concurrent_per_provider']
            generator.shutdown()
            
        # Testa configurações inválidas
        invalid_configs = [
            {'max_workers': 0, 'max_concurrent_per_provider': 1},
            {'max_workers': 5, 'max_concurrent_per_provider': 0},
            {'max_workers': -1, 'max_concurrent_per_provider': 1}
        ]
        
        for config in invalid_configs:
            with pytest.raises((ValueError, AssertionError)):
                PipelineParallelGenerator(**config)
                
    def test_rate_limiting_provider_specific_configs(self):
        """Testa configurações específicas por provedor."""
        generator = PipelineParallelGenerator(max_workers=2)
        
        # Verifica configurações específicas
        openai_config = generator.rate_limiter.configs['openai']
        deepseek_config = generator.rate_limiter.configs['deepseek']
        
        # OpenAI deve ter configurações mais permissivas
        assert openai_config.requests_per_minute >= deepseek_config.requests_per_minute
        assert openai_config.max_concurrent >= deepseek_config.max_concurrent
        
        print(f"OpenAI: {openai_config.requests_per_minute} RPM, {openai_config.max_concurrent} concurrent")
        print(f"DeepSeek: {deepseek_config.requests_per_minute} RPM, {deepseek_config.max_concurrent} concurrent")
        
        generator.shutdown()
        
    def test_rate_limiting_edge_cases(self):
        """Testa casos extremos de rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Edge case test", index=0)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.01)  # Delay mínimo
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Teste com rate limiting muito baixo
            generator = PipelineParallelGenerator(max_workers=1, max_concurrent_per_provider=1)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-edge-case"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações
            assert len(results) == 1
            assert execution_time > 0
            
            print(f"Edge case execution: {execution_time:.2f}s")
            
            # Mesmo com rate limiting baixo, deve completar
            assert execution_time < 1.0  # Máximo 1 segundo 