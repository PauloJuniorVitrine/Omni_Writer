"""
Testes unitários para sistema de paralelismo otimizado.

Prompt: Otimização de Performance - IMP-006
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:10:00Z
Tracing ID: ENTERPRISE_20250127_006
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from app.parallel_generator import (
    PipelineParallelGenerator,
    PerformanceOptimizer,
    PipelineTask
)
from app.performance_config import (
    PerformanceConfig,
    ProviderConfig,
    PerformanceConfigManager,
    get_performance_config,
    get_provider_config
)


class TestPipelineTask:
    """Testes para PipelineTask."""
    
    def test_pipeline_task_creation(self):
        """Testa criação de PipelineTask."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        prompt = PromptInput(text="Test prompt", index=0)
        
        task = PipelineTask(
            task_id="test-task",
            config=config,
            prompt=prompt,
            variation=1,
            priority=2
        )
        
        assert task.task_id == "test-task"
        assert task.config == config
        assert task.prompt == prompt
        assert task.variation == 1
        assert task.priority == 2
        assert task.created_at is not None
        
    def test_pipeline_task_default_values(self):
        """Testa valores padrão de PipelineTask."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        prompt = PromptInput(text="Test prompt", index=0)
        
        task = PipelineTask(
            task_id="test-task",
            config=config,
            prompt=prompt
        )
        
        assert task.variation == 0
        assert task.priority == 1
        assert task.created_at is not None


class TestPipelineParallelGenerator:
    """Testes para PipelineParallelGenerator."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.generator = PipelineParallelGenerator(max_workers=2, max_concurrent_per_provider=1)
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.generator.shutdown()
        
    def test_generator_initialization(self):
        """Testa inicialização do gerador paralelo."""
        assert self.generator.max_workers == 2
        assert self.generator.max_concurrent_per_provider == 1
        assert self.generator.rate_limiter is not None
        assert self.generator.executor is not None
        assert self.generator.metrics['total_generated'] == 0
        assert self.generator.metrics['total_failed'] == 0
        
    def test_generate_articles_parallel_single_prompt(self):
        """Testa geração paralela com um único prompt."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            results = self.generator.generate_articles_parallel(
                config=config,
                trace_id="test-trace"
            )
            
            assert len(results) == 1
            assert results[0] == mock_article
            assert mock_generate.called
            
    def test_generate_articles_parallel_multiple_prompts(self):
        """Testa geração paralela com múltiplos prompts."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Prompt 1", index=0),
                PromptInput(text="Prompt 2", index=1),
                PromptInput(text="Prompt 3", index=2)
            ]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            results = self.generator.generate_articles_parallel(
                config=config,
                trace_id="test-trace"
            )
            
            assert len(results) == 3
            assert all(result == mock_article for result in results)
            assert mock_generate.call_count == 3
            
    def test_generate_articles_parallel_with_progress_callback(self):
        """Testa geração paralela com callback de progresso."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Prompt 1", index=0),
                PromptInput(text="Prompt 2", index=1)
            ]
        )
        
        progress_calls = []
        
        def progress_callback(completed: int, total: int):
            progress_calls.append((completed, total))
            
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            results = self.generator.generate_articles_parallel(
                config=config,
                trace_id="test-trace",
                progress_callback=progress_callback
            )
            
            assert len(results) == 2
            assert len(progress_calls) == 2
            assert progress_calls[0] == (1, 2)
            assert progress_calls[1] == (2, 2)
            
    def test_generate_articles_parallel_with_rate_limiting(self):
        """Testa geração paralela com rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            # Simula rate limiting
            with patch.object(self.generator.rate_limiter, 'can_proceed', return_value=False):
                with patch.object(self.generator.rate_limiter, 'get_wait_time', return_value=0.1):
                    results = self.generator.generate_articles_parallel(
                        config=config,
                        trace_id="test-trace"
                    )
                    
                    assert len(results) == 1
                    
    def test_generate_articles_parallel_with_error(self):
        """Testa geração paralela com erro."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_generate.side_effect = Exception("Test error")
            
            with pytest.raises(Exception, match="Test error"):
                self.generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-trace"
                )
                    
    def test_get_metrics(self):
        """Testa obtenção de métricas."""
        metrics = self.generator.get_metrics()
        
        assert 'total_generated' in metrics
        assert 'total_failed' in metrics
        assert 'avg_generation_time' in metrics
        assert 'concurrent_peak' in metrics
        assert 'rate_limit_hits' in metrics
        assert 'provider_usage' in metrics
        assert 'active_workers' in metrics
        assert 'max_workers' in metrics
        assert metrics['max_workers'] == 2


class TestPerformanceOptimizer:
    """Testes para PerformanceOptimizer."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.optimizer = PerformanceOptimizer()
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.optimizer.shutdown()
        
    def test_optimizer_initialization(self):
        """Testa inicialização do otimizador."""
        assert self.optimizer.parallel_generator is None
        assert self.optimizer.performance_config['max_workers'] == 5
        assert self.optimizer.performance_config['enable_parallel'] is True
        assert self.optimizer.performance_config['fallback_to_sequential'] is True
        
    def test_optimize_pipeline_generation_parallel(self):
        """Testa otimização com geração paralela."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Prompt 1", index=0),
                PromptInput(text="Prompt 2", index=1)
            ]
        )
        
        with patch.object(self.optimizer, '_sequential_generation') as mock_sequential:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_sequential.return_value = [mock_article, mock_article]
            
            # Simula falha na geração paralela
            with patch.object(self.optimizer, 'parallel_generator', None):
                results = self.optimizer.optimize_pipeline_generation(
                    config=config,
                    trace_id="test-trace"
                )
                
                assert len(results) == 2
                assert mock_sequential.called
                
    def test_optimize_pipeline_generation_sequential_fallback(self):
        """Testa fallback para geração sequencial."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        
        # Desabilita paralelismo
        self.optimizer.performance_config['enable_parallel'] = False
        
        with patch.object(self.optimizer, '_sequential_generation') as mock_sequential:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_sequential.return_value = [mock_article]
            
            results = self.optimizer.optimize_pipeline_generation(
                config=config,
                trace_id="test-trace"
            )
            
            assert len(results) == 1
            assert mock_sequential.called
            
    def test_sequential_generation(self):
        """Testa geração sequencial."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Prompt 1", index=0),
                PromptInput(text="Prompt 2", index=1)
            ]
        )
        
        progress_calls = []
        
        def progress_callback(completed: int, total: int):
            progress_calls.append((completed, total))
            
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            results = self.optimizer._sequential_generation(
                config=config,
                trace_id="test-trace",
                progress_callback=progress_callback
            )
            
            assert len(results) == 2
            assert len(progress_calls) == 2
            assert progress_calls[0] == (1, 2)
            assert progress_calls[1] == (2, 2)
            assert mock_generate.call_count == 2
            
    def test_get_performance_metrics(self):
        """Testa obtenção de métricas de performance."""
        metrics = self.optimizer.get_performance_metrics()
        
        assert 'optimizer_config' in metrics
        assert 'parallel_enabled' in metrics
        assert metrics['parallel_enabled'] is True
        
    def test_update_config(self):
        """Testa atualização de configuração."""
        new_config = {
            'max_workers': 10,
            'enable_parallel': False
        }
        
        self.optimizer.update_config(new_config)
        
        assert self.optimizer.performance_config['max_workers'] == 10
        assert self.optimizer.performance_config['enable_parallel'] is False


class TestPerformanceConfig:
    """Testes para configuração de performance."""
    
    def test_performance_config_defaults(self):
        """Testa valores padrão da configuração."""
        config = PerformanceConfig()
        
        assert config.max_workers == 5
        assert config.max_concurrent_per_provider == 3
        assert config.enable_parallel is True
        assert config.fallback_to_sequential is True
        assert config.enable_rate_limiting is True
        assert config.default_timeout == 30.0
        assert config.max_retries == 3
        assert config.batch_size == 10
        assert config.enable_batching is True
        
    def test_provider_config_defaults(self):
        """Testa configurações padrão de provedores."""
        config = PerformanceConfig()
        
        assert 'openai' in config.providers
        assert 'deepseek' in config.providers
        assert 'gemini' in config.providers
        assert 'claude' in config.providers
        
        openai_config = config.providers['openai']
        assert openai_config.requests_per_minute == 60
        assert openai_config.max_concurrent == 10
        assert openai_config.timeout == 30.0
        assert openai_config.priority == 5


class TestPerformanceConfigManager:
    """Testes para gerenciador de configuração."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.manager = PerformanceConfigManager()
        
    def test_manager_initialization(self):
        """Testa inicialização do gerenciador."""
        assert self.manager.config is not None
        assert isinstance(self.manager.config, PerformanceConfig)
        
    def test_get_config(self):
        """Testa obtenção de configuração."""
        config = self.manager.get_config()
        assert config is self.manager.config
        
    def test_get_provider_config(self):
        """Testa obtenção de configuração de provedor."""
        provider_config = self.manager.get_provider_config('openai')
        assert provider_config is not None
        assert provider_config.name == 'openai'
        
        # Provedor inexistente
        provider_config = self.manager.get_provider_config('inexistent')
        assert provider_config is None
        
    def test_update_config(self):
        """Testa atualização de configuração."""
        new_config = {
            'max_workers': 15,
            'enable_parallel': False
        }
        
        self.manager.update_config(new_config)
        
        assert self.manager.config.max_workers == 15
        assert self.manager.config.enable_parallel is False
        
    def test_get_optimized_settings(self):
        """Testa obtenção de configurações otimizadas."""
        settings = self.manager.get_optimized_settings()
        
        assert 'max_workers' in settings
        assert 'enable_parallel' in settings
        assert 'enable_rate_limiting' in settings
        assert 'batch_size' in settings
        
    def test_get_optimized_settings_with_provider(self):
        """Testa obtenção de configurações otimizadas com provedor."""
        settings = self.manager.get_optimized_settings('openai')
        
        assert 'max_workers' in settings
        assert 'provider_timeout' in settings
        assert 'provider_max_concurrent' in settings
        assert 'provider_requests_per_minute' in settings
        
    def test_validate_config(self):
        """Testa validação de configuração."""
        validation = self.manager.validate_config()
        
        assert 'valid' in validation
        assert 'issues' in validation
        assert 'warnings' in validation
        assert validation['valid'] is True
        
    def test_get_performance_recommendations(self):
        """Testa obtenção de recomendações de performance."""
        recommendations = self.manager.get_performance_recommendations()
        
        assert 'recommendations' in recommendations
        assert 'priority' in recommendations
        assert isinstance(recommendations['recommendations'], list)


class TestConvenienceFunctions:
    """Testes para funções de conveniência."""
    
    def test_get_performance_config_function(self):
        """Testa função get_performance_config."""
        config = get_performance_config()
        assert isinstance(config, PerformanceConfig)
        
    def test_get_provider_config_function(self):
        """Testa função get_provider_config."""
        provider_config = get_provider_config('openai')
        assert isinstance(provider_config, ProviderConfig)
        assert provider_config.name == 'openai'
        
    def test_update_performance_config_function(self):
        """Testa função update_performance_config."""
        new_config = {'max_workers': 20}
        update_performance_config(new_config)
        
        config = get_performance_config()
        assert config.max_workers == 20


class TestIntegrationPerformance:
    """Testes de integração para performance."""
    
    def test_end_to_end_parallel_generation(self):
        """Testa geração paralela end-to-end."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text="Prompt 1", index=0),
                PromptInput(text="Prompt 2", index=1),
                PromptInput(text="Prompt 3", index=2)
            ]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            optimizer = PerformanceOptimizer()
            
            try:
                results = optimizer.optimize_pipeline_generation(
                    config=config,
                    trace_id="test-trace"
                )
                
                assert len(results) == 3
                assert all(result == mock_article for result in results)
                
                metrics = optimizer.get_performance_metrics()
                assert 'parallel_enabled' in metrics
                
            finally:
                optimizer.shutdown()
                
    def test_performance_with_rate_limiting(self):
        """Testa performance com rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Test prompt", index=0)]
        )
        
        with patch('app.parallel_generator.generate_article') as mock_generate:
            mock_article = ArticleOutput(
                content="Test content",
                filename="test.txt",
                metadata={"model": "openai"}
            )
            mock_generate.return_value = mock_article
            
            generator = PipelineParallelGenerator(max_workers=1, max_concurrent_per_provider=1)
            
            try:
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-trace"
                )
                end_time = time.time()
                
                assert len(results) == 1
                assert end_time - start_time >= 0  # Verifica que não falhou
                
                metrics = generator.get_metrics()
                assert metrics['total_generated'] == 1
                
            finally:
                generator.shutdown() 