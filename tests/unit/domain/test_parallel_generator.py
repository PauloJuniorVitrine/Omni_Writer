"""
Testes Unitários - Paralelismo Controlado na Geração
====================================================

Testes baseados exclusivamente no código real implementado em:
- omni_writer/domain/parallel_generator.py

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from omni_writer.domain.parallel_generator import (
    ParallelArticleGenerator,
    RateLimiter,
    RateLimitConfig,
    GenerationTask
)


class TestRateLimiter:
    """Testes para o sistema de rate limiting"""
    
    def test_rate_limiter_initialization(self):
        """Testa inicialização do rate limiter"""
        rate_limiter = RateLimiter()
        
        assert 'openai' in rate_limiter.configs
        assert 'gemini' in rate_limiter.configs
        assert 'claude' in rate_limiter.configs
        
        # Verifica configurações padrão
        openai_config = rate_limiter.configs['openai']
        assert openai_config.requests_per_minute == 60
        assert openai_config.max_concurrent == 10
    
    def test_can_proceed_with_no_requests(self):
        """Testa se pode prosseguir quando não há requisições"""
        rate_limiter = RateLimiter()
        
        assert rate_limiter.can_proceed('openai') is True
        assert rate_limiter.can_proceed('gemini') is True
    
    def test_can_proceed_with_rate_limit_exceeded(self):
        """Testa bloqueio quando rate limit é excedido"""
        rate_limiter = RateLimiter()
        
        # Simula múltiplas requisições
        for _ in range(60):
            rate_limiter.record_request('openai')
        
        # A 61ª requisição deve ser bloqueada
        assert rate_limiter.can_proceed('openai') is False
    
    def test_can_proceed_with_concurrent_limit_exceeded(self):
        """Testa bloqueio quando limite de concorrência é excedido"""
        rate_limiter = RateLimiter()
        
        # Simula requisições ativas
        for _ in range(10):
            rate_limiter.record_request('openai')
        
        # A 11ª requisição deve ser bloqueada
        assert rate_limiter.can_proceed('openai') is False
    
    def test_release_request_decreases_active_count(self):
        """Testa liberação de requisição"""
        rate_limiter = RateLimiter()
        
        # Registra requisição
        rate_limiter.record_request('openai')
        assert rate_limiter.active_requests['openai'] == 1
        
        # Libera requisição
        rate_limiter.release_request('openai')
        assert rate_limiter.active_requests['openai'] == 0
    
    def test_cleanup_old_requests(self):
        """Testa limpeza de requisições antigas"""
        rate_limiter = RateLimiter()
        
        # Adiciona requisição antiga
        old_time = datetime.now() - timedelta(hours=2)
        rate_limiter.request_times['openai'].append(old_time)
        
        # Adiciona requisição recente
        recent_time = datetime.now()
        rate_limiter.request_times['openai'].append(recent_time)
        
        # Executa limpeza
        rate_limiter._cleanup_old_requests('openai', datetime.now())
        
        # Apenas a requisição recente deve permanecer
        assert len(rate_limiter.request_times['openai']) == 1
        assert rate_limiter.request_times['openai'][0] == recent_time


class TestGenerationTask:
    """Testes para a classe GenerationTask"""
    
    def test_generation_task_creation(self):
        """Testa criação de tarefa de geração"""
        task = GenerationTask(
            task_id="test_123",
            categoria_id=1,
            artigo_idx=1,
            prompt_data={"test": "data"},
            clusters="test_clusters",
            provider_name="openai",
            created_at=datetime.now(),
            priority=1
        )
        
        assert task.task_id == "test_123"
        assert task.categoria_id == 1
        assert task.artigo_idx == 1
        assert task.provider_name == "openai"
        assert task.priority == 1


class TestParallelArticleGenerator:
    """Testes para o gerador paralelo de artigos"""
    
    @pytest.fixture
    def mock_session(self):
        """Mock da sessão do banco"""
        session = Mock()
        
        # Mock da categoria
        categoria = Mock()
        categoria.id = 1
        categoria.prompt_path = "/test/prompt.txt"
        categoria.ia_provider = "openai"
        categoria.clusters = "test_clusters"
        
        # Mock do blog
        blog = Mock()
        blog.nome = "test_blog"
        categoria.blog = blog
        
        session.query.return_value.get.return_value = categoria
        return session
    
    @pytest.fixture
    def generator(self, mock_session):
        """Instância do gerador para testes"""
        return ParallelArticleGenerator(mock_session, "test_output", max_workers=2)
    
    def test_generator_initialization(self, mock_session):
        """Testa inicialização do gerador"""
        generator = ParallelArticleGenerator(mock_session, "test_output", max_workers=3)
        
        assert generator.max_workers == 3
        assert generator.output_dir == "test_output"
        assert generator.session == mock_session
        assert isinstance(generator.rate_limiter, RateLimiter)
    
    def test_generate_for_categoria_parallel_success(self, generator, mock_session):
        """Testa geração paralela bem-sucedida"""
        # Mock do parser
        with patch('omni_writer.domain.parallel_generator.PromptBaseArtigosParser') as mock_parser:
            mock_parser_instance = Mock()
            mock_parser_instance.parse.return_value = {"test": "prompt_data"}
            mock_parser.return_value = mock_parser_instance
            
            # Mock da geração de artigo
            with patch.object(generator, '_generate_single_article') as mock_generate:
                mock_generate.return_value = {
                    'task_id': 'test_1',
                    'artigo_idx': 1,
                    'success': True,
                    'content': 'Artigo gerado com sucesso',
                    'generation_time': 2.5,
                    'provider': 'openai'
                }
                
                # Mock do sistema de arquivos
                with patch('os.makedirs'), patch('builtins.open', create=True):
                    result = generator.generate_for_categoria_parallel(1, "2025-W01")
                    
                    assert result['categoria_id'] == 1
                    assert result['total_tasks'] == 6
                    assert result['successful'] == 6
                    assert result['failed'] == 0
    
    def test_generate_for_categoria_parallel_invalid_categoria(self, generator, mock_session):
        """Testa geração com categoria inválida"""
        # Mock de categoria não encontrada
        mock_session.query.return_value.get.return_value = None
        
        with pytest.raises(ValueError, match="Categoria inválida ou sem prompt associado"):
            generator.generate_for_categoria_parallel(999, "2025-W01")
    
    def test_generate_for_categoria_parallel_no_prompt_path(self, generator, mock_session):
        """Testa geração com categoria sem prompt"""
        # Mock de categoria sem prompt_path
        categoria = Mock()
        categoria.prompt_path = None
        mock_session.query.return_value.get.return_value = categoria
        
        with pytest.raises(ValueError, match="Categoria inválida ou sem prompt associado"):
            generator.generate_for_categoria_parallel(1, "2025-W01")
    
    def test_generate_single_article_success(self, generator):
        """Testa geração de artigo único com sucesso"""
        # Mock da categoria
        categoria = Mock()
        categoria.ia_provider = "openai"
        
        # Mock da tarefa
        task = GenerationTask(
            task_id="test_1",
            categoria_id=1,
            artigo_idx=1,
            prompt_data={"test": "data"},
            clusters="test_clusters",
            provider_name="openai",
            created_at=datetime.now(),
            priority=1
        )
        
        # Mock da geração de artigo
        with patch('omni_writer.domain.parallel_generator.ArticleGenerator') as mock_generator_class:
            mock_generator = Mock()
            mock_generator._generate_article_content.return_value = "Artigo gerado"
            mock_generator_class.return_value = mock_generator
            
            result = generator._generate_single_article(task, categoria)
            
            assert result['success'] is True
            assert result['content'] == "Artigo gerado"
            assert result['provider'] == "openai"
            assert 'generation_time' in result
    
    def test_generate_single_article_failure(self, generator):
        """Testa falha na geração de artigo único"""
        # Mock da categoria
        categoria = Mock()
        categoria.ia_provider = "openai"
        
        # Mock da tarefa
        task = GenerationTask(
            task_id="test_1",
            categoria_id=1,
            artigo_idx=1,
            prompt_data={"test": "data"},
            clusters="test_clusters",
            provider_name="openai",
            created_at=datetime.now(),
            priority=1
        )
        
        # Mock da geração de artigo com erro
        with patch('omni_writer.domain.parallel_generator.ArticleGenerator') as mock_generator_class:
            mock_generator = Mock()
            mock_generator._generate_article_content.side_effect = Exception("Erro de API")
            mock_generator_class.return_value = mock_generator
            
            result = generator._generate_single_article(task, categoria)
            
            assert result['success'] is False
            assert "Erro de API" in result['error']
            assert result['provider'] == "openai"
    
    def test_get_metrics(self, generator):
        """Testa obtenção de métricas"""
        # Simula algumas métricas
        generator.metrics['total_generated'] = 10
        generator.metrics['total_failed'] = 2
        generator.metrics['avg_generation_time'] = 5.5
        
        metrics = generator.get_metrics()
        
        assert metrics['total_generated'] == 10
        assert metrics['total_failed'] == 2
        assert metrics['avg_generation_time'] == 5.5
    
    def test_shutdown(self, generator):
        """Testa desligamento do gerador"""
        generator.shutdown()
        
        # Verifica se o executor foi desligado
        generator.executor.shutdown.assert_called_once_with(wait=True)
    
    def test_context_manager(self, generator):
        """Testa uso como context manager"""
        with generator as g:
            assert g == generator
        
        # Verifica se shutdown foi chamado
        generator.executor.shutdown.assert_called_once_with(wait=True)


class TestRateLimitConfig:
    """Testes para configuração de rate limiting"""
    
    def test_rate_limit_config_creation(self):
        """Testa criação de configuração de rate limit"""
        config = RateLimitConfig(
            provider_name="test_provider",
            requests_per_minute=30,
            requests_per_hour=1000,
            max_concurrent=5,
            retry_delay=2.0,
            backoff_multiplier=1.5
        )
        
        assert config.provider_name == "test_provider"
        assert config.requests_per_minute == 30
        assert config.requests_per_hour == 1000
        assert config.max_concurrent == 5
        assert config.retry_delay == 2.0
        assert config.backoff_multiplier == 1.5
    
    def test_rate_limit_config_defaults(self):
        """Testa valores padrão da configuração"""
        config = RateLimitConfig(
            provider_name="test_provider",
            requests_per_minute=3,
            requests_per_hour=60,
            max_concurrent=1
        )
        
        assert config.requests_per_minute == 3
        assert config.requests_per_hour == 60
        assert config.max_concurrent == 1
        assert config.retry_delay == 1.0
        assert config.backoff_multiplier == 2.0 