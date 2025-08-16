"""
Testes para Processamento Paralelo Real - Pipeline Otimizado

Prompt: Testes para Processamento Paralelo - Seção 3.1
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T20:30:00Z
Tracing ID: TEST_PIPELINE_PARALLEL_20250127_003

Testes baseados em código real do sistema Omni Writer.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock
from dataclasses import dataclass
from typing import List, Dict, Any

from app.pipeline import (
    GenerationTask, 
    ParallelProcessor, 
    BatchProcessor, 
    OptimizedPipeline
)
from omni_writer.domain.models import GenerationConfig, PromptInput


@dataclass
class MockPromptInput:
    """Mock de PromptInput para testes"""
    content: str = "Teste de prompt"
    style: str = "formal"
    tone: str = "profissional"


@dataclass
class MockGenerationConfig:
    """Mock de GenerationConfig para testes"""
    api_key: str = "test_key"
    model_type: str = "gpt-4"
    prompts: List[MockPromptInput] = None
    
    def __post_init__(self):
        if self.prompts is None:
            self.prompts = [MockPromptInput()]


class TestGenerationTask:
    """Testes para GenerationTask"""
    
    def test_generation_task_creation(self):
        """Testa criação de tarefa de geração"""
        config = MockGenerationConfig()
        prompt = MockPromptInput()
        
        task = GenerationTask(
            task_id="test_task_001",
            prompt=prompt,
            config=config,
            priority=1
        )
        
        assert task.task_id == "test_task_001"
        assert task.prompt == prompt
        assert task.config == config
        assert task.priority == 1
        assert task.created_at is not None
    
    def test_generation_task_default_priority(self):
        """Testa prioridade padrão da tarefa"""
        config = MockGenerationConfig()
        prompt = MockPromptInput()
        
        task = GenerationTask(
            task_id="test_task_002",
            prompt=prompt,
            config=config
        )
        
        assert task.priority == 1


class TestParallelProcessor:
    """Testes para ParallelProcessor"""
    
    @pytest.fixture
    def processor(self):
        """Fixture para ParallelProcessor"""
        return ParallelProcessor(max_workers=2)
    
    @pytest.mark.asyncio
    async def test_parallel_processor_initialization(self, processor):
        """Testa inicialização do processador paralelo"""
        assert processor.max_workers == 2
        assert processor.executor is not None
        assert processor.semaphore is not None
    
    @pytest.mark.asyncio
    async def test_process_single_task_success(self, processor):
        """Testa processamento de tarefa individual com sucesso"""
        config = MockGenerationConfig()
        prompt = MockPromptInput()
        
        task = GenerationTask(
            task_id="test_task_003",
            prompt=prompt,
            config=config
        )
        
        # Mock do generate_article
        with patch('app.pipeline.generate_article') as mock_generate:
            mock_article = Mock()
            mock_generate.return_value = mock_article
            
            result = await processor._process_task(task)
            
            assert result['task_id'] == "test_task_003"
            assert result['article'] == mock_article
            assert result['success'] is True
            assert result['execution_time'] > 0
    
    @pytest.mark.asyncio
    async def test_process_single_task_error(self, processor):
        """Testa processamento de tarefa individual com erro"""
        config = MockGenerationConfig()
        prompt = MockPromptInput()
        
        task = GenerationTask(
            task_id="test_task_004",
            prompt=prompt,
            config=config
        )
        
        # Mock do generate_article com erro
        with patch('app.pipeline.generate_article') as mock_generate:
            mock_generate.side_effect = Exception("Erro de teste")
            
            result = await processor._process_task(task)
            
            assert result['task_id'] == "test_task_004"
            assert result['success'] is False
            assert 'error' in result
            assert result['execution_time'] > 0
    
    @pytest.mark.asyncio
    async def test_process_batch_multiple_tasks(self, processor):
        """Testa processamento de lote com múltiplas tarefas"""
        config = MockGenerationConfig()
        tasks = []
        
        for i in range(3):
            task = GenerationTask(
                task_id=f"test_task_{i}",
                prompt=MockPromptInput(content=f"Prompt {i}"),
                config=config
            )
            tasks.append(task)
        
        # Mock do generate_article
        with patch('app.pipeline.generate_article') as mock_generate:
            mock_article = Mock()
            mock_generate.return_value = mock_article
            
            results = await processor.process_batch(tasks)
            
            assert len(results) == 3
            for result in results:
                assert result['success'] is True
                assert result['article'] == mock_article
    
    def test_processor_shutdown(self, processor):
        """Testa shutdown do processador"""
        processor.shutdown()
        # Verifica se o executor foi fechado
        assert processor.executor._shutdown is True


class TestBatchProcessor:
    """Testes para BatchProcessor"""
    
    @pytest.fixture
    def batch_processor(self):
        """Fixture para BatchProcessor"""
        return BatchProcessor(batch_size=2)
    
    def test_batch_processor_initialization(self, batch_processor):
        """Testa inicialização do processador de lotes"""
        assert batch_processor.batch_size == 2
        assert batch_processor.processor is not None
    
    @pytest.mark.asyncio
    async def test_process_prompts_single_batch(self, batch_processor):
        """Testa processamento de prompts em lote único"""
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content=f"Prompt {i}") for i in range(2)]
        
        # Mock do processamento paralelo
        with patch.object(batch_processor.processor, 'process_batch') as mock_process:
            mock_results = [
                {'task_id': f'test_task_{i}', 'success': True, 'article': Mock()}
                for i in range(2)
            ]
            mock_process.return_value = mock_results
            
            results = await batch_processor.process_prompts(config, "test_trace_id")
            
            assert len(results) == 2
            mock_process.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_prompts_multiple_batches(self, batch_processor):
        """Testa processamento de prompts em múltiplos lotes"""
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content=f"Prompt {i}") for i in range(5)]
        
        # Mock do processamento paralelo
        with patch.object(batch_processor.processor, 'process_batch') as mock_process:
            mock_results = [
                {'task_id': f'test_task_{i}', 'success': True, 'article': Mock()}
                for i in range(2)
            ]
            mock_process.return_value = mock_results
            
            results = await batch_processor.process_prompts(config, "test_trace_id")
            
            # Deve processar 3 lotes (2, 2, 1)
            assert mock_process.call_count == 3
            assert len(results) == 6  # 2 resultados por lote * 3 lotes
    
    def test_batch_processor_shutdown(self, batch_processor):
        """Testa shutdown do processador de lotes"""
        with patch.object(batch_processor.processor, 'shutdown') as mock_shutdown:
            batch_processor.shutdown()
            mock_shutdown.assert_called_once()


class TestOptimizedPipeline:
    """Testes para OptimizedPipeline"""
    
    @pytest.fixture
    def pipeline(self):
        """Fixture para OptimizedPipeline"""
        with patch('app.pipeline.get_performance_config') as mock_config:
            mock_config.return_value = Mock(batch_size=5)
            return OptimizedPipeline()
    
    def test_pipeline_initialization(self, pipeline):
        """Testa inicialização do pipeline otimizado"""
        assert pipeline.performance_config is not None
        assert pipeline.batch_processor is not None
    
    @pytest.mark.asyncio
    async def test_run_generation_pipeline_success(self, pipeline):
        """Testa execução bem-sucedida do pipeline"""
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content=f"Prompt {i}") for i in range(3)]
        
        # Mock do processamento de lotes
        with patch.object(pipeline.batch_processor, 'process_prompts') as mock_process:
            mock_results = [
                {
                    'task_id': f'test_task_{i}',
                    'success': True,
                    'article': Mock()
                }
                for i in range(3)
            ]
            mock_process.return_value = mock_results
            
            # Mock do save_article e make_zip
            with patch('app.pipeline.save_article') as mock_save:
                with patch('app.pipeline.make_zip') as mock_zip:
                    mock_zip.return_value = "/path/to/zip"
                    
                    result = await pipeline.run_generation_pipeline(config, "test_trace_id")
                    
                    assert result == "/path/to/zip"
                    assert mock_process.called
                    assert mock_save.call_count == 3
                    assert mock_zip.called
    
    @pytest.mark.asyncio
    async def test_run_generation_pipeline_with_errors(self, pipeline):
        """Testa execução do pipeline com alguns erros"""
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content=f"Prompt {i}") for i in range(3)]
        
        # Mock do processamento de lotes com alguns erros
        with patch.object(pipeline.batch_processor, 'process_prompts') as mock_process:
            mock_results = [
                {
                    'task_id': 'test_task_0',
                    'success': True,
                    'article': Mock()
                },
                {
                    'task_id': 'test_task_1',
                    'success': False,
                    'error': 'Erro de teste'
                },
                {
                    'task_id': 'test_task_2',
                    'success': True,
                    'article': Mock()
                }
            ]
            mock_process.return_value = mock_results
            
            # Mock do save_article e make_zip
            with patch('app.pipeline.save_article') as mock_save:
                with patch('app.pipeline.make_zip') as mock_zip:
                    mock_zip.return_value = "/path/to/zip"
                    
                    result = await pipeline.run_generation_pipeline(config, "test_trace_id")
                    
                    assert result == "/path/to/zip"
                    # Apenas 2 artigos devem ser salvos (os bem-sucedidos)
                    assert mock_save.call_count == 2
    
    @pytest.mark.asyncio
    async def test_run_generation_pipeline_exception(self, pipeline):
        """Testa execução do pipeline com exceção"""
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content="Prompt")]
        
        # Mock do processamento de lotes com exceção
        with patch.object(pipeline.batch_processor, 'process_prompts') as mock_process:
            mock_process.side_effect = Exception("Erro crítico")
            
            with pytest.raises(Exception, match="Erro crítico"):
                await pipeline.run_generation_pipeline(config, "test_trace_id")
    
    def test_pipeline_shutdown(self, pipeline):
        """Testa shutdown do pipeline"""
        with patch.object(pipeline.batch_processor, 'shutdown') as mock_shutdown:
            pipeline.batch_processor.shutdown()
            mock_shutdown.assert_called_once()


class TestPipelineIntegration:
    """Testes de integração do pipeline"""
    
    @pytest.mark.asyncio
    async def test_full_pipeline_flow(self):
        """Testa fluxo completo do pipeline"""
        # Configuração de teste
        config = MockGenerationConfig()
        config.prompts = [MockPromptInput(content=f"Prompt {i}") for i in range(4)]
        
        # Mock de todas as dependências
        with patch('app.pipeline.generate_article') as mock_generate:
            with patch('app.pipeline.save_article') as mock_save:
                with patch('app.pipeline.make_zip') as mock_zip:
                    with patch('app.pipeline.get_performance_config') as mock_config:
                        
                        # Configura mocks
                        mock_article = Mock()
                        mock_generate.return_value = mock_article
                        mock_zip.return_value = "/path/to/zip"
                        mock_config.return_value = Mock(batch_size=2)
                        
                        # Executa pipeline
                        pipeline = OptimizedPipeline()
                        result = await pipeline.run_generation_pipeline(config, "test_trace_id")
                        
                        # Validações
                        assert result == "/path/to/zip"
                        assert mock_generate.call_count == 4
                        assert mock_save.call_count == 4
                        assert mock_zip.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 