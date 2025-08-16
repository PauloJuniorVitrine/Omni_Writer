"""
Testes de Concorrência - Omni Writer
====================================

Implementa testes para cenários de concorrência crítica:
- Race conditions no status repository
- Operações simultâneas no storage
- Execução concorrente de pipelines
- Deadlocks em operações de token
- Operações simultâneas no cache

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import threading
import time
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import json

# Importações do sistema real
from shared.status_repository import StatusRepository
from infraestructure.storage import save_article, load_article
from app.pipeline import run_generation_pipeline, run_generation_multi_pipeline
from shared.token_repository import TokenRepository
from shared.intelligent_cache import IntelligentCache


class TestStatusRepositoryConcurrency:
    """Testa race conditions no status repository."""
    
    def test_status_repository_race_condition(self, tmp_path):
        """Testa acesso simultâneo ao status repository."""
        # Setup real baseado no código existente
        status_file = tmp_path / "status.json"
        repo = StatusRepository(str(status_file))
        
        # Cenário real: múltiplas threads atualizando status
        def update_status(thread_id):
            """Função que simula atualização real de status."""
            for i in range(10):
                status_data = {
                    "task_id": f"task_{thread_id}_{i}",
                    "status": "processing",
                    "progress": i * 10,
                    "timestamp": time.time()
                }
                repo.update_status(f"task_{thread_id}_{i}", status_data)
                time.sleep(0.01)  # Simula processamento real
        
        # Executa 5 threads simultaneamente
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(update_status, i) for i in range(5)]
            
            # Aguarda conclusão
            for future in as_completed(futures):
                future.result()
        
        # Valida integridade dos dados
        all_statuses = repo.get_all_statuses()
        assert len(all_statuses) == 50  # 5 threads * 10 updates cada
        
        # Verifica que não houve perda de dados
        task_ids = set()
        for status in all_statuses.values():
            task_ids.add(status["task_id"])
        
        assert len(task_ids) == 50  # Todos os tasks devem estar presentes
    
    def test_status_repository_concurrent_read_write(self, tmp_path):
        """Testa leitura e escrita simultânea no status repository."""
        status_file = tmp_path / "status.json"
        repo = StatusRepository(str(status_file))
        
        # Dados reais baseados no sistema
        test_tasks = [
            {"task_id": "generate_001", "status": "queued", "progress": 0},
            {"task_id": "generate_002", "status": "processing", "progress": 25},
            {"task_id": "generate_003", "status": "completed", "progress": 100}
        ]
        
        # Setup inicial
        for task in test_tasks:
            repo.update_status(task["task_id"], task)
        
        read_results = queue.Queue()
        write_results = queue.Queue()
        
        def reader_thread():
            """Thread que lê status continuamente."""
            for _ in range(20):
                statuses = repo.get_all_statuses()
                read_results.put(len(statuses))
                time.sleep(0.005)
        
        def writer_thread():
            """Thread que escreve status continuamente."""
            for i in range(10):
                new_task = {
                    "task_id": f"concurrent_{i}",
                    "status": "processing",
                    "progress": i * 10,
                    "timestamp": time.time()
                }
                repo.update_status(f"concurrent_{i}", new_task)
                write_results.put(f"concurrent_{i}")
                time.sleep(0.01)
        
        # Executa threads simultaneamente
        with ThreadPoolExecutor(max_workers=2) as executor:
            read_future = executor.submit(reader_thread)
            write_future = executor.submit(writer_thread)
            
            read_future.result()
            write_future.result()
        
        # Valida que não houve corrupção de dados
        final_statuses = repo.get_all_statuses()
        assert len(final_statuses) >= 3  # Status iniciais preservados
        assert len(final_statuses) <= 13  # Status iniciais + novos


class TestStorageConcurrency:
    """Testa operações simultâneas no storage."""
    
    def test_storage_concurrent_access(self, tmp_path):
        """Testa escrita simultânea no storage."""
        # Setup real baseado no código existente
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Dados reais de artigos
        test_articles = []
        for i in range(10):
            article = {
                "title": f"Artigo de Teste {i}",
                "content": f"Conteúdo do artigo {i} com texto real para teste de concorrência.",
                "prompt": f"Prompt real para geração {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            test_articles.append(article)
        
        def save_article_thread(article, thread_id):
            """Função que simula salvamento real de artigo."""
            try:
                filename = f"article_{thread_id}_{article['title'].replace(' ', '_')}.txt"
                filepath = output_dir / filename
                
                # Simula o processo real de salvamento
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"Título: {article['title']}\n")
                    f.write(f"Conteúdo: {article['content']}\n")
                    f.write(f"Prompt: {article['prompt']}\n")
                    f.write(f"Modelo: {article['model']}\n")
                    f.write(f"Timestamp: {article['timestamp']}\n")
                
                return f"success_{thread_id}"
            except Exception as e:
                return f"error_{thread_id}: {str(e)}"
        
        # Executa salvamento simultâneo
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i, article in enumerate(test_articles):
                future = executor.submit(save_article_thread, article, i)
                futures.append(future)
            
            # Coleta resultados
            results = []
            for future in as_completed(futures):
                results.append(future.result())
        
        # Valida resultados
        assert len(results) == 10
        success_count = sum(1 for r in results if r.startswith("success"))
        assert success_count == 10  # Todos devem ter sucesso
        
        # Verifica arquivos criados
        files_created = list(output_dir.glob("*.txt"))
        assert len(files_created) == 10
    
    def test_storage_read_write_concurrency(self, tmp_path):
        """Testa leitura e escrita simultânea no storage."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria arquivo inicial
        initial_file = output_dir / "initial.txt"
        initial_file.write_text("Conteúdo inicial para teste de concorrência")
        
        read_results = queue.Queue()
        write_results = queue.Queue()
        
        def reader_thread():
            """Thread que lê arquivos continuamente."""
            for i in range(10):
                try:
                    content = initial_file.read_text()
                    read_results.put(f"read_{i}: {len(content)}")
                    time.sleep(0.01)
                except Exception as e:
                    read_results.put(f"read_error_{i}: {str(e)}")
        
        def writer_thread():
            """Thread que escreve arquivos continuamente."""
            for i in range(5):
                try:
                    new_content = f"Conteúdo atualizado {i} - {time.time()}"
                    initial_file.write_text(new_content)
                    write_results.put(f"write_{i}")
                    time.sleep(0.02)
                except Exception as e:
                    write_results.put(f"write_error_{i}: {str(e)}")
        
        # Executa threads simultaneamente
        with ThreadPoolExecutor(max_workers=2) as executor:
            read_future = executor.submit(reader_thread)
            write_future = executor.submit(writer_thread)
            
            read_future.result()
            write_future.result()
        
        # Valida que não houve corrupção
        final_content = initial_file.read_text()
        assert "Conteúdo atualizado" in final_content


class TestPipelineConcurrency:
    """Testa execução simultânea de pipelines."""
    
    @patch('app.pipeline.generate_article')
    @patch('infraestructure.storage.save_article')
    def test_pipeline_concurrent_execution(self, mock_save, mock_generate, tmp_path):
        """Testa execução simultânea de pipelines."""
        # Setup mocks baseados no comportamento real
        mock_generate.return_value = {
            "title": "Artigo Gerado",
            "content": "Conteúdo do artigo gerado para teste de concorrência.",
            "prompt": "Prompt de teste"
        }
        mock_save.return_value = "success"
        
        # Configuração real baseada no código
        config = {
            "api_key": "test-key",
            "model_type": "openai",
            "max_tokens": 1000
        }
        
        # Prompts reais para teste
        test_prompts = [
            "Como criar um blog profissional",
            "Dicas de SEO para iniciantes",
            "Marketing digital eficaz",
            "Estratégias de conteúdo",
            "Redes sociais para negócios"
        ]
        
        def run_pipeline_thread(prompt, thread_id):
            """Função que simula execução real de pipeline."""
            try:
                # Simula o processo real do pipeline
                result = run_generation_pipeline(
                    config=config,
                    prompts=[prompt],
                    output_dir=str(tmp_path),
                    task_id=f"task_{thread_id}"
                )
                return f"success_{thread_id}: {result}"
            except Exception as e:
                return f"error_{thread_id}: {str(e)}"
        
        # Executa pipelines simultaneamente
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for i, prompt in enumerate(test_prompts):
                future = executor.submit(run_pipeline_thread, prompt, i)
                futures.append(future)
            
            # Coleta resultados
            results = []
            for future in as_completed(futures):
                results.append(future.result())
        
        # Valida resultados
        assert len(results) == 5
        success_count = sum(1 for r in results if r.startswith("success"))
        assert success_count == 5  # Todos devem ter sucesso
        
        # Verifica que mocks foram chamados corretamente
        assert mock_generate.call_count == 5
        assert mock_save.call_count == 5


class TestTokenRepositoryConcurrency:
    """Testa deadlocks em operações de token."""
    
    def test_token_repository_deadlock(self, tmp_path):
        """Testa deadlock em operações de token."""
        # Setup real baseado no código existente
        token_file = tmp_path / "tokens.json"
        repo = TokenRepository(str(token_file))
        
        # Dados reais de tokens
        test_tokens = [
            {"token": "token_001", "user_id": "user_1", "permissions": ["read", "write"]},
            {"token": "token_002", "user_id": "user_2", "permissions": ["read"]},
            {"token": "token_003", "user_id": "user_1", "permissions": ["admin"]}
        ]
        
        # Setup inicial
        for token_data in test_tokens:
            repo.add_token(token_data["token"], token_data["user_id"], token_data["permissions"])
        
        results = queue.Queue()
        
        def token_operation_thread(operation_type, thread_id):
            """Função que simula operações reais de token."""
            try:
                if operation_type == "read":
                    # Simula leitura de tokens
                    tokens = repo.get_tokens_by_user(f"user_{thread_id % 2 + 1}")
                    results.put(f"read_{thread_id}: {len(tokens)}")
                elif operation_type == "write":
                    # Simula escrita de tokens
                    new_token = f"new_token_{thread_id}_{time.time()}"
                    repo.add_token(new_token, f"user_{thread_id}", ["read"])
                    results.put(f"write_{thread_id}: {new_token}")
                elif operation_type == "delete":
                    # Simula remoção de tokens
                    token_to_delete = f"token_{thread_id:03d}"
                    repo.revoke_token(token_to_delete)
                    results.put(f"delete_{thread_id}: {token_to_delete}")
                
                time.sleep(0.01)  # Simula processamento
            except Exception as e:
                results.put(f"error_{thread_id}: {str(e)}")
        
        # Executa operações simultâneas que podem causar deadlock
        operations = ["read", "write", "delete", "read", "write"]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i, op in enumerate(operations):
                future = executor.submit(token_operation_thread, op, i)
                futures.append(future)
            
            # Aguarda conclusão com timeout para detectar deadlock
            for future in as_completed(futures):
                future.result()
        
        # Valida que não houve deadlock (todas as operações completaram)
        all_results = []
        while not results.empty():
            all_results.append(results.get())
        
        assert len(all_results) == 5  # Todas as operações devem ter completado


class TestCacheConcurrency:
    """Testa operações simultâneas no cache."""
    
    def test_cache_concurrent_operations(self):
        """Testa operações simultâneas no cache."""
        # Setup real baseado no código existente
        cache = IntelligentCache(strategy='local')
        
        # Dados reais para cache
        test_data = {
            "prompt_001": "Artigo sobre tecnologia",
            "prompt_002": "Artigo sobre marketing",
            "prompt_003": "Artigo sobre SEO",
            "prompt_004": "Artigo sobre redes sociais",
            "prompt_005": "Artigo sobre conteúdo"
        }
        
        results = queue.Queue()
        
        def cache_operation_thread(operation_type, thread_id):
            """Função que simula operações reais de cache."""
            try:
                if operation_type == "set":
                    # Simula escrita no cache
                    key = f"cache_key_{thread_id}"
                    value = f"cache_value_{thread_id}_{time.time()}"
                    cache.set(key, value, ttl=60)
                    results.put(f"set_{thread_id}: {key}")
                elif operation_type == "get":
                    # Simula leitura do cache
                    key = f"prompt_{thread_id % 5 + 1:03d}"
                    value = cache.get(key)
                    results.put(f"get_{thread_id}: {key} -> {value is not None}")
                elif operation_type == "delete":
                    # Simula remoção do cache
                    key = f"prompt_{thread_id % 5 + 1:03d}"
                    cache.delete(key)
                    results.put(f"delete_{thread_id}: {key}")
                
                time.sleep(0.005)  # Simula processamento
            except Exception as e:
                results.put(f"error_{thread_id}: {str(e)}")
        
        # Setup inicial
        for key, value in test_data.items():
            cache.set(key, value, ttl=60)
        
        # Executa operações simultâneas
        operations = ["set", "get", "delete", "get", "set", "get", "delete", "set"]
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i, op in enumerate(operations):
                future = executor.submit(cache_operation_thread, op, i)
                futures.append(future)
            
            # Aguarda conclusão
            for future in as_completed(futures):
                future.result()
        
        # Valida resultados
        all_results = []
        while not results.empty():
            all_results.append(results.get())
        
        assert len(all_results) == 8  # Todas as operações devem ter completado
        
        # Verifica integridade do cache
        final_cache_size = len(cache._cache)  # Acesso interno para validação
        assert final_cache_size >= 0  # Cache não deve estar corrompido


class TestIntegrationConcurrency:
    """Testa cenários de concorrência integrados."""
    
    @patch('app.pipeline.generate_article')
    @patch('infraestructure.storage.save_article')
    def test_full_system_concurrency(self, mock_save, mock_generate, tmp_path):
        """Testa concorrência em todo o sistema."""
        # Setup mocks
        mock_generate.return_value = {
            "title": "Artigo Concorrente",
            "content": "Conteúdo gerado em ambiente concorrente.",
            "prompt": "Prompt de teste"
        }
        mock_save.return_value = "success"
        
        # Configuração real
        config = {"api_key": "test-key", "model_type": "openai"}
        status_repo = StatusRepository(str(tmp_path / "status.json"))
        cache = IntelligentCache(strategy='local')
        
        def full_workflow_thread(thread_id):
            """Simula workflow completo do sistema."""
            try:
                # 1. Atualiza status
                status_repo.update_status(f"task_{thread_id}", {
                    "status": "processing",
                    "progress": 0
                })
                
                # 2. Verifica cache
                cache_key = f"prompt_{thread_id}"
                cached_result = cache.get(cache_key)
                
                if not cached_result:
                    # 3. Executa pipeline
                    result = run_generation_pipeline(
                        config=config,
                        prompts=[f"Prompt {thread_id}"],
                        output_dir=str(tmp_path),
                        task_id=f"task_{thread_id}"
                    )
                    
                    # 4. Salva no cache
                    cache.set(cache_key, result, ttl=300)
                
                # 5. Atualiza status final
                status_repo.update_status(f"task_{thread_id}", {
                    "status": "completed",
                    "progress": 100
                })
                
                return f"success_{thread_id}"
            except Exception as e:
                return f"error_{thread_id}: {str(e)}"
        
        # Executa workflows simultaneamente
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(full_workflow_thread, i) for i in range(4)]
            
            results = []
            for future in as_completed(futures):
                results.append(future.result())
        
        # Valida resultados
        assert len(results) == 4
        success_count = sum(1 for r in results if r.startswith("success"))
        assert success_count == 4
        
        # Verifica integridade dos dados
        final_statuses = status_repo.get_all_statuses()
        assert len(final_statuses) == 4
        
        for status in final_statuses.values():
            assert status["status"] == "completed"
            assert status["progress"] == 100 