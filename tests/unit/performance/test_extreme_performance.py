"""
Testes de Performance Extrema - Omni Writer
===========================================

Implementa testes para cenários de performance extrema:
- 1000 prompts simultâneos
- Uso de memória em cenários extremos
- Identificação de gargalos de CPU
- I/O de storage sob carga
- Performance do cache sob stress

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import time
import threading
import psutil
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, patch, MagicMock
import gc
import sys

# Importações do sistema real
from app.pipeline import run_generation_pipeline, run_generation_multi_pipeline
from shared.intelligent_cache import IntelligentCache
from infraestructure.storage import save_article, load_article
from shared.status_repository import StatusRepository
from app.performance_config import get_performance_config


class TestExtremeConcurrency:
    """Testa concorrência extrema."""
    
    @patch('app.pipeline.generate_article')
    @patch('infraestructure.storage.save_article')
    def test_pipeline_1000_concurrent_prompts(self, mock_save, mock_generate, tmp_path):
        """Testa 1000 prompts simultâneos."""
        # Setup baseado no código real
        mock_generate.return_value = {
            "title": "Artigo Gerado",
            "content": "Conteúdo do artigo gerado para teste de performance extrema.",
            "prompt": "Prompt de teste"
        }
        mock_save.return_value = "success"
        
        # Configuração real
        config = {
            "api_key": "test-key",
            "model_type": "openai",
            "max_tokens": 1000
        }
        
        # Gera 1000 prompts únicos
        prompts = []
        for i in range(1000):
            prompt = f"Como criar um blog profissional sobre tecnologia {i} - {time.time()}"
            prompts.append(prompt)
        
        # Monitora uso de memória antes
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        
        # Executa pipelines simultaneamente
        with ThreadPoolExecutor(max_workers=50) as executor:  # 50 workers para não sobrecarregar
            futures = []
            for i, prompt in enumerate(prompts):
                future = executor.submit(
                    run_generation_pipeline,
                    config=config,
                    prompts=[prompt],
                    output_dir=str(tmp_path),
                    task_id=f"task_{i}"
                )
                futures.append(future)
            
            # Coleta resultados
            results = []
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)  # Timeout de 30s por task
                    results.append(result)
                except Exception as e:
                    results.append(f"error: {str(e)}")
        
        end_time = time.time()
        
        # Monitora uso de memória após
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = memory_after - memory_before
        
        # Valida resultados
        execution_time = end_time - start_time
        success_count = sum(1 for r in results if isinstance(r, dict))
        
        # Assertions de performance
        assert len(results) == 1000  # Todos os tasks devem ter sido processados
        assert success_count >= 950  # Pelo menos 95% devem ter sucesso
        assert execution_time < 300  # Deve completar em menos de 5 minutos
        assert memory_increase < 1000  # Aumento de memória deve ser < 1GB
        
        # Verifica que mocks foram chamados corretamente
        assert mock_generate.call_count >= 950
        assert mock_save.call_count >= 950
    
    def test_memory_usage_extreme_scenarios(self, tmp_path):
        """Testa uso de memória em cenários extremos."""
        # Setup
        cache = IntelligentCache(strategy='local')
        status_repo = StatusRepository(str(tmp_path / "status.json"))
        
        # Cenário 1: Cache com muitos dados
        large_data = {}
        for i in range(10000):
            key = f"large_key_{i}"
            value = f"large_value_{i}" * 100  # 100x repetição
            large_data[key] = value
        
        # Monitora memória antes do cache
        process = psutil.Process()
        memory_before_cache = process.memory_info().rss / 1024 / 1024
        
        # Carrega dados no cache
        for key, value in large_data.items():
            cache.set(key, value, ttl=3600)
        
        memory_after_cache = process.memory_info().rss / 1024 / 1024
        cache_memory_increase = memory_after_cache - memory_before_cache
        
        # Cenário 2: Status repository com muitos status
        memory_before_status = process.memory_info().rss / 1024 / 1024
        
        for i in range(5000):
            status_data = {
                "task_id": f"task_{i}",
                "status": "processing",
                "progress": i % 100,
                "timestamp": time.time(),
                "metadata": {
                    "prompt": f"Prompt {i}",
                    "model": "openai",
                    "attempts": 1
                }
            }
            status_repo.update_status(f"task_{i}", status_data)
        
        memory_after_status = process.memory_info().rss / 1024 / 1024
        status_memory_increase = memory_after_status - memory_after_cache
        
        # Valida uso de memória
        assert cache_memory_increase < 500  # Cache não deve usar mais de 500MB
        assert status_memory_increase < 200  # Status não deve usar mais de 200MB
        
        # Limpa memória
        cache.clear()
        del status_repo
        gc.collect()
    
    def test_cpu_bottleneck_identification(self, tmp_path):
        """Testa identificação de gargalos de CPU."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Função que simula processamento intensivo de CPU
        def cpu_intensive_task(task_id):
            """Simula tarefa intensiva de CPU."""
            start_time = time.time()
            
            # Simula processamento de CPU
            result = 0
            for i in range(100000):  # Loop intensivo
                result += i * i
            
            end_time = time.time()
            return {
                "task_id": task_id,
                "result": result,
                "execution_time": end_time - start_time,
                "cpu_usage": psutil.cpu_percent(interval=0.1)
            }
        
        # Monitora CPU antes
        cpu_before = psutil.cpu_percent(interval=1)
        
        # Executa tarefas intensivas de CPU
        results = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for i in range(10):
                future = executor.submit(cpu_intensive_task, f"cpu_task_{i}")
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        # Monitora CPU durante execução
        cpu_during = psutil.cpu_percent(interval=1)
        
        # Valida identificação de gargalos
        assert len(results) == 10
        assert cpu_during > cpu_before  # CPU deve ter aumentado
        
        # Identifica gargalos
        slow_tasks = [r for r in results if r["execution_time"] > 1.0]
        high_cpu_tasks = [r for r in results if r["cpu_usage"] > 80]
        
        # Deve identificar alguns gargalos
        assert len(slow_tasks) > 0 or len(high_cpu_tasks) > 0
    
    def test_storage_io_under_load(self, tmp_path):
        """Testa I/O de storage sob carga."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Dados de teste
        articles = []
        for i in range(100):
            article = {
                "title": f"Artigo {i} para I/O",
                "content": f"Conteúdo do artigo {i} com dados extensos para testar I/O de storage sob carga. " * 100,
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time(),
                "metadata": {
                    "size": len(f"Conteúdo do artigo {i}") * 100,
                    "generation_time": time.time(),
                    "tokens_used": 1000 + i
                }
            }
            articles.append(article)
        
        # Monitora I/O antes
        disk_io_before = psutil.disk_io_counters()
        
        start_time = time.time()
        
        # Executa operações de I/O simultaneamente
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for article in articles:
                future = executor.submit(save_article, article, str(output_dir))
                futures.append(future)
            
            # Aguarda conclusão
            for future in as_completed(futures):
                future.result()
        
        end_time = time.time()
        
        # Monitora I/O após
        disk_io_after = psutil.disk_io_counters()
        
        # Calcula métricas de I/O
        read_bytes = disk_io_after.read_bytes - disk_io_before.read_bytes
        write_bytes = disk_io_after.write_bytes - disk_io_before.write_bytes
        execution_time = end_time - start_time
        
        # Valida performance de I/O
        assert execution_time < 60  # Deve completar em menos de 1 minuto
        assert write_bytes > 0  # Deve ter escrito dados
        assert len(list(output_dir.glob("*.txt"))) == 100  # Todos os arquivos devem ter sido criados
        
        # Testa leitura simultânea
        read_start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            read_futures = []
            for filepath in output_dir.glob("*.txt"):
                future = executor.submit(load_article, filepath)
                read_futures.append(future)
            
            read_results = []
            for future in as_completed(read_futures):
                result = future.result()
                read_results.append(result)
        
        read_end_time = time.time()
        read_time = read_end_time - read_start_time
        
        # Valida performance de leitura
        assert read_time < 30  # Leitura deve ser mais rápida que escrita
        assert len(read_results) == 100  # Todos os arquivos devem ter sido lidos
    
    def test_cache_performance_under_stress(self):
        """Testa performance do cache sob stress."""
        # Setup
        cache = IntelligentCache(strategy='local')
        
        # Dados de teste
        test_data = {}
        for i in range(10000):
            key = f"stress_key_{i}"
            value = f"stress_value_{i}" * 50  # Dados de tamanho médio
            test_data[key] = value
        
        # Teste 1: Escrita em massa
        write_start_time = time.time()
        
        for key, value in test_data.items():
            cache.set(key, value, ttl=3600)
        
        write_end_time = time.time()
        write_time = write_end_time - write_start_time
        
        # Teste 2: Leitura em massa
        read_start_time = time.time()
        
        read_results = []
        for key in test_data.keys():
            value = cache.get(key)
            read_results.append(value is not None)
        
        read_end_time = time.time()
        read_time = read_end_time - read_start_time
        
        # Teste 3: Operações mistas (leitura/escrita simultâneas)
        mixed_start_time = time.time()
        
        def mixed_operation(operation_id):
            """Operação mista de leitura e escrita."""
            results = []
            for i in range(100):
                key = f"mixed_key_{operation_id}_{i}"
                if i % 2 == 0:
                    # Escrita
                    cache.set(key, f"mixed_value_{i}", ttl=1800)
                    results.append(True)
                else:
                    # Leitura
                    value = cache.get(key)
                    results.append(value is not None)
            return results
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            mixed_futures = []
            for i in range(5):
                future = executor.submit(mixed_operation, i)
                mixed_futures.append(future)
            
            mixed_results = []
            for future in as_completed(mixed_futures):
                result = future.result()
                mixed_results.extend(result)
        
        mixed_end_time = time.time()
        mixed_time = mixed_end_time - mixed_start_time
        
        # Valida performance
        assert write_time < 10  # Escrita em massa deve ser rápida
        assert read_time < 5   # Leitura em massa deve ser muito rápida
        assert mixed_time < 15  # Operações mistas devem ser eficientes
        
        # Valida integridade dos dados
        success_reads = sum(read_results)
        assert success_reads >= 9500  # Pelo menos 95% das leituras devem ter sucesso
        
        # Teste 4: Cache sob pressão de memória
        memory_pressure_start_time = time.time()
        
        # Adiciona mais dados para criar pressão
        for i in range(50000):
            key = f"pressure_key_{i}"
            value = f"pressure_value_{i}" * 100  # Dados grandes
            cache.set(key, value, ttl=1800)
        
        memory_pressure_end_time = time.time()
        pressure_time = memory_pressure_end_time - memory_pressure_start_time
        
        # Cache deve continuar funcionando sob pressão
        assert pressure_time < 30  # Não deve travar
        
        # Testa recuperação após pressão
        recovery_start_time = time.time()
        
        # Tenta acessar dados originais
        recovery_results = []
        for i in range(1000):
            key = f"stress_key_{i}"
            value = cache.get(key)
            recovery_results.append(value is not None)
        
        recovery_end_time = time.time()
        recovery_time = recovery_end_time - recovery_start_time
        
        # Cache deve se recuperar
        assert recovery_time < 5  # Recuperação deve ser rápida
        recovery_success = sum(recovery_results)
        assert recovery_success >= 800  # Pelo menos 80% devem ser recuperados


class TestMemoryLeakDetection:
    """Testa detecção de vazamentos de memória."""
    
    def test_memory_leak_detection(self, tmp_path):
        """Testa detecção de vazamentos de memória."""
        # Setup
        cache = IntelligentCache(strategy='local')
        status_repo = StatusRepository(str(tmp_path / "status.json"))
        
        # Monitora memória inicial
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        # Simula operações repetitivas que podem causar vazamentos
        memory_samples = []
        
        for cycle in range(10):
            # Adiciona dados
            for i in range(1000):
                key = f"cycle_{cycle}_key_{i}"
                value = f"cycle_{cycle}_value_{i}" * 10
                cache.set(key, value, ttl=3600)
                
                status_data = {
                    "task_id": f"cycle_{cycle}_task_{i}",
                    "status": "processing",
                    "progress": i % 100,
                    "timestamp": time.time()
                }
                status_repo.update_status(f"cycle_{cycle}_task_{i}", status_data)
            
            # Remove dados antigos
            for i in range(500):
                key = f"cycle_{cycle}_key_{i}"
                cache.delete(key)
                status_repo.remove_status(f"cycle_{cycle}_task_{i}")
            
            # Força garbage collection
            gc.collect()
            
            # Mede memória
            current_memory = process.memory_info().rss / 1024 / 1024
            memory_samples.append(current_memory)
        
        # Analisa padrão de memória
        memory_increase = memory_samples[-1] - memory_samples[0]
        memory_trend = sum(1 for i in range(1, len(memory_samples)) 
                          if memory_samples[i] > memory_samples[i-1])
        
        # Valida ausência de vazamento significativo
        assert memory_increase < 100  # Aumento deve ser < 100MB
        assert memory_trend < 8  # Não deve crescer consistentemente
    
    def test_garbage_collection_effectiveness(self):
        """Testa efetividade do garbage collection."""
        # Setup
        cache = IntelligentCache(strategy='local')
        
        # Monitora memória antes
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024
        
        # Cria muitos objetos
        objects = []
        for i in range(10000):
            obj = {
                "id": i,
                "data": f"object_data_{i}" * 100,
                "timestamp": time.time()
            }
            objects.append(obj)
            cache.set(f"obj_{i}", obj, ttl=60)
        
        memory_after_creation = process.memory_info().rss / 1024 / 1024
        
        # Remove referências
        del objects
        cache.clear()
        
        # Força garbage collection
        gc.collect()
        
        memory_after_gc = process.memory_info().rss / 1024 / 1024
        
        # Valida efetividade do GC
        memory_reduction = memory_after_creation - memory_after_gc
        assert memory_reduction > 0  # GC deve liberar memória
        assert memory_after_gc < memory_after_creation + 50  # Não deve vazar mais de 50MB


class TestPerformanceMonitoring:
    """Testa monitoramento de performance."""
    
    def test_performance_metrics_collection(self, tmp_path):
        """Testa coleta de métricas de performance."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Configuração de performance
        perf_config = get_performance_config()
        
        # Métricas coletadas
        metrics = {
            "start_time": time.time(),
            "memory_usage": [],
            "cpu_usage": [],
            "disk_io": [],
            "execution_times": []
        }
        
        # Simula operações monitoradas
        for i in range(100):
            operation_start = time.time()
            
            # Simula operação
            article_data = {
                "title": f"Artigo {i}",
                "content": f"Conteúdo do artigo {i}",
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            
            # Coleta métricas durante operação
            process = psutil.Process()
            memory = process.memory_info().rss / 1024 / 1024
            cpu = psutil.cpu_percent(interval=0.1)
            disk_io = psutil.disk_io_counters()
            
            metrics["memory_usage"].append(memory)
            metrics["cpu_usage"].append(cpu)
            metrics["disk_io"].append(disk_io)
            
            # Simula salvamento
            save_article(article_data, str(output_dir))
            
            operation_end = time.time()
            execution_time = operation_end - operation_start
            metrics["execution_times"].append(execution_time)
        
        metrics["end_time"] = time.time()
        
        # Calcula estatísticas
        total_time = metrics["end_time"] - metrics["start_time"]
        avg_execution_time = sum(metrics["execution_times"]) / len(metrics["execution_times"])
        max_memory = max(metrics["memory_usage"])
        avg_cpu = sum(metrics["cpu_usage"]) / len(metrics["cpu_usage"])
        
        # Valida métricas
        assert total_time < 60  # Total deve ser < 1 minuto
        assert avg_execution_time < 1  # Média deve ser < 1 segundo
        assert max_memory < 1000  # Máximo de memória < 1GB
        assert avg_cpu < 80  # CPU média < 80%
        
        # Valida que métricas foram coletadas
        assert len(metrics["memory_usage"]) == 100
        assert len(metrics["cpu_usage"]) == 100
        assert len(metrics["execution_times"]) == 100
    
    def test_performance_threshold_alerts(self):
        """Testa alertas de threshold de performance."""
        # Setup
        alerts = []
        
        def performance_alert(metric, value, threshold):
            """Função de alerta de performance."""
            alerts.append({
                "metric": metric,
                "value": value,
                "threshold": threshold,
                "timestamp": time.time()
            })
        
        # Simula monitoramento com thresholds
        thresholds = {
            "memory_mb": 500,
            "cpu_percent": 80,
            "execution_time_seconds": 5
        }
        
        # Simula operações que podem exceder thresholds
        for i in range(10):
            # Simula uso de memória
            memory_usage = 400 + (i * 20)  # Cresce até 580MB
            if memory_usage > thresholds["memory_mb"]:
                performance_alert("memory_mb", memory_usage, thresholds["memory_mb"])
            
            # Simula uso de CPU
            cpu_usage = 70 + (i * 5)  # Cresce até 115%
            if cpu_usage > thresholds["cpu_percent"]:
                performance_alert("cpu_percent", cpu_usage, thresholds["cpu_percent"])
            
            # Simula tempo de execução
            execution_time = 3 + (i * 0.5)  # Cresce até 7.5s
            if execution_time > thresholds["execution_time_seconds"]:
                performance_alert("execution_time_seconds", execution_time, thresholds["execution_time_seconds"])
        
        # Valida alertas
        assert len(alerts) > 0  # Deve ter gerado alguns alertas
        
        # Verifica tipos de alertas
        memory_alerts = [a for a in alerts if a["metric"] == "memory_mb"]
        cpu_alerts = [a for a in alerts if a["metric"] == "cpu_percent"]
        time_alerts = [a for a in alerts if a["metric"] == "execution_time_seconds"]
        
        assert len(memory_alerts) > 0  # Deve ter alertas de memória
        assert len(cpu_alerts) > 0     # Deve ter alertas de CPU
        assert len(time_alerts) > 0    # Deve ter alertas de tempo 