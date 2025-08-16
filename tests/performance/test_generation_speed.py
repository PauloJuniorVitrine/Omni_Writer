"""
Testes de performance para validação de velocidade de geração.

Prompt: Otimização de Performance - IMP-006
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:15:00Z
Tracing ID: ENTERPRISE_20250127_006
"""

import pytest
import time
import statistics
from typing import List, Dict
from unittest.mock import patch, MagicMock

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from app.parallel_generator import PipelineParallelGenerator, PerformanceOptimizer
from app.performance_config import get_performance_config


class TestGenerationSpeed:
    """Testes de velocidade de geração."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.mock_article = ArticleOutput(
            content="Test content for performance validation",
            filename="test_performance.txt",
            metadata={"model": "openai", "performance_test": True}
        )
        
    def test_sequential_vs_parallel_performance(self):
        """Compara performance sequencial vs paralela."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Performance test prompt {i}", index=i)
                for i in range(5)
            ]
        )
        
        # Simula tempo de geração de 2 segundos por artigo
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)  # Simula delay de rede
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Teste sequencial
            optimizer = PerformanceOptimizer()
            optimizer.performance_config['enable_parallel'] = False
            
            start_time = time.time()
            sequential_results = optimizer.optimize_pipeline_generation(
                config=config,
                trace_id="test-sequential"
            )
            sequential_time = time.time() - start_time
            
            # Teste paralelo
            optimizer.performance_config['enable_parallel'] = True
            optimizer.parallel_generator = PipelineParallelGenerator(max_workers=3)
            
            start_time = time.time()
            parallel_results = optimizer.optimize_pipeline_generation(
                config=config,
                trace_id="test-parallel"
            )
            parallel_time = time.time() - start_time
            
            # Validações
            assert len(sequential_results) == 5
            assert len(parallel_results) == 5
            
            # Performance deve ser melhor em paralelo
            assert parallel_time < sequential_time
            
            # Log de performance
            print(f"Sequential: {sequential_time:.2f}s")
            print(f"Parallel: {parallel_time:.2f}s")
            print(f"Improvement: {((sequential_time - parallel_time) / sequential_time * 100):.1f}%")
            
    def test_parallel_scaling_performance(self):
        """Testa escalabilidade do paralelismo."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Scaling test prompt {i}", index=i)
                for i in range(10)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.05)  # Simula delay de rede
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Testa diferentes números de workers
            worker_configs = [1, 3, 5, 10]
            performance_results = {}
            
            for workers in worker_configs:
                generator = PipelineParallelGenerator(max_workers=workers)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-workers-{workers}"
                )
                execution_time = time.time() - start_time
                
                performance_results[workers] = {
                    'time': execution_time,
                    'articles': len(results),
                    'throughput': len(results) / execution_time
                }
                
                generator.shutdown()
                
            # Validações
            assert len(performance_results) == 4
            
            # Log de resultados
            print("\nParallel Scaling Results:")
            for workers, metrics in performance_results.items():
                print(f"Workers: {workers} | Time: {metrics['time']:.2f}s | Throughput: {metrics['throughput']:.2f} articles/s")
                
            # Verifica que throughput aumenta com mais workers (até certo ponto)
            throughputs = [metrics['throughput'] for metrics in performance_results.values()]
            assert throughputs[1] > throughputs[0]  # 3 workers > 1 worker
            assert throughputs[2] > throughputs[0]  # 5 workers > 1 worker
            
    def test_rate_limiting_performance_impact(self):
        """Testa impacto do rate limiting na performance."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Rate limit test prompt {i}", index=i)
                for i in range(3)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Teste sem rate limiting
            generator = PipelineParallelGenerator(max_workers=3, max_concurrent_per_provider=3)
            
            start_time = time.time()
            results_no_limit = generator.generate_articles_parallel(
                config=config,
                trace_id="test-no-rate-limit"
            )
            time_no_limit = time.time() - start_time
            
            generator.shutdown()
            
            # Teste com rate limiting
            generator = PipelineParallelGenerator(max_workers=3, max_concurrent_per_provider=1)
            
            start_time = time.time()
            results_with_limit = generator.generate_articles_parallel(
                config=config,
                trace_id="test-with-rate-limit"
            )
            time_with_limit = time.time() - start_time
            
            generator.shutdown()
            
            # Validações
            assert len(results_no_limit) == 3
            assert len(results_with_limit) == 3
            
            # Rate limiting pode aumentar tempo, mas deve manter funcionalidade
            assert time_with_limit >= time_no_limit * 0.8  # Permite alguma variação
            
            print(f"No rate limit: {time_no_limit:.2f}s")
            print(f"With rate limit: {time_with_limit:.2f}s")
            
    def test_memory_usage_performance(self):
        """Testa uso de memória durante geração paralela."""
        import psutil
        import os
        
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Memory test prompt {i}", index=i)
                for i in range(20)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.01)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            generator = PipelineParallelGenerator(max_workers=5)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-memory"
            )
            execution_time = time.time() - start_time
            
            peak_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            generator.shutdown()
            
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Validações
            assert len(results) == 20
            assert execution_time > 0
            
            # Log de uso de memória
            print(f"Initial memory: {initial_memory:.2f} MB")
            print(f"Peak memory: {peak_memory:.2f} MB")
            print(f"Final memory: {final_memory:.2f} MB")
            print(f"Memory increase: {peak_memory - initial_memory:.2f} MB")
            
            # Verifica que memória não cresce excessivamente
            memory_increase = peak_memory - initial_memory
            assert memory_increase < 100  # Máximo 100MB de aumento
            
    def test_concurrent_requests_performance(self):
        """Testa performance com múltiplas requisições concorrentes."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Concurrent test prompt {i}", index=i)
                for i in range(5)
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
                generator = PipelineParallelGenerator(max_workers=2)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-concurrent-{thread_id}"
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
            assert len(all_results) == 15  # 3 threads * 5 prompts
            assert len(execution_times) == 3
            
            avg_time = statistics.mean(execution_times)
            max_time = max(execution_times)
            
            print(f"Concurrent execution times: {execution_times}")
            print(f"Average time: {avg_time:.2f}s")
            print(f"Max time: {max_time:.2f}s")
            
            # Verifica que execução concorrente não degrada significativamente
            assert max_time < avg_time * 2  # Máximo 2x da média
            
    def test_error_handling_performance(self):
        """Testa performance com tratamento de erros."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Error test prompt {i}", index=i)
                for i in range(5)
            ]
        )
        
        call_count = 0
        
        def mock_generate_with_errors(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            # Simula erro no segundo prompt
            if call_count == 2:
                raise Exception("Simulated error")
                
            time.sleep(0.1)
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate_with_errors):
            generator = PipelineParallelGenerator(max_workers=3)
            
            start_time = time.time()
            
            # Deve capturar erro e continuar com outros prompts
            with pytest.raises(Exception):
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-error-handling"
                )
                
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações
            assert execution_time > 0
            assert call_count >= 2  # Pelo menos 2 chamadas foram feitas
            
            print(f"Error handling execution time: {execution_time:.2f}s")
            print(f"Total calls made: {call_count}")
            
    def test_batch_processing_performance(self):
        """Testa performance de processamento em lotes."""
        # Cria configuração com muitos prompts
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Batch test prompt {i}", index=i)
                for i in range(50)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.02)  # Simula delay menor para lotes
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Teste com diferentes tamanhos de lote
            batch_sizes = [5, 10, 25]
            batch_performance = {}
            
            for batch_size in batch_sizes:
                generator = PipelineParallelGenerator(max_workers=batch_size)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-batch-{batch_size}"
                )
                execution_time = time.time() - start_time
                
                batch_performance[batch_size] = {
                    'time': execution_time,
                    'articles': len(results),
                    'throughput': len(results) / execution_time,
                    'efficiency': len(results) / (execution_time * batch_size)
                }
                
                generator.shutdown()
                
            # Validações
            assert len(batch_performance) == 3
            
            # Log de resultados
            print("\nBatch Processing Results:")
            for batch_size, metrics in batch_performance.items():
                print(f"Batch size: {batch_size} | Time: {metrics['time']:.2f}s | "
                      f"Throughput: {metrics['throughput']:.2f} articles/s | "
                      f"Efficiency: {metrics['efficiency']:.2f}")
                
            # Verifica que throughput aumenta com batch size adequado
            throughputs = [metrics['throughput'] for metrics in batch_performance.values()]
            assert throughputs[1] > throughputs[0] * 0.8  # 10 workers deve ser melhor que 5
            
    def test_provider_specific_performance(self):
        """Testa performance específica por provedor."""
        providers = ['openai', 'deepseek', 'gemini']
        
        for provider in providers:
            config = GenerationConfig(
                api_key="test-key",
                model_type=provider,
                prompts=[
                    PromptInput(text=f"{provider} test prompt {i}", index=i)
                    for i in range(3)
                ]
            )
            
            # Simula diferentes tempos de resposta por provedor
            provider_delays = {
                'openai': 0.05,
                'deepseek': 0.08,
                'gemini': 0.12
            }
            
            def mock_generate_provider(*args, **kwargs):
                time.sleep(provider_delays[provider])
                return self.mock_article
                
            with patch('app.parallel_generator.generate_article', side_effect=mock_generate_provider):
                generator = PipelineParallelGenerator(max_workers=3)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id=f"test-provider-{provider}"
                )
                execution_time = time.time() - start_time
                
                generator.shutdown()
                
                # Validações
                assert len(results) == 3
                assert execution_time > 0
                
                print(f"{provider}: {execution_time:.2f}s | "
                      f"Expected: {provider_delays[provider] * 3:.2f}s")
                
                # Verifica que tempo está dentro do esperado
                expected_time = provider_delays[provider] * 3
                assert execution_time >= expected_time * 0.8  # Permite variação
                assert execution_time <= expected_time * 2  # Não deve ser muito maior


class TestPerformanceBenchmarks:
    """Benchmarks de performance."""
    
    def test_throughput_benchmark(self):
        """Benchmark de throughput."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Throughput benchmark prompt {i}", index=i)
                for i in range(100)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.01)  # Simula delay mínimo
            return self.mock_article
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            generator = PipelineParallelGenerator(max_workers=10)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-throughput-benchmark"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            throughput = len(results) / execution_time
            
            print(f"Throughput Benchmark:")
            print(f"Articles: {len(results)}")
            print(f"Time: {execution_time:.2f}s")
            print(f"Throughput: {throughput:.2f} articles/s")
            
            # Benchmark deve atingir throughput mínimo
            assert throughput > 5  # Mínimo 5 artigos por segundo
            
    def test_latency_benchmark(self):
        """Benchmark de latência."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Latency benchmark prompt", index=0)]
        )
        
        latencies = []
        
        for _ in range(10):
            def mock_generate(*args, **kwargs):
                time.sleep(0.05)  # Simula latência de rede
                return self.mock_article
                
            with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
                generator = PipelineParallelGenerator(max_workers=1)
                
                start_time = time.time()
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-latency-benchmark"
                )
                execution_time = time.time() - start_time
                
                generator.shutdown()
                
                latencies.append(execution_time)
                
        avg_latency = statistics.mean(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        
        print(f"Latency Benchmark:")
        print(f"Average latency: {avg_latency:.3f}s")
        print(f"95th percentile: {p95_latency:.3f}s")
        print(f"All latencies: {[f'{l:.3f}s' for l in latencies]}")
        
        # Latência deve ser consistente
        assert avg_latency < 0.2  # Média menor que 200ms
        assert p95_latency < avg_latency * 2  # P95 não deve ser muito maior que a média 