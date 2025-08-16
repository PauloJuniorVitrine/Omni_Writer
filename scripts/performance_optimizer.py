"""
Script de Otimização de Performance para Omni Writer.
Identifica e otimiza endpoints com performance abaixo do esperado.

Prompt: Implementação de Otimização de Performance
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T13:00:00Z
Tracing ID: PERFORMANCE_OPTIMIZER_20250128_001
"""
import os
import json
import time
import logging
import requests
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict, deque
import psutil
import sqlite3
import hashlib

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("performance_optimizer")

@dataclass
class PerformanceMetrics:
    """Métricas de performance de um endpoint."""
    endpoint: str
    method: str
    response_time_ms: float
    status_code: int
    payload_size_bytes: int
    timestamp: datetime
    cpu_usage_percent: float
    memory_usage_mb: float
    is_slow: bool
    trace_id: str
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'endpoint': self.endpoint,
            'method': self.method,
            'response_time_ms': self.response_time_ms,
            'status_code': self.status_code,
            'payload_size_bytes': self.payload_size_bytes,
            'timestamp': self.timestamp.isoformat(),
            'cpu_usage_percent': self.cpu_usage_percent,
            'memory_usage_mb': self.memory_usage_mb,
            'is_slow': self.is_slow,
            'trace_id': self.trace_id
        }

@dataclass
class OptimizationRecommendation:
    """Recomendação de otimização."""
    recommendation_id: str
    endpoint: str
    issue_type: str  # 'slow_response', 'high_cpu', 'high_memory', 'bottleneck'
    severity: str  # 'low', 'medium', 'high', 'critical'
    current_value: float
    target_value: float
    improvement_percent: float
    description: str
    recommendations: List[str]
    estimated_impact: str
    timestamp: datetime
    trace_id: str
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'recommendation_id': self.recommendation_id,
            'endpoint': self.endpoint,
            'issue_type': self.issue_type,
            'severity': self.severity,
            'current_value': self.current_value,
            'target_value': self.target_value,
            'improvement_percent': self.improvement_percent,
            'description': self.description,
            'recommendations': self.recommendations,
            'estimated_impact': self.estimated_impact,
            'timestamp': self.timestamp.isoformat(),
            'trace_id': self.trace_id
        }

class PerformanceOptimizer:
    """
    Otimizador de performance para identificar e resolver gargalos.
    Baseado no código real do projeto Omni Writer.
    """
    
    def __init__(self, config_path: str = "scripts/performance_optimizer_config.json"):
        """
        Inicializa o otimizador de performance.
        
        Args:
            config_path: Caminho para arquivo de configuração
        """
        self.config = self._load_config(config_path)
        self.base_url = self.config.get('base_url', 'http://localhost:5000')
        self.metrics_history: deque = deque(maxlen=self.config.get('max_history', 10000))
        self.recommendations_history: deque = deque(maxlen=self.config.get('max_recommendations', 1000))
        self.endpoint_stats: Dict[str, Dict] = defaultdict(lambda: {
            'total_requests': 0,
            'total_response_time_ms': 0,
            'avg_response_time_ms': 0,
            'max_response_time_ms': 0,
            'min_response_time_ms': float('inf'),
            'slow_requests_count': 0,
            'error_count': 0,
            'cpu_usage_samples': [],
            'memory_usage_samples': []
        })
        self.trace_id = f"PERF_OPT_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.running = False
        
        logger.info(f"Performance Optimizer inicializado | trace_id={self.trace_id}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Carrega configuração do otimizador."""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                # Configuração padrão baseada no projeto real
                return {
                    "base_url": "http://localhost:5000",
                    "thresholds": {
                        "response_time_ms": {
                            "low": 100,      # 100ms
                            "medium": 300,   # 300ms
                            "high": 1000,    # 1s
                            "critical": 5000 # 5s
                        },
                        "cpu_usage_percent": {
                            "low": 20,
                            "medium": 50,
                            "high": 80,
                            "critical": 95
                        },
                        "memory_usage_mb": {
                            "low": 100,
                            "medium": 500,
                            "high": 1000,
                            "critical": 2000
                        }
                    },
                    "endpoint_targets": {
                        "/api/generate-articles": {"response_time_ms": 2000},
                        "/api/entrega-zip": {"response_time_ms": 5000},
                        "/generate": {"response_time_ms": 3000},
                        "/download": {"response_time_ms": 1000}
                    },
                    "monitoring": {
                        "enabled": True,
                        "sample_rate": 1.0,
                        "max_history": 10000,
                        "max_recommendations": 1000,
                        "test_interval_seconds": 60
                    },
                    "optimization": {
                        "enable_caching": True,
                        "enable_compression": True,
                        "enable_connection_pooling": True,
                        "enable_query_optimization": True
                    },
                    "notification_channels": ["slack", "email"],
                    "reporting": {
                        "generate_reports": True,
                        "report_interval_hours": 24,
                        "save_to_file": True
                    }
                }
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            return {}
    
    def get_system_metrics(self) -> Tuple[float, float]:
        """
        Obtém métricas do sistema.
        
        Returns:
            (cpu_usage_percent, memory_usage_mb)
        """
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage_mb = memory.used / (1024 * 1024)
            
            return cpu_usage, memory_usage_mb
            
        except Exception as e:
            logger.error(f"Erro ao obter métricas do sistema: {e}")
            return 0.0, 0.0
    
    def test_endpoint_performance(self, endpoint: str, method: str = "GET", 
                                payload: Dict = None, timeout: int = 30) -> PerformanceMetrics:
        """
        Testa performance de um endpoint.
        
        Args:
            endpoint: Endpoint a ser testado
            method: Método HTTP
            payload: Payload da requisição
            timeout: Timeout em segundos
            
        Returns:
            Métricas de performance
        """
        try:
            # Obtém métricas do sistema antes da requisição
            cpu_before, memory_before = self.get_system_metrics()
            
            # Faz a requisição
            start_time = time.time()
            
            if method.upper() == "GET":
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    timeout=timeout
                )
            elif method.upper() == "POST":
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=payload or {},
                    timeout=timeout
                )
            else:
                response = requests.request(
                    method,
                    f"{self.base_url}{endpoint}",
                    json=payload or {},
                    timeout=timeout
                )
            
            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000
            
            # Obtém métricas do sistema após a requisição
            cpu_after, memory_after = self.get_system_metrics()
            
            # Calcula payload size
            payload_size = len(response.content) if response.content else 0
            
            # Verifica se é lento
            is_slow = self._is_endpoint_slow(endpoint, response_time_ms)
            
            metrics = PerformanceMetrics(
                endpoint=endpoint,
                method=method,
                response_time_ms=response_time_ms,
                status_code=response.status_code,
                payload_size_bytes=payload_size,
                timestamp=datetime.utcnow(),
                cpu_usage_percent=max(cpu_before, cpu_after),
                memory_usage_mb=max(memory_before, memory_after),
                is_slow=is_slow,
                trace_id=self.trace_id
            )
            
            # Atualiza estatísticas
            self._update_endpoint_stats(metrics)
            
            # Adiciona ao histórico
            self.metrics_history.append(metrics)
            
            # Gera recomendações se necessário
            if is_slow or metrics.status_code >= 400:
                self._generate_optimization_recommendations(metrics)
            
            return metrics
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout ao testar {endpoint}")
            return self._create_timeout_metrics(endpoint, method)
            
        except Exception as e:
            logger.error(f"Erro ao testar {endpoint}: {e}")
            return self._create_error_metrics(endpoint, method, str(e))
    
    def _is_endpoint_slow(self, endpoint: str, response_time_ms: float) -> bool:
        """Verifica se endpoint está lento."""
        try:
            # Verifica target específico do endpoint
            endpoint_target = self.config.get('endpoint_targets', {}).get(endpoint, {})
            target_time = endpoint_target.get('response_time_ms', 1000)
            
            if response_time_ms > target_time:
                return True
            
            # Verifica thresholds gerais
            thresholds = self.config.get('thresholds', {}).get('response_time_ms', {})
            
            if response_time_ms > thresholds.get('critical', 5000):
                return True
            elif response_time_ms > thresholds.get('high', 1000):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao verificar se endpoint está lento: {e}")
            return False
    
    def _create_timeout_metrics(self, endpoint: str, method: str) -> PerformanceMetrics:
        """Cria métricas para timeout."""
        return PerformanceMetrics(
            endpoint=endpoint,
            method=method,
            response_time_ms=30000,  # 30s timeout
            status_code=408,
            payload_size_bytes=0,
            timestamp=datetime.utcnow(),
            cpu_usage_percent=0.0,
            memory_usage_mb=0.0,
            is_slow=True,
            trace_id=self.trace_id
        )
    
    def _create_error_metrics(self, endpoint: str, method: str, error: str) -> PerformanceMetrics:
        """Cria métricas para erro."""
        return PerformanceMetrics(
            endpoint=endpoint,
            method=method,
            response_time_ms=0,
            status_code=500,
            payload_size_bytes=0,
            timestamp=datetime.utcnow(),
            cpu_usage_percent=0.0,
            memory_usage_mb=0.0,
            is_slow=True,
            trace_id=self.trace_id
        )
    
    def _update_endpoint_stats(self, metrics: PerformanceMetrics):
        """Atualiza estatísticas do endpoint."""
        try:
            stats = self.endpoint_stats[metrics.endpoint]
            stats['total_requests'] += 1
            stats['total_response_time_ms'] += metrics.response_time_ms
            stats['avg_response_time_ms'] = stats['total_response_time_ms'] / stats['total_requests']
            stats['max_response_time_ms'] = max(stats['max_response_time_ms'], metrics.response_time_ms)
            stats['min_response_time_ms'] = min(stats['min_response_time_ms'], metrics.response_time_ms)
            
            if metrics.is_slow:
                stats['slow_requests_count'] += 1
            
            if metrics.status_code >= 400:
                stats['error_count'] += 1
            
            # Adiciona amostras de CPU e memória
            stats['cpu_usage_samples'].append(metrics.cpu_usage_percent)
            stats['memory_usage_samples'].append(metrics.memory_usage_mb)
            
            # Mantém apenas as últimas 100 amostras
            if len(stats['cpu_usage_samples']) > 100:
                stats['cpu_usage_samples'] = stats['cpu_usage_samples'][-100:]
            if len(stats['memory_usage_samples']) > 100:
                stats['memory_usage_samples'] = stats['memory_usage_samples'][-100:]
                
        except Exception as e:
            logger.error(f"Erro ao atualizar estatísticas: {e}")
    
    def _generate_optimization_recommendations(self, metrics: PerformanceMetrics):
        """Gera recomendações de otimização."""
        try:
            recommendations = []
            
            # Verifica response time
            if metrics.response_time_ms > 1000:
                recommendations.append(self._create_response_time_recommendation(metrics))
            
            # Verifica CPU usage
            if metrics.cpu_usage_percent > 80:
                recommendations.append(self._create_cpu_recommendation(metrics))
            
            # Verifica memory usage
            if metrics.memory_usage_mb > 1000:
                recommendations.append(self._create_memory_recommendation(metrics))
            
            # Verifica status code
            if metrics.status_code >= 400:
                recommendations.append(self._create_error_recommendation(metrics))
            
            # Adiciona recomendações ao histórico
            for rec in recommendations:
                self.recommendations_history.append(rec)
                
        except Exception as e:
            logger.error(f"Erro ao gerar recomendações: {e}")
    
    def _create_response_time_recommendation(self, metrics: PerformanceMetrics) -> OptimizationRecommendation:
        """Cria recomendação para response time lento."""
        target_time = self.config.get('endpoint_targets', {}).get(metrics.endpoint, {}).get('response_time_ms', 1000)
        improvement = ((metrics.response_time_ms - target_time) / metrics.response_time_ms) * 100
        
        return OptimizationRecommendation(
            recommendation_id=f"RESP_TIME_{int(time.time())}_{hash(metrics.endpoint) % 10000}",
            endpoint=metrics.endpoint,
            issue_type="slow_response",
            severity="high" if metrics.response_time_ms > 5000 else "medium",
            current_value=metrics.response_time_ms,
            target_value=target_time,
            improvement_percent=improvement,
            description=f"Response time lento: {metrics.response_time_ms:.1f}ms > {target_time}ms",
            recommendations=[
                "Implementar cache para dados frequentemente acessados",
                "Otimizar queries de banco de dados",
                "Considerar paginação para resultados grandes",
                "Habilitar compressão de resposta"
            ],
            estimated_impact=f"Redução de {improvement:.1f}% no tempo de resposta",
            timestamp=datetime.utcnow(),
            trace_id=metrics.trace_id
        )
    
    def _create_cpu_recommendation(self, metrics: PerformanceMetrics) -> OptimizationRecommendation:
        """Cria recomendação para uso alto de CPU."""
        improvement = ((metrics.cpu_usage_percent - 50) / metrics.cpu_usage_percent) * 100
        
        return OptimizationRecommendation(
            recommendation_id=f"CPU_{int(time.time())}_{hash(metrics.endpoint) % 10000}",
            endpoint=metrics.endpoint,
            issue_type="high_cpu",
            severity="high" if metrics.cpu_usage_percent > 90 else "medium",
            current_value=metrics.cpu_usage_percent,
            target_value=50.0,
            improvement_percent=improvement,
            description=f"Uso alto de CPU: {metrics.cpu_usage_percent:.1f}%",
            recommendations=[
                "Otimizar algoritmos computacionalmente intensivos",
                "Implementar processamento assíncrono",
                "Considerar cache de resultados computados",
                "Revisar loops e operações repetitivas"
            ],
            estimated_impact=f"Redução de {improvement:.1f}% no uso de CPU",
            timestamp=datetime.utcnow(),
            trace_id=metrics.trace_id
        )
    
    def _create_memory_recommendation(self, metrics: PerformanceMetrics) -> OptimizationRecommendation:
        """Cria recomendação para uso alto de memória."""
        improvement = ((metrics.memory_usage_mb - 500) / metrics.memory_usage_mb) * 100
        
        return OptimizationRecommendation(
            recommendation_id=f"MEMORY_{int(time.time())}_{hash(metrics.endpoint) % 10000}",
            endpoint=metrics.endpoint,
            issue_type="high_memory",
            severity="high" if metrics.memory_usage_mb > 1500 else "medium",
            current_value=metrics.memory_usage_mb,
            target_value=500.0,
            improvement_percent=improvement,
            description=f"Uso alto de memória: {metrics.memory_usage_mb:.1f}MB",
            recommendations=[
                "Implementar streaming para dados grandes",
                "Otimizar estruturas de dados",
                "Considerar paginação de resultados",
                "Revisar vazamentos de memória"
            ],
            estimated_impact=f"Redução de {improvement:.1f}% no uso de memória",
            timestamp=datetime.utcnow(),
            trace_id=metrics.trace_id
        )
    
    def _create_error_recommendation(self, metrics: PerformanceMetrics) -> OptimizationRecommendation:
        """Cria recomendação para erros."""
        return OptimizationRecommendation(
            recommendation_id=f"ERROR_{int(time.time())}_{hash(metrics.endpoint) % 10000}",
            endpoint=metrics.endpoint,
            issue_type="error_rate",
            severity="critical" if metrics.status_code >= 500 else "high",
            current_value=metrics.status_code,
            target_value=200,
            improvement_percent=100.0,
            description=f"Erro HTTP {metrics.status_code}",
            recommendations=[
                "Revisar logs de erro para identificar causa raiz",
                "Implementar tratamento robusto de exceções",
                "Adicionar validação de entrada",
                "Considerar circuit breaker para dependências externas"
            ],
            estimated_impact="Redução de 100% na taxa de erro",
            timestamp=datetime.utcnow(),
            trace_id=metrics.trace_id
        )
    
    def run_performance_tests(self, endpoints: List[str] = None) -> List[PerformanceMetrics]:
        """
        Executa testes de performance em endpoints.
        
        Args:
            endpoints: Lista de endpoints para testar
            
        Returns:
            Lista de métricas de performance
        """
        if endpoints is None:
            endpoints = list(self.config.get('endpoint_targets', {}).keys())
        
        logger.info(f"Iniciando testes de performance para {len(endpoints)} endpoints")
        
        results = []
        
        # Executa testes em paralelo
        with ThreadPoolExecutor(max_workers=min(len(endpoints), 5)) as executor:
            futures = []
            
            for endpoint in endpoints:
                method = "POST" if endpoint in ["/api/generate-articles", "/generate"] else "GET"
                payload = {"test": "data"} if method == "POST" else None
                
                future = executor.submit(self.test_endpoint_performance, endpoint, method, payload)
                futures.append(future)
            
            # Coleta resultados
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Teste concluído: {result.endpoint} - {result.response_time_ms:.1f}ms")
                except Exception as e:
                    logger.error(f"Erro no teste: {e}")
        
        return results
    
    def get_endpoint_statistics(self, endpoint: str = None) -> Dict:
        """
        Obtém estatísticas de endpoints.
        
        Args:
            endpoint: Endpoint específico ou None para todos
            
        Returns:
            Estatísticas dos endpoints
        """
        try:
            if endpoint:
                return self.endpoint_stats.get(endpoint, {})
            else:
                return dict(self.endpoint_stats)
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            return {}
    
    def get_slow_endpoints(self, hours: int = 24) -> List[PerformanceMetrics]:
        """
        Obtém endpoints lentos das últimas horas.
        
        Args:
            hours: Número de horas para buscar
            
        Returns:
            Lista de endpoints lentos
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            return [
                metrics for metrics in self.metrics_history
                if metrics.is_slow and metrics.timestamp > cutoff_time
            ]
        except Exception as e:
            logger.error(f"Erro ao obter endpoints lentos: {e}")
            return []
    
    def generate_report(self, output_path: str = "logs/performance_optimizer_report.json") -> str:
        """
        Gera relatório de otimização de performance.
        
        Args:
            output_path: Caminho para salvar o relatório
            
        Returns:
            Caminho do relatório gerado
        """
        try:
            # Cria diretório se não existir
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Calcula métricas gerais
            total_requests = sum(stats['total_requests'] for stats in self.endpoint_stats.values())
            total_slow = sum(stats['slow_requests_count'] for stats in self.endpoint_stats.values())
            slow_rate = (total_slow / total_requests * 100) if total_requests > 0 else 0
            
            # Top endpoints problemáticos
            problematic_endpoints = sorted(
                self.endpoint_stats.items(),
                key=lambda x: x[1]['slow_requests_count'],
                reverse=True
            )[:5]
            
            report = {
                'trace_id': self.trace_id,
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'total_requests': total_requests,
                    'total_slow_requests': total_slow,
                    'slow_rate_percent': slow_rate,
                    'monitored_endpoints': len(self.endpoint_stats)
                },
                'endpoint_statistics': dict(self.endpoint_stats),
                'problematic_endpoints': [
                    {
                        'endpoint': endpoint,
                        'stats': stats
                    }
                    for endpoint, stats in problematic_endpoints
                ],
                'recent_recommendations': [
                    rec.to_dict() for rec in list(self.recommendations_history)[-10:]
                ],
                'optimization_suggestions': self._generate_optimization_suggestions()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Relatório gerado: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""
    
    def _generate_optimization_suggestions(self) -> List[str]:
        """Gera sugestões de otimização globais."""
        suggestions = []
        
        total_requests = sum(stats['total_requests'] for stats in self.endpoint_stats.values())
        total_slow = sum(stats['slow_requests_count'] for stats in self.endpoint_stats.values())
        
        if total_requests > 0:
            slow_rate = total_slow / total_requests * 100
            
            if slow_rate > 20:
                suggestions.append("Taxa de endpoints lentos alta (>20%). Revisar arquitetura geral.")
            
            if slow_rate > 10:
                suggestions.append("Implementar cache global para melhorar performance")
            
            if slow_rate > 5:
                suggestions.append("Considerar otimização de banco de dados")
        
        # Verifica endpoints específicos
        for endpoint, stats in self.endpoint_stats.items():
            if stats['total_requests'] > 0:
                slow_rate = stats['slow_requests_count'] / stats['total_requests'] * 100
                if slow_rate > 30:
                    suggestions.append(f"Endpoint {endpoint} tem alta taxa de lentidão ({slow_rate:.1f}%)")
        
        if not suggestions:
            suggestions.append("Sistema está operando com performance adequada")
        
        return suggestions

def main():
    """Função principal do script."""
    try:
        # Inicializa otimizador
        optimizer = PerformanceOptimizer()
        
        # Executa testes de performance
        print("🚀 Performance Optimizer - Executando testes")
        print("=" * 50)
        
        endpoints = [
            "/api/generate-articles",
            "/api/entrega-zip", 
            "/generate",
            "/download"
        ]
        
        results = optimizer.run_performance_tests(endpoints)
        
        # Exibe resultados
        for result in results:
            status = "⚠️ LENTO" if result.is_slow else "✅ OK"
            print(f"{status} {result.endpoint}: {result.response_time_ms:.1f}ms")
        
        # Gera relatório
        report_path = optimizer.generate_report()
        
        print(f"\n📊 Relatório gerado: {report_path}")
        print("✅ Performance Optimizer funcionando corretamente!")
        
        return 0
        
    except Exception as e:
        logger.error(f"Erro na execução do performance optimizer: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main()) 