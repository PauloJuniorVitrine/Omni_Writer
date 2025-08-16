#!/usr/bin/env python3
"""
📊 PAYLOAD AUDITOR - Sistema de Auditoria de Payloads Excessivos
Tracing ID: PAYLOAD_AUDIT_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Monitorar e alertar sobre payloads excessivos (>500KB) para prevenir
degradação de performance e timeouts.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import gzip
from collections import defaultdict, deque

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/payload_auditor.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('payload_auditor')

@dataclass
class PayloadMetrics:
    """Métricas de payload para análise e alertas."""
    endpoint: str
    method: str
    payload_size_bytes: int
    payload_size_kb: float
    compression_ratio: float
    timestamp: datetime
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    processing_time_ms: Optional[float] = None
    is_excessive: bool = False
    
    def __post_init__(self):
        """Calcula métricas derivadas após inicialização."""
        self.payload_size_kb = self.payload_size_bytes / 1024
        self.is_excessive = self.payload_size_kb > 500  # Threshold de 500KB

@dataclass
class PayloadAlert:
    """Estrutura para alertas de payload excessivo."""
    alert_id: str
    severity: str  # 'warning', 'critical', 'emergency'
    endpoint: str
    payload_size_kb: float
    threshold_kb: float
    timestamp: datetime
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    recommendations: Optional[List[str]] = None
    
    def __post_init__(self):
        """Inicializa recomendações padrão."""
        if self.recommendations is None:
            self.recommendations = []

class PayloadAuditor:
    """
    Sistema principal de auditoria de payloads.
    
    Funcionalidades:
    - Monitoramento automático de tamanho de payloads
    - Detecção de payloads excessivos (>500KB)
    - Geração de alertas e relatórios
    - Análise de tendências e padrões
    - Recomendações de otimização
    """
    
    def __init__(self, 
                 max_payload_kb: float = 500,
                 alert_threshold_kb: float = 400,
                 critical_threshold_kb: float = 1000,
                 max_history_size: int = 10000):
        """
        Inicializa o auditor de payloads.
        
        Args:
            max_payload_kb: Tamanho máximo permitido em KB
            alert_threshold_kb: Threshold para alertas de warning
            critical_threshold_kb: Threshold para alertas críticos
            max_history_size: Tamanho máximo do histórico em memória
        """
        self.max_payload_kb = max_payload_kb
        self.alert_threshold_kb = alert_threshold_kb
        self.critical_threshold_kb = critical_threshold_kb
        self.max_history_size = max_history_size
        
        # Histórico de payloads (usando deque para performance)
        self.payload_history: deque = deque(maxlen=max_history_size)
        
        # Métricas agregadas por endpoint
        self.endpoint_metrics: Dict[str, Dict] = defaultdict(lambda: {
            'total_requests': 0,
            'excessive_requests': 0,
            'total_payload_size': 0,
            'max_payload_size': 0,
            'avg_payload_size': 0,
            'last_alert': None
        })
        
        # Alertas gerados
        self.alerts: List[PayloadAlert] = []
        
        # Configuração de logging
        self.logger = logger
        self.logger.info(f"PayloadAuditor inicializado - Max: {max_payload_kb}KB, Alert: {alert_threshold_kb}KB")
    
    def analyze_payload(self, 
                       payload: str | bytes | dict,
                       endpoint: str,
                       method: str = "POST",
                       user_id: Optional[str] = None,
                       request_id: Optional[str] = None) -> PayloadMetrics:
        """
        Analisa um payload e retorna métricas detalhadas.
        
        Args:
            payload: Conteúdo do payload
            endpoint: Endpoint da requisição
            method: Método HTTP
            user_id: ID do usuário (opcional)
            request_id: ID da requisição (opcional)
            
        Returns:
            PayloadMetrics com análise completa
        """
        start_time = time.time()
        
        # Converte payload para bytes se necessário
        if isinstance(payload, dict):
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        elif isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = payload
        
        # Calcula tamanho e compressão
        payload_size = len(payload_bytes)
        compressed_size = len(gzip.compress(payload_bytes))
        compression_ratio = compressed_size / payload_size if payload_size > 0 else 0
        
        # Cria métricas
        metrics = PayloadMetrics(
            endpoint=endpoint,
            method=method,
            payload_size_bytes=payload_size,
            payload_size_kb=payload_size / 1024,
            compression_ratio=compression_ratio,
            timestamp=datetime.now(),
            user_id=user_id,
            request_id=request_id,
            processing_time_ms=(time.time() - start_time) * 1000
        )
        
        # Atualiza histórico e métricas
        self._update_metrics(metrics)
        
        # Gera alertas se necessário
        if metrics.is_excessive:
            self._generate_alert(metrics)
        
        self.logger.info(f"Payload analisado: {endpoint} - {metrics.payload_size_kb:.2f}KB "
                        f"({'EXCESSIVO' if metrics.is_excessive else 'OK'})")
        
        return metrics
    
    def _update_metrics(self, metrics: PayloadMetrics) -> None:
        """Atualiza métricas agregadas por endpoint."""
        self.payload_history.append(metrics)
        
        endpoint_data = self.endpoint_metrics[metrics.endpoint]
        endpoint_data['total_requests'] += 1
        endpoint_data['total_payload_size'] += metrics.payload_size_bytes
        
        if metrics.is_excessive:
            endpoint_data['excessive_requests'] += 1
        
        if metrics.payload_size_bytes > endpoint_data['max_payload_size']:
            endpoint_data['max_payload_size'] = metrics.payload_size_bytes
        
        # Calcula média móvel
        endpoint_data['avg_payload_size'] = (
            endpoint_data['total_payload_size'] / endpoint_data['total_requests']
        )
    
    def _generate_alert(self, metrics: PayloadMetrics) -> None:
        """Gera alerta para payload excessivo."""
        # Determina severidade
        if metrics.payload_size_kb >= self.critical_threshold_kb:
            severity = 'critical'
        elif metrics.payload_size_kb >= self.alert_threshold_kb:
            severity = 'warning'
        else:
            severity = 'info'
        
        # Gera recomendações
        recommendations = self._generate_recommendations(metrics)
        
        # Cria alerta
        alert = PayloadAlert(
            alert_id=f"PAYLOAD_{int(time.time())}_{hash(metrics.endpoint) % 10000}",
            severity=severity,
            endpoint=metrics.endpoint,
            payload_size_kb=metrics.payload_size_kb,
            threshold_kb=self.max_payload_kb,
            timestamp=metrics.timestamp,
            user_id=metrics.user_id,
            request_id=metrics.request_id,
            recommendations=recommendations
        )
        
        self.alerts.append(alert)
        self.endpoint_metrics[metrics.endpoint]['last_alert'] = alert.timestamp
        
        # Log do alerta
        self.logger.warning(f"ALERTA {severity.upper()}: Payload excessivo em {metrics.endpoint} - "
                           f"{metrics.payload_size_kb:.2f}KB (limite: {self.max_payload_kb}KB)")
        
        # Log detalhado para alertas críticos
        if severity == 'critical':
            self.logger.critical(f"PAYLOAD CRÍTICO: {json.dumps(asdict(alert), default=str)}")
    
    def _generate_recommendations(self, metrics: PayloadMetrics) -> List[str]:
        """Gera recomendações específicas para otimização."""
        recommendations = []
        
        if metrics.compression_ratio > 0.8:
            recommendations.append("Considerar compressão adicional - ratio atual muito alto")
        
        if metrics.payload_size_kb > 1000:
            recommendations.append("Implementar paginação ou streaming para payloads grandes")
        
        if metrics.endpoint in ['/api/generate-articles', '/api/upload-content']:
            recommendations.append("Considerar upload em chunks para conteúdo grande")
        
        if not recommendations:
            recommendations.append("Revisar estrutura de dados para reduzir tamanho")
        
        return recommendations
    
    def get_excessive_payloads_report(self, 
                                    hours: int = 24,
                                    min_size_kb: float = 100) -> Dict:
        """
        Gera relatório de payloads excessivos.
        
        Args:
            hours: Período de análise em horas
            min_size_kb: Tamanho mínimo para incluir no relatório
            
        Returns:
            Dicionário com relatório estruturado
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        excessive_payloads = [
            p for p in self.payload_history
            if p.timestamp >= cutoff_time and p.payload_size_kb >= min_size_kb
        ]
        
        # Agrupa por endpoint
        by_endpoint = defaultdict(list)
        for payload in excessive_payloads:
            by_endpoint[payload.endpoint].append(payload)
        
        # Calcula estatísticas
        total_excessive = len(excessive_payloads)
        total_size = sum(p.payload_size_bytes for p in excessive_payloads)
        avg_size = total_size / total_excessive if total_excessive > 0 else 0
        
        report = {
            'period_hours': hours,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_excessive_payloads': total_excessive,
                'total_size_bytes': total_size,
                'total_size_kb': total_size / 1024,
                'avg_size_kb': avg_size / 1024,
                'endpoints_affected': len(by_endpoint)
            },
            'by_endpoint': {},
            'top_offenders': []
        }
        
        # Detalhes por endpoint
        for endpoint, payloads in by_endpoint.items():
            endpoint_size = sum(p.payload_size_bytes for p in payloads)
            report['by_endpoint'][endpoint] = {
                'count': len(payloads),
                'total_size_kb': endpoint_size / 1024,
                'avg_size_kb': (endpoint_size / len(payloads)) / 1024,
                'max_size_kb': max(p.payload_size_kb for p in payloads),
                'recent_alerts': len([p for p in payloads if p.is_excessive])
            }
        
        # Top offenders (maiores payloads)
        top_offenders = sorted(
            excessive_payloads,
            key=lambda x: x.payload_size_kb,
            reverse=True
        )[:10]
        
        report['top_offenders'] = [
            {
                'endpoint': p.endpoint,
                'size_kb': p.payload_size_kb,
                'timestamp': p.timestamp.isoformat(),
                'user_id': p.user_id
            }
            for p in top_offenders
        ]
        
        return report
    
    def get_performance_impact_analysis(self) -> Dict:
        """Analisa impacto de payloads excessivos na performance."""
        if not self.payload_history:
            return {'error': 'Nenhum dado disponível para análise'}
        
        # Calcula métricas de performance
        excessive_payloads = [p for p in self.payload_history if p.is_excessive]
        normal_payloads = [p for p in self.payload_history if not p.is_excessive]
        
        analysis = {
            'total_requests': len(self.payload_history),
            'excessive_requests': len(excessive_payloads),
            'excessive_percentage': (len(excessive_payloads) / len(self.payload_history)) * 100,
            'performance_impact': {}
        }
        
        if excessive_payloads and normal_payloads:
            avg_excessive_time = sum(p.processing_time_ms or 0 for p in excessive_payloads) / len(excessive_payloads)
            avg_normal_time = sum(p.processing_time_ms or 0 for p in normal_payloads) / len(normal_payloads)
            
            analysis['performance_impact'] = {
                'avg_excessive_processing_ms': avg_excessive_time,
                'avg_normal_processing_ms': avg_normal_time,
                'performance_degradation_factor': avg_excessive_time / avg_normal_time if avg_normal_time > 0 else 0,
                'estimated_timeout_risk': len([p for p in excessive_payloads if p.payload_size_kb > 1000])
            }
        
        return analysis
    
    def export_metrics(self, format: str = 'json') -> str:
        """
        Exporta métricas para análise externa.
        
        Args:
            format: Formato de exportação ('json', 'csv')
            
        Returns:
            String com dados exportados
        """
        if format == 'json':
            export_data = {
                'metadata': {
                    'exported_at': datetime.now().isoformat(),
                    'total_payloads': len(self.payload_history),
                    'max_payload_kb': self.max_payload_kb,
                    'alert_threshold_kb': self.alert_threshold_kb
                },
                'endpoint_metrics': dict(self.endpoint_metrics),
                'recent_alerts': [
                    asdict(alert) for alert in self.alerts[-100:]  # Últimos 100 alertas
                ],
                'performance_analysis': self.get_performance_impact_analysis()
            }
            return json.dumps(export_data, indent=2, default=str)
        
        elif format == 'csv':
            # Implementar exportação CSV se necessário
            return "CSV export not implemented yet"
        
        else:
            raise ValueError(f"Formato não suportado: {format}")
    
    def clear_history(self) -> None:
        """Limpa histórico de payloads (útil para testes)."""
        self.payload_history.clear()
        self.endpoint_metrics.clear()
        self.alerts.clear()
        self.logger.info("Histórico de payloads limpo")

# Instância global para uso em middleware
payload_auditor = PayloadAuditor()

def get_payload_auditor() -> PayloadAuditor:
    """Retorna instância global do auditor de payloads."""
    return payload_auditor

if __name__ == "__main__":
    # Teste básico do sistema
    auditor = PayloadAuditor()
    
    # Simula payloads de teste
    test_payloads = [
        ("/api/generate-articles", {"content": "x" * 1000000}),  # ~1MB
        ("/api/upload-content", {"data": "x" * 200000}),         # ~200KB
        ("/api/status", {"status": "ok"}),                       # ~20B
    ]
    
    for endpoint, payload in test_payloads:
        metrics = auditor.analyze_payload(payload, endpoint)
        print(f"Endpoint: {endpoint}, Size: {metrics.payload_size_kb:.2f}KB, "
              f"Excessive: {metrics.is_excessive}")
    
    # Gera relatório
    report = auditor.get_excessive_payloads_report()
    print(f"\nRelatório: {report['summary']['total_excessive_payloads']} payloads excessivos")
    
    # Exporta métricas
    export = auditor.export_metrics('json')
    print(f"\nExport: {len(export)} caracteres") 