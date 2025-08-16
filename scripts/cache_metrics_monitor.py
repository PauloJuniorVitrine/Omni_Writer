#!/usr/bin/env python3
"""
Monitor de Métricas de Cache para Omni Writer.
Monitora hit/miss ratio, performance e saúde do cache Redis.
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.intelligent_cache import IntelligentCache
from shared.config import REDIS_URL

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cache_monitor')

class CacheMetricsMonitor:
    """
    Monitor de métricas de cache em tempo real.
    
    Funcionalidades:
    - Monitoramento contínuo de hit/miss ratio
    - Alertas de performance
    - Relatórios de saúde do cache
    - Análise de tendências
    """
    
    def __init__(self, redis_url: Optional[str] = None, interval: int = 30):
        self.redis_url = redis_url or REDIS_URL
        self.interval = interval
        self.cache = IntelligentCache(redis_url=self.redis_url, enable_metrics=True)
        self.history = []
        self.alerts = []
        
        # Thresholds para alertas
        self.thresholds = {
            'hit_ratio_min': 70.0,  # Hit ratio mínimo
            'error_rate_max': 5.0,  # Taxa de erro máxima
            'response_time_max': 100,  # Tempo de resposta máximo (ms)
            'cache_size_max': 1000  # Tamanho máximo do cache local
        }
    
    def collect_metrics(self) -> Dict:
        """
        Coleta métricas atuais do cache.
        
        Returns:
            Dicionário com métricas coletadas
        """
        start_time = time.time()
        
        try:
            # Coleta métricas básicas
            metrics = self.cache.get_metrics()
            
            # Adiciona timestamp
            metrics['timestamp'] = datetime.now().isoformat()
            metrics['response_time_ms'] = round((time.time() - start_time) * 1000, 2)
            
            # Coleta informações adicionais
            cache_info = self.cache.get_cache_info()
            metrics.update(cache_info)
            
            # Calcula taxas
            total_requests = metrics.get('total_requests', 0)
            if total_requests > 0:
                metrics['error_rate'] = (metrics.get('errors', 0) / total_requests) * 100
            else:
                metrics['error_rate'] = 0.0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Erro ao coletar métricas: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'response_time_ms': round((time.time() - start_time) * 1000, 2)
            }
    
    def check_alerts(self, metrics: Dict) -> List[Dict]:
        """
        Verifica se há alertas baseados nas métricas.
        
        Args:
            metrics: Métricas coletadas
        
        Returns:
            Lista de alertas
        """
        alerts = []
        
        # Verifica hit ratio
        hit_ratio = metrics.get('hit_ratio', 0)
        if hit_ratio < self.thresholds['hit_ratio_min']:
            alerts.append({
                'type': 'warning',
                'message': f'Hit ratio baixo: {hit_ratio}% (mínimo: {self.thresholds["hit_ratio_min"]}%)',
                'metric': 'hit_ratio',
                'value': hit_ratio,
                'threshold': self.thresholds['hit_ratio_min']
            })
        
        # Verifica taxa de erro
        error_rate = metrics.get('error_rate', 0)
        if error_rate > self.thresholds['error_rate_max']:
            alerts.append({
                'type': 'error',
                'message': f'Taxa de erro alta: {error_rate}% (máximo: {self.thresholds["error_rate_max"]}%)',
                'metric': 'error_rate',
                'value': error_rate,
                'threshold': self.thresholds['error_rate_max']
            })
        
        # Verifica tempo de resposta
        response_time = metrics.get('response_time_ms', 0)
        if response_time > self.thresholds['response_time_max']:
            alerts.append({
                'type': 'warning',
                'message': f'Tempo de resposta alto: {response_time}ms (máximo: {self.thresholds["response_time_max"]}ms)',
                'metric': 'response_time',
                'value': response_time,
                'threshold': self.thresholds['response_time_max']
            })
        
        # Verifica tamanho do cache local
        local_cache_size = metrics.get('local_cache_size', 0)
        if local_cache_size > self.thresholds['cache_size_max']:
            alerts.append({
                'type': 'info',
                'message': f'Cache local grande: {local_cache_size} itens (máximo: {self.thresholds["cache_size_max"]})',
                'metric': 'local_cache_size',
                'value': local_cache_size,
                'threshold': self.thresholds['cache_size_max']
            })
        
        # Verifica disponibilidade do Redis
        if not metrics.get('redis_available', False):
            alerts.append({
                'type': 'error',
                'message': 'Redis não disponível - usando cache local',
                'metric': 'redis_available',
                'value': False,
                'threshold': True
            })
        
        return alerts
    
    def print_metrics(self, metrics: Dict, alerts: List[Dict]):
        """
        Imprime métricas formatadas no console.
        
        Args:
            metrics: Métricas coletadas
            alerts: Alertas gerados
        """
        print("\n" + "="*60)
        print(f"📊 MÉTRICAS DE CACHE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Métricas principais
        print(f"🎯 Hit Ratio: {metrics.get('hit_ratio', 0)}%")
        print(f"📈 Total Requests: {metrics.get('total_requests', 0)}")
        print(f"✅ Hits: {metrics.get('hits', 0)}")
        print(f"❌ Misses: {metrics.get('misses', 0)}")
        print(f"💾 Sets: {metrics.get('sets', 0)}")
        print(f"🗑️  Deletes: {metrics.get('deletes', 0)}")
        print(f"⚠️  Errors: {metrics.get('errors', 0)}")
        print(f"📊 Error Rate: {metrics.get('error_rate', 0):.2f}%")
        print(f"⏱️  Response Time: {metrics.get('response_time_ms', 0)}ms")
        
        # Status do Redis
        redis_status = "🟢 Disponível" if metrics.get('redis_available', False) else "🔴 Indisponível"
        print(f"🔴 Redis: {redis_status}")
        
        # Cache local
        print(f"💻 Cache Local: {metrics.get('local_cache_size', 0)} itens")
        
        # Alertas
        if alerts:
            print("\n🚨 ALERTAS:")
            for alert in alerts:
                icon = "⚠️" if alert['type'] == 'warning' else "❌" if alert['type'] == 'error' else "ℹ️"
                print(f"  {icon} {alert['message']}")
        else:
            print("\n✅ Nenhum alerta detectado")
        
        print("="*60)
    
    def save_metrics(self, metrics: Dict, filename: Optional[str] = None):
        """
        Salva métricas em arquivo JSON.
        
        Args:
            metrics: Métricas coletadas
            filename: Nome do arquivo (opcional)
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cache_metrics_{timestamp}.json"
        
        filepath = os.path.join('logs', filename)
        
        try:
            os.makedirs('logs', exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Métricas salvas em: {filepath}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar métricas: {e}")
    
    def generate_report(self, duration_minutes: int = 60) -> Dict:
        """
        Gera relatório de métricas do período.
        
        Args:
            duration_minutes: Duração do período em minutos
        
        Returns:
            Relatório consolidado
        """
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        
        # Filtra histórico
        recent_metrics = [
            m for m in self.history 
            if datetime.fromisoformat(m['timestamp']) > cutoff_time
        ]
        
        if not recent_metrics:
            return {'error': 'Nenhuma métrica disponível para o período'}
        
        # Calcula estatísticas
        hit_ratios = [m.get('hit_ratio', 0) for m in recent_metrics]
        response_times = [m.get('response_time_ms', 0) for m in recent_metrics]
        error_rates = [m.get('error_rate', 0) for m in recent_metrics]
        
        report = {
            'period': f"Últimos {duration_minutes} minutos",
            'total_samples': len(recent_metrics),
            'hit_ratio': {
                'avg': round(sum(hit_ratios) / len(hit_ratios), 2),
                'min': min(hit_ratios),
                'max': max(hit_ratios)
            },
            'response_time': {
                'avg': round(sum(response_times) / len(response_times), 2),
                'min': min(response_times),
                'max': max(response_times)
            },
            'error_rate': {
                'avg': round(sum(error_rates) / len(error_rates), 2),
                'min': min(error_rates),
                'max': max(error_rates)
            },
            'redis_availability': {
                'available': sum(1 for m in recent_metrics if m.get('redis_available', False)),
                'total': len(recent_metrics),
                'percentage': round(
                    sum(1 for m in recent_metrics if m.get('redis_available', False)) / len(recent_metrics) * 100, 2
                )
            }
        }
        
        return report
    
    def monitor_continuous(self, save_metrics: bool = False, report_interval: int = 10):
        """
        Monitoramento contínuo de métricas.
        
        Args:
            save_metrics: Se deve salvar métricas em arquivo
            report_interval: Intervalo para relatórios (em ciclos)
        """
        logger.info(f"Iniciando monitoramento contínuo (intervalo: {self.interval}s)")
        
        cycle_count = 0
        
        try:
            while True:
                cycle_count += 1
                
                # Coleta métricas
                metrics = self.collect_metrics()
                self.history.append(metrics)
                
                # Verifica alertas
                alerts = self.check_alerts(metrics)
                self.alerts.extend(alerts)
                
                # Imprime métricas
                self.print_metrics(metrics, alerts)
                
                # Salva métricas se solicitado
                if save_metrics and cycle_count % 10 == 0:  # A cada 10 ciclos
                    self.save_metrics(metrics)
                
                # Gera relatório periódico
                if cycle_count % report_interval == 0:
                    report = self.generate_report()
                    print("\n📋 RELATÓRIO PERIÓDICO:")
                    print(json.dumps(report, indent=2, ensure_ascii=False))
                
                # Limpa histórico antigo (mantém últimas 1000 entradas)
                if len(self.history) > 1000:
                    self.history = self.history[-1000:]
                
                # Aguarda próximo ciclo
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            logger.info("Monitoramento interrompido pelo usuário")
            
            # Gera relatório final
            final_report = self.generate_report()
            print("\n📋 RELATÓRIO FINAL:")
            print(json.dumps(final_report, indent=2, ensure_ascii=False))
    
    def run_single_check(self):
        """
        Executa verificação única de métricas.
        """
        logger.info("Executando verificação única de métricas")
        
        metrics = self.collect_metrics()
        alerts = self.check_alerts(metrics)
        
        self.print_metrics(metrics, alerts)
        
        return metrics, alerts

def main():
    """Função principal do script."""
    parser = argparse.ArgumentParser(description='Monitor de Métricas de Cache')
    parser.add_argument('--redis-url', help='URL do Redis')
    parser.add_argument('--interval', type=int, default=30, help='Intervalo de monitoramento (segundos)')
    parser.add_argument('--continuous', action='store_true', help='Monitoramento contínuo')
    parser.add_argument('--save-metrics', action='store_true', help='Salvar métricas em arquivo')
    parser.add_argument('--report-interval', type=int, default=10, help='Intervalo para relatórios (ciclos)')
    parser.add_argument('--duration', type=int, default=60, help='Duração para relatórios (minutos)')
    
    args = parser.parse_args()
    
    # Cria monitor
    monitor = CacheMetricsMonitor(
        redis_url=args.redis_url,
        interval=args.interval
    )
    
    if args.continuous:
        # Monitoramento contínuo
        monitor.monitor_continuous(
            save_metrics=args.save_metrics,
            report_interval=args.report_interval
        )
    else:
        # Verificação única
        metrics, alerts = monitor.run_single_check()
        
        # Gera relatório se solicitado
        if args.duration > 0:
            report = monitor.generate_report(args.duration)
            print("\n📋 RELATÓRIO:")
            print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main() 