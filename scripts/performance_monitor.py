#!/usr/bin/env python3
"""
Monitor de Performance em Tempo Real
- Monitoramento de métricas de sistema
- Análise de performance de aplicação
- Alertas automáticos de degradação
- Geração de relatórios de performance

📐 CoCoT: Baseado em boas práticas de monitoramento de performance
🌲 ToT: Múltiplas estratégias de monitoramento implementadas
♻️ ReAct: Simulado para diferentes cenários de degradação

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T16:00:00Z
**Tracing ID:** PERFORMANCE_MONITOR_md1ppfhs
**Origem:** Necessidade de monitoramento contínuo de performance
"""

import os
import sys
import time
import json
import psutil
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import argparse
import signal
from pathlib import Path

@dataclass
class PerformanceMetrics:
    """Métricas de performance coletadas"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_usage_percent: float
    network_io_bytes: int
    response_time_ms: float
    status_code: int
    error_rate: float
    throughput_rps: float
    active_connections: int
    load_average: float

@dataclass
class AlertConfig:
    """Configuração de alertas"""
    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0
    disk_threshold: float = 90.0
    response_time_threshold: float = 3000.0
    error_rate_threshold: float = 5.0
    throughput_threshold: float = 10.0

class PerformanceMonitor:
    """Monitor de performance em tempo real"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get('base_url', 'http://localhost:5000')
        self.interval = config.get('interval', 5)  # segundos
        self.duration = config.get('duration', 3600)  # 1 hora
        self.alert_config = AlertConfig(**config.get('alerts', {}))
        
        self.metrics: List[PerformanceMetrics] = []
        self.alerts: List[Dict[str, Any]] = []
        self.running = False
        self.start_time = None
        
        # Configurar handlers de sinal
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handler para sinais de interrupção"""
        print(f"\n🛑 Recebido sinal {signum}. Encerrando monitoramento...")
        self.stop()
        sys.exit(0)
        
    def start(self):
        """Iniciar monitoramento"""
        print("🚀 Iniciando Monitor de Performance...")
        print(f"📐 CoCoT: Monitoramento baseado em boas práticas")
        print(f"🌲 ToT: Múltiplas estratégias de análise")
        print(f"♻️ ReAct: Simulado para diferentes cenários")
        print()
        
        self.running = True
        self.start_time = datetime.now()
        
        # Verificar conectividade
        if not self.check_connectivity():
            print("❌ Não foi possível conectar com a aplicação")
            return
            
        print(f"✅ Conectado com {self.base_url}")
        print(f"⏱️ Intervalo de monitoramento: {self.interval}s")
        print(f"⏰ Duração: {self.duration}s")
        print()
        
        # Iniciar thread de monitoramento
        monitor_thread = threading.Thread(target=self.monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            # Aguardar conclusão ou interrupção
            while self.running and (datetime.now() - self.start_time).seconds < self.duration:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Interrupção manual")
        finally:
            self.stop()
            
    def stop(self):
        """Parar monitoramento"""
        self.running = False
        self.generate_report()
        
    def check_connectivity(self) -> bool:
        """Verificar conectividade com a aplicação"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
            
    def monitor_loop(self):
        """Loop principal de monitoramento"""
        while self.running:
            try:
                # Coletar métricas
                metrics = self.collect_metrics()
                self.metrics.append(metrics)
                
                # Verificar alertas
                alerts = self.check_alerts(metrics)
                if alerts:
                    self.alerts.extend(alerts)
                    for alert in alerts:
                        print(f"🚨 {alert['type']}: {alert['message']}")
                
                # Aguardar próximo ciclo
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"❌ Erro no monitoramento: {e}")
                time.sleep(self.interval)
                
    def collect_metrics(self) -> PerformanceMetrics:
        """Coletar métricas do sistema e aplicação"""
        # Métricas do sistema
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network_io = psutil.net_io_counters()
        
        # Métricas de carga (Linux)
        try:
            load_avg = os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0
        except:
            load_avg = 0.0
            
        # Métricas da aplicação
        response_time, status_code, error_rate, throughput, connections = self.measure_application_metrics()
        
        return PerformanceMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used_mb=memory.used / (1024 * 1024),
            disk_usage_percent=disk.percent,
            network_io_bytes=network_io.bytes_sent + network_io.bytes_recv,
            response_time_ms=response_time,
            status_code=status_code,
            error_rate=error_rate,
            throughput_rps=throughput,
            active_connections=connections,
            load_average=load_avg
        )
        
    def measure_application_metrics(self) -> tuple:
        """Medir métricas da aplicação"""
        response_time = 0.0
        status_code = 0
        error_rate = 0.0
        throughput = 0.0
        connections = 0
        
        try:
            # Teste de resposta da aplicação
            start_time = time.time()
            response = requests.get(f"{self.base_url}/health", timeout=10)
            response_time = (time.time() - start_time) * 1000
            status_code = response.status_code
            
            # Simular cálculo de throughput (baseado em métricas históricas)
            if len(self.metrics) > 0:
                recent_metrics = self.metrics[-10:]  # Últimas 10 medições
                throughput = len(recent_metrics) / (self.interval * len(recent_metrics))
                
            # Simular cálculo de conexões ativas
            connections = len(psutil.net_connections()) if hasattr(psutil, 'net_connections') else 0
            
        except requests.exceptions.RequestException as e:
            response_time = 10000.0  # Timeout
            status_code = 0
            error_rate = 100.0
            
        return response_time, status_code, error_rate, throughput, connections
        
    def check_alerts(self, metrics: PerformanceMetrics) -> List[Dict[str, Any]]:
        """Verificar alertas baseados nas métricas"""
        alerts = []
        
        # Alerta de CPU
        if metrics.cpu_percent > self.alert_config.cpu_threshold:
            alerts.append({
                'type': 'CPU_HIGH',
                'message': f'CPU usage: {metrics.cpu_percent:.1f}% > {self.alert_config.cpu_threshold}%',
                'severity': 'warning' if metrics.cpu_percent < 90 else 'critical',
                'timestamp': metrics.timestamp
            })
            
        # Alerta de memória
        if metrics.memory_percent > self.alert_config.memory_threshold:
            alerts.append({
                'type': 'MEMORY_HIGH',
                'message': f'Memory usage: {metrics.memory_percent:.1f}% > {self.alert_config.memory_threshold}%',
                'severity': 'warning' if metrics.memory_percent < 95 else 'critical',
                'timestamp': metrics.timestamp
            })
            
        # Alerta de disco
        if metrics.disk_usage_percent > self.alert_config.disk_threshold:
            alerts.append({
                'type': 'DISK_HIGH',
                'message': f'Disk usage: {metrics.disk_usage_percent:.1f}% > {self.alert_config.disk_threshold}%',
                'severity': 'warning' if metrics.disk_usage_percent < 95 else 'critical',
                'timestamp': metrics.timestamp
            })
            
        # Alerta de tempo de resposta
        if metrics.response_time_ms > self.alert_config.response_time_threshold:
            alerts.append({
                'type': 'RESPONSE_TIME_HIGH',
                'message': f'Response time: {metrics.response_time_ms:.1f}ms > {self.alert_config.response_time_threshold}ms',
                'severity': 'warning' if metrics.response_time_ms < 10000 else 'critical',
                'timestamp': metrics.timestamp
            })
            
        # Alerta de taxa de erro
        if metrics.error_rate > self.alert_config.error_rate_threshold:
            alerts.append({
                'type': 'ERROR_RATE_HIGH',
                'message': f'Error rate: {metrics.error_rate:.1f}% > {self.alert_config.error_rate_threshold}%',
                'severity': 'warning' if metrics.error_rate < 20 else 'critical',
                'timestamp': metrics.timestamp
            })
            
        # Alerta de throughput baixo
        if metrics.throughput_rps < self.alert_config.throughput_threshold:
            alerts.append({
                'type': 'THROUGHPUT_LOW',
                'message': f'Throughput: {metrics.throughput_rps:.1f} req/s < {self.alert_config.throughput_threshold} req/s',
                'severity': 'warning',
                'timestamp': metrics.timestamp
            })
            
        return alerts
        
    def generate_report(self):
        """Gerar relatório de performance"""
        if not self.metrics:
            print("❌ Nenhuma métrica coletada")
            return
            
        print("\n📊 Gerando relatório de performance...")
        
        # Calcular estatísticas
        stats = self.calculate_statistics()
        
        # Gerar relatório
        report = {
            'summary': {
                'monitoring_duration': (datetime.now() - self.start_time).total_seconds(),
                'total_measurements': len(self.metrics),
                'total_alerts': len(self.alerts),
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat()
            },
            'statistics': stats,
            'alerts': self.alerts,
            'recommendations': self.generate_recommendations(stats)
        }
        
        # Salvar relatório
        report_dir = Path('test-results/performance')
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_path = report_dir / f'performance-monitor-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        print(f"📄 Relatório salvo em: {report_path}")
        
        # Mostrar resumo
        self.show_summary(stats)
        
    def calculate_statistics(self) -> Dict[str, Any]:
        """Calcular estatísticas das métricas"""
        if not self.metrics:
            return {}
            
        # Extrair valores
        cpu_values = [m.cpu_percent for m in self.metrics]
        memory_values = [m.memory_percent for m in self.metrics]
        response_times = [m.response_time_ms for m in self.metrics]
        error_rates = [m.error_rate for m in self.metrics]
        throughput_values = [m.throughput_rps for m in self.metrics]
        
        return {
            'cpu': {
                'average': sum(cpu_values) / len(cpu_values),
                'max': max(cpu_values),
                'min': min(cpu_values),
                'p95': self.percentile(cpu_values, 95)
            },
            'memory': {
                'average': sum(memory_values) / len(memory_values),
                'max': max(memory_values),
                'min': min(memory_values),
                'p95': self.percentile(memory_values, 95)
            },
            'response_time': {
                'average': sum(response_times) / len(response_times),
                'max': max(response_times),
                'min': min(response_times),
                'p95': self.percentile(response_times, 95)
            },
            'error_rate': {
                'average': sum(error_rates) / len(error_rates),
                'max': max(error_rates),
                'min': min(error_rates)
            },
            'throughput': {
                'average': sum(throughput_values) / len(throughput_values),
                'max': max(throughput_values),
                'min': min(throughput_values)
            }
        }
        
    def percentile(self, values: List[float], p: float) -> float:
        """Calcular percentil"""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        index = int((p / 100) * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]
        
    def generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Gerar recomendações baseadas nas estatísticas"""
        recommendations = []
        
        if 'cpu' in stats:
            if stats['cpu']['average'] > 70:
                recommendations.append('⚠️ CPU usage alto - considere otimizar processos ou escalar recursos')
            if stats['cpu']['p95'] > 90:
                recommendations.append('🚨 CPU usage crítico no p95 - ação imediata necessária')
                
        if 'memory' in stats:
            if stats['memory']['average'] > 80:
                recommendations.append('⚠️ Memory usage alto - verifique vazamentos de memória')
            if stats['memory']['p95'] > 95:
                recommendations.append('🚨 Memory usage crítico no p95 - investigação urgente')
                
        if 'response_time' in stats:
            if stats['response_time']['average'] > 2000:
                recommendations.append('⚠️ Tempo de resposta alto - otimize queries ou implemente cache')
            if stats['response_time']['p95'] > 5000:
                recommendations.append('🚨 Tempo de resposta crítico no p95 - otimização urgente')
                
        if 'error_rate' in stats:
            if stats['error_rate']['average'] > 2:
                recommendations.append('⚠️ Taxa de erro elevada - investigue logs de erro')
            if stats['error_rate']['max'] > 10:
                recommendations.append('🚨 Picos de erro detectados - análise de causa raiz necessária')
                
        if not recommendations:
            recommendations.append('✅ Performance dentro dos parâmetros aceitáveis')
            
        return recommendations
        
    def show_summary(self, stats: Dict[str, Any]):
        """Mostrar resumo das estatísticas"""
        print("\n📊 RESUMO DO MONITORAMENTO")
        print("=" * 50)
        
        if 'cpu' in stats:
            print(f"CPU: {stats['cpu']['average']:.1f}% (médio) | {stats['cpu']['max']:.1f}% (máx) | {stats['cpu']['p95']:.1f}% (p95)")
            
        if 'memory' in stats:
            print(f"Memory: {stats['memory']['average']:.1f}% (médio) | {stats['memory']['max']:.1f}% (máx) | {stats['memory']['p95']:.1f}% (p95)")
            
        if 'response_time' in stats:
            print(f"Response Time: {stats['response_time']['average']:.1f}ms (médio) | {stats['response_time']['max']:.1f}ms (máx) | {stats['response_time']['p95']:.1f}ms (p95)")
            
        if 'error_rate' in stats:
            print(f"Error Rate: {stats['error_rate']['average']:.1f}% (médio) | {stats['error_rate']['max']:.1f}% (máx)")
            
        if 'throughput' in stats:
            print(f"Throughput: {stats['throughput']['average']:.1f} req/s (médio) | {stats['throughput']['max']:.1f} req/s (máx)")
            
        print(f"\n🚨 Alertas: {len(self.alerts)}")
        print(f"⏱️ Duração: {(datetime.now() - self.start_time).total_seconds():.0f}s")
        print(f"📈 Medições: {len(self.metrics)}")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Monitor de Performance em Tempo Real")
    parser.add_argument("--url", default="http://localhost:5000", help="URL da aplicação")
    parser.add_argument("--interval", type=int, default=5, help="Intervalo de monitoramento (segundos)")
    parser.add_argument("--duration", type=int, default=3600, help="Duração do monitoramento (segundos)")
    parser.add_argument("--cpu-threshold", type=float, default=80.0, help="Threshold de CPU (%)")
    parser.add_argument("--memory-threshold", type=float, default=85.0, help="Threshold de memória (%)")
    parser.add_argument("--disk-threshold", type=float, default=90.0, help="Threshold de disco (%)")
    parser.add_argument("--response-time-threshold", type=float, default=3000.0, help="Threshold de tempo de resposta (ms)")
    parser.add_argument("--error-rate-threshold", type=float, default=5.0, help="Threshold de taxa de erro (%)")
    parser.add_argument("--throughput-threshold", type=float, default=10.0, help="Threshold de throughput (req/s)")
    
    args = parser.parse_args()
    
    # Configuração
    config = {
        'base_url': args.url,
        'interval': args.interval,
        'duration': args.duration,
        'alerts': {
            'cpu_threshold': args.cpu_threshold,
            'memory_threshold': args.memory_threshold,
            'disk_threshold': args.disk_threshold,
            'response_time_threshold': args.response_time_threshold,
            'error_rate_threshold': args.error_rate_threshold,
            'throughput_threshold': args.throughput_threshold
        }
    }
    
    # Iniciar monitoramento
    monitor = PerformanceMonitor(config)
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\n👋 Encerrando...")
    finally:
        monitor.generate_report()


if __name__ == "__main__":
    main() 