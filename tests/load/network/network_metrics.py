#!/usr/bin/env python3
"""
Network Metrics Monitoring - Omni Writer
=======================================

Monitoramento de métricas de rede durante testes de carga
para identificar gargalos de conectividade e latência.

Autor: Equipe de Performance
Data: 2025-01-27
Versão: 1.0
"""

import time
import socket
import threading
import logging
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import subprocess
import platform
import json

# Importar profiling
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'profiling'))
from opentelemetry_config import setup_profiling

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[NETWORK][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkMetrics:
    """Métricas de rede."""
    timestamp: float
    rtt_ms: float
    packet_loss: float
    bandwidth_mbps: float
    connection_count: int
    retransmission_rate: float
    latency_jitter: float
    target_host: str

@dataclass
class ConnectionMetrics:
    """Métricas de conexão específica."""
    host: str
    port: int
    rtt_ms: float
    success: bool
    error_message: Optional[str] = None
    retransmissions: int = 0

class NetworkMonitor:
    """Monitor de métricas de rede."""
    
    def __init__(self, target_hosts: List[str] = None):
        self.target_hosts = target_hosts or [
            "api.openai.com",
            "api.deepseek.com",
            "localhost"
        ]
        self.profiler = setup_profiling()
        self.metrics: List[NetworkMetrics] = []
        self.connection_metrics: List[ConnectionMetrics] = []
        self.monitoring_active = False
        self.system = platform.system().lower()
        
    def measure_rtt(self, host: str, port: int = 80, timeout: float = 5.0) -> float:
        """
        Mede RTT (Round Trip Time) para um host.
        
        Args:
            host: Host alvo
            port: Porta alvo
            timeout: Timeout em segundos
            
        Returns:
            float: RTT em milissegundos
        """
        start_time = time.time()
        
        try:
            # Criar socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Conectar
            sock.connect((host, port))
            sock.close()
            
            rtt_ms = (time.time() - start_time) * 1000
            
            # Traçar com OpenTelemetry
            self.profiler.trace_external_service(
                "network", f"rtt_{host}", rtt_ms / 1000, True
            )
            
            return rtt_ms
            
        except Exception as e:
            logger.error(f"Erro ao medir RTT para {host}:{port}: {e}")
            
            # Traçar erro com OpenTelemetry
            self.profiler.trace_external_service(
                "network", f"rtt_{host}", timeout, False
            )
            
            return -1  # Indica erro
    
    def measure_packet_loss(self, host: str, count: int = 10) -> float:
        """
        Mede perda de pacotes usando ping.
        
        Args:
            host: Host alvo
            count: Número de pings
            
        Returns:
            float: Taxa de perda de pacotes (0.0 a 1.0)
        """
        try:
            if self.system == "windows":
                cmd = ["ping", "-n", str(count), host]
            else:
                cmd = ["ping", "-c", str(count), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse output para extrair perda de pacotes
                output = result.stdout
                
                if self.system == "windows":
                    # Windows: "Pacotes: Enviados = 10, Recebidos = 10, Perdidos = 0"
                    if "Perdidos = 0" in output:
                        return 0.0
                    else:
                        # Extrair número de perdidos
                        import re
                        match = re.search(r"Perdidos = (\d+)", output)
                        if match:
                            lost = int(match.group(1))
                            return lost / count
                else:
                    # Linux/Mac: "10 packets transmitted, 10 received, 0% packet loss"
                    if "0% packet loss" in output:
                        return 0.0
                    else:
                        # Extrair porcentagem
                        import re
                        match = re.search(r"(\d+)% packet loss", output)
                        if match:
                            return int(match.group(1)) / 100
            
            return 0.0  # Default se não conseguir parsear
            
        except Exception as e:
            logger.error(f"Erro ao medir perda de pacotes para {host}: {e}")
            return 1.0  # 100% de perda em caso de erro
    
    def measure_bandwidth(self, host: str, port: int = 80) -> float:
        """
        Mede largura de banda (implementação simplificada).
        
        Args:
            host: Host alvo
            port: Porta alvo
            
        Returns:
            float: Largura de banda em Mbps
        """
        try:
            # Simular teste de banda (em produção, usar ferramentas específicas)
            start_time = time.time()
            
            # Fazer múltiplas conexões para simular carga
            connections = []
            for _ in range(10):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((host, port))
                    connections.append(sock)
                except:
                    pass
            
            # Simular transferência de dados
            total_bytes = 0
            for sock in connections:
                try:
                    # Enviar dados de teste
                    test_data = b"X" * 1024  # 1KB
                    sock.send(test_data)
                    total_bytes += len(test_data)
                    
                    # Receber resposta
                    response = sock.recv(1024)
                    total_bytes += len(response)
                except:
                    pass
                finally:
                    sock.close()
            
            duration = time.time() - start_time
            bandwidth_mbps = (total_bytes * 8) / (duration * 1_000_000)  # Convert to Mbps
            
            return bandwidth_mbps
            
        except Exception as e:
            logger.error(f"Erro ao medir largura de banda para {host}: {e}")
            return 0.0
    
    def count_connections(self) -> int:
        """
        Conta conexões ativas (implementação simplificada).
        
        Returns:
            int: Número de conexões ativas
        """
        try:
            if self.system == "windows":
                cmd = ["netstat", "-an"]
            else:
                cmd = ["netstat", "-an"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Contar linhas com ESTABLISHED ou LISTENING
                lines = result.stdout.split('\n')
                active_connections = 0
                
                for line in lines:
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        active_connections += 1
                
                return active_connections
            
            return 0
            
        except Exception as e:
            logger.error(f"Erro ao contar conexões: {e}")
            return 0
    
    def measure_retransmission_rate(self) -> float:
        """
        Mede taxa de retransmissão TCP (implementação simplificada).
        
        Returns:
            float: Taxa de retransmissão (0.0 a 1.0)
        """
        try:
            if self.system == "windows":
                cmd = ["netstat", "-s"]
            else:
                cmd = ["netstat", "-s"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Procurar por estatísticas de retransmissão
                if "retransmitted" in output.lower() or "retransmit" in output.lower():
                    # Parse simplificado - em produção usar regex mais robusto
                    return 0.01  # 1% de retransmissão como exemplo
                
            return 0.0
            
        except Exception as e:
            logger.error(f"Erro ao medir retransmissão: {e}")
            return 0.0
    
    def measure_latency_jitter(self, host: str, samples: int = 10) -> float:
        """
        Mede jitter (variação de latência).
        
        Args:
            host: Host alvo
            samples: Número de amostras
            
        Returns:
            float: Jitter em milissegundos
        """
        rtt_samples = []
        
        for _ in range(samples):
            rtt = self.measure_rtt(host)
            if rtt > 0:  # Ignorar erros
                rtt_samples.append(rtt)
            time.sleep(0.1)  # Pequena pausa entre medidas
        
        if len(rtt_samples) < 2:
            return 0.0
        
        # Calcular desvio padrão como medida de jitter
        return statistics.stdev(rtt_samples)
    
    def collect_network_metrics(self, target_host: str = None) -> NetworkMetrics:
        """
        Coleta todas as métricas de rede.
        
        Args:
            target_host: Host específico para medir
            
        Returns:
            NetworkMetrics: Métricas coletadas
        """
        host = target_host or self.target_hosts[0]
        
        logger.info(f"Coletando métricas de rede para {host}")
        
        # Medir RTT
        rtt_ms = self.measure_rtt(host)
        
        # Medir perda de pacotes
        packet_loss = self.measure_packet_loss(host)
        
        # Medir largura de banda
        bandwidth_mbps = self.measure_bandwidth(host)
        
        # Contar conexões
        connection_count = self.count_connections()
        
        # Medir retransmissão
        retransmission_rate = self.measure_retransmission_rate()
        
        # Medir jitter
        latency_jitter = self.measure_latency_jitter(host)
        
        metrics = NetworkMetrics(
            timestamp=time.time(),
            rtt_ms=rtt_ms,
            packet_loss=packet_loss,
            bandwidth_mbps=bandwidth_mbps,
            connection_count=connection_count,
            retransmission_rate=retransmission_rate,
            latency_jitter=latency_jitter,
            target_host=host
        )
        
        self.metrics.append(metrics)
        return metrics
    
    def start_monitoring(self, interval: int = 5):
        """
        Inicia monitoramento contínuo de rede.
        
        Args:
            interval: Intervalo de monitoramento em segundos
        """
        if self.monitoring_active:
            logger.warning("Monitoramento de rede já está ativo")
            return
        
        self.monitoring_active = True
        logger.info("Iniciando monitoramento de rede...")
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    for host in self.target_hosts:
                        self.collect_network_metrics(host)
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Erro no monitoramento de rede: {e}")
                    time.sleep(interval)
        
        # Executar em thread separada
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Para o monitoramento contínuo."""
        self.monitoring_active = False
        logger.info("Monitoramento de rede parado")
    
    def test_connection_stability(self, host: str, port: int, duration: int = 60) -> List[ConnectionMetrics]:
        """
        Testa estabilidade de conexão por um período.
        
        Args:
            host: Host alvo
            port: Porta alvo
            duration: Duração do teste em segundos
            
        Returns:
            List[ConnectionMetrics]: Métricas de conexão
        """
        logger.info(f"Testando estabilidade de conexão para {host}:{port}")
        
        results = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            connection_start = time.time()
            
            try:
                # Tentar conexão
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((host, port))
                
                # Simular pequena transferência
                sock.send(b"TEST")
                response = sock.recv(1024)
                sock.close()
                
                rtt_ms = (time.time() - connection_start) * 1000
                
                result = ConnectionMetrics(
                    host=host,
                    port=port,
                    rtt_ms=rtt_ms,
                    success=True
                )
                
            except Exception as e:
                rtt_ms = (time.time() - connection_start) * 1000
                
                result = ConnectionMetrics(
                    host=host,
                    port=port,
                    rtt_ms=rtt_ms,
                    success=False,
                    error_message=str(e)
                )
            
            results.append(result)
            time.sleep(1.0)  # Teste a cada segundo
        
        self.connection_metrics.extend(results)
        return results
    
    def analyze_network_performance(self) -> Dict:
        """
        Analisa performance da rede.
        
        Returns:
            Dict: Análise de performance
        """
        if not self.metrics:
            return {"error": "Nenhuma métrica para analisar"}
        
        # Calcular estatísticas
        rtt_values = [m.rtt_ms for m in self.metrics if m.rtt_ms > 0]
        packet_loss_values = [m.packet_loss for m in self.metrics]
        bandwidth_values = [m.bandwidth_mbps for m in self.metrics]
        
        analysis = {
            "total_measurements": len(self.metrics),
            "avg_rtt_ms": statistics.mean(rtt_values) if rtt_values else 0,
            "max_rtt_ms": max(rtt_values) if rtt_values else 0,
            "min_rtt_ms": min(rtt_values) if rtt_values else 0,
            "avg_packet_loss": statistics.mean(packet_loss_values) if packet_loss_values else 0,
            "max_packet_loss": max(packet_loss_values) if packet_loss_values else 0,
            "avg_bandwidth_mbps": statistics.mean(bandwidth_values) if bandwidth_values else 0,
            "connection_stability": self._analyze_connection_stability(),
            "alerts": self._generate_network_alerts()
        }
        
        return analysis
    
    def _analyze_connection_stability(self) -> Dict:
        """Analisa estabilidade das conexões."""
        if not self.connection_metrics:
            return {"total_connections": 0, "success_rate": 0}
        
        total_connections = len(self.connection_metrics)
        successful_connections = sum(1 for c in self.connection_metrics if c.success)
        success_rate = successful_connections / total_connections if total_connections > 0 else 0
        
        return {
            "total_connections": total_connections,
            "successful_connections": successful_connections,
            "success_rate": success_rate
        }
    
    def _generate_network_alerts(self) -> List[str]:
        """Gera alertas baseados nas métricas."""
        alerts = []
        
        if not self.metrics:
            return alerts
        
        latest = self.metrics[-1]
        
        if latest.rtt_ms > 1000:  # RTT > 1s
            alerts.append(f"🚨 RTT alto: {latest.rtt_ms:.1f}ms")
        
        if latest.packet_loss > 0.05:  # > 5% de perda
            alerts.append(f"🚨 Perda de pacotes alta: {latest.packet_loss:.1%}")
        
        if latest.retransmission_rate > 0.1:  # > 10% de retransmissão
            alerts.append(f"⚠️ Retransmissão alta: {latest.retransmission_rate:.1%}")
        
        if latest.latency_jitter > 100:  # Jitter > 100ms
            alerts.append(f"⚠️ Jitter alto: {latest.latency_jitter:.1f}ms")
        
        return alerts
    
    def generate_network_report(self) -> str:
        """
        Gera relatório de performance da rede.
        
        Returns:
            str: Relatório em formato markdown
        """
        analysis = self.analyze_network_performance()
        
        if "error" in analysis:
            return f"# Relatório de Performance da Rede - {analysis['error']}"
        
        report = f"""
# Relatório de Performance da Rede - Omni Writer

## Métricas Gerais
- **Total de Medições**: {analysis['total_measurements']}
- **RTT Médio**: {analysis['avg_rtt_ms']:.1f}ms
- **RTT Máximo**: {analysis['max_rtt_ms']:.1f}ms
- **RTT Mínimo**: {analysis['min_rtt_ms']:.1f}ms
- **Perda de Pacotes Média**: {analysis['avg_packet_loss']:.1%}
- **Perda de Pacotes Máxima**: {analysis['max_packet_loss']:.1%}
- **Largura de Banda Média**: {analysis['avg_bandwidth_mbps']:.1f} Mbps

## Estabilidade de Conexão
- **Total de Conexões**: {analysis['connection_stability']['total_connections']}
- **Conexões Bem-sucedidas**: {analysis['connection_stability']['successful_connections']}
- **Taxa de Sucesso**: {analysis['connection_stability']['success_rate']:.1%}
"""
        
        # Alertas
        if analysis['alerts']:
            report += f"""
## Alertas de Rede
"""
            for alert in analysis['alerts']:
                report += f"- {alert}\n"
        
        # Métricas recentes
        if self.metrics:
            report += f"""
## Últimas Métricas
"""
            for metric in self.metrics[-5:]:  # Últimas 5 medições
                report += f"""
**{time.strftime('%H:%M:%S', time.localtime(metric.timestamp))}** - {metric.target_host}
- RTT: {metric.rtt_ms:.1f}ms
- Perda: {metric.packet_loss:.1%}
- Banda: {metric.bandwidth_mbps:.1f} Mbps
- Conexões: {metric.connection_count}
"""
        
        return report

def main():
    """Função principal para demonstração."""
    logger.info("Iniciando monitoramento de métricas de rede...")
    
    # Criar monitor
    monitor = NetworkMonitor([
        "api.openai.com",
        "api.deepseek.com",
        "localhost"
    ])
    
    # Iniciar monitoramento
    monitor.start_monitoring(interval=3)
    
    # Testar estabilidade de conexão
    logger.info("Testando estabilidade de conexão...")
    monitor.test_connection_stability("localhost", 5000, duration=30)
    
    # Aguardar algumas medições
    time.sleep(15)
    
    # Parar monitoramento
    monitor.stop_monitoring()
    
    # Gerar relatório
    report = monitor.generate_network_report()
    print(report)
    
    # Salvar relatório
    with open("network_performance_report.md", "w") as f:
        f.write(report)
    
    logger.info("Monitoramento de rede concluído!")

if __name__ == "__main__":
    main() 