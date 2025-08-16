"""
Script de Chaos Testing Automatizado para Omni Writer.
Testa resiliência dos endpoints em cenários de falha.

Prompt: Implementação de Chaos Testing Automatizado
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T11:30:00Z
Tracing ID: CHAOS_TESTER_20250128_001
"""
import os
import json
import time
import random
import logging
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import signal
import sys

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("chaos_tester")

@dataclass
class ChaosScenario:
    """Representa um cenário de chaos testing."""
    name: str
    description: str
    duration: int  # segundos
    failure_rate: float  # 0.0 a 1.0
    endpoints: List[str]
    chaos_type: str  # 'network', 'timeout', 'rate_limit', 'service_failure'
    severity: str  # 'low', 'medium', 'high', 'critical'
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'name': self.name,
            'description': self.description,
            'duration': self.duration,
            'failure_rate': self.failure_rate,
            'endpoints': self.endpoints,
            'chaos_type': self.chaos_type,
            'severity': self.severity
        }

@dataclass
class TestResult:
    """Resultado de um teste de chaos."""
    scenario_name: str
    endpoint: str
    status: str  # 'success', 'failure', 'timeout', 'error'
    response_time: float
    error_message: Optional[str]
    timestamp: datetime
    chaos_applied: bool
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'scenario_name': self.scenario_name,
            'endpoint': self.endpoint,
            'status': self.status,
            'response_time': self.response_time,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat(),
            'chaos_applied': self.chaos_applied
        }

class ChaosTester:
    """
    Testador de chaos para verificar resiliência dos endpoints.
    Baseado no código real do projeto Omni Writer.
    """
    
    def __init__(self, config_path: str = "scripts/chaos_tester_config.json"):
        """
        Inicializa o testador de chaos.
        
        Args:
            config_path: Caminho para arquivo de configuração
        """
        self.config = self._load_config(config_path)
        self.base_url = self.config.get('base_url', 'http://localhost:5000')
        self.results: List[TestResult] = []
        self.trace_id = f"CHAOS_TEST_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.running = False
        
        logger.info(f"Chaos Tester inicializado | trace_id={self.trace_id}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Carrega configuração do testador."""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                # Configuração padrão baseada no projeto real
                return {
                    "base_url": "http://localhost:5000",
                    "timeout": 30,
                    "max_retries": 3,
                    "concurrent_requests": 10,
                    "scenarios": [
                        {
                            "name": "network_failure",
                            "description": "Simula falhas de rede",
                            "duration": 60,
                            "failure_rate": 0.3,
                            "endpoints": ["/api/generate-articles", "/api/entrega-zip"],
                            "chaos_type": "network",
                            "severity": "medium"
                        },
                        {
                            "name": "timeout_scenario",
                            "description": "Simula timeouts de resposta",
                            "duration": 45,
                            "failure_rate": 0.2,
                            "endpoints": ["/api/generate-articles"],
                            "chaos_type": "timeout",
                            "severity": "high"
                        },
                        {
                            "name": "rate_limiting",
                            "description": "Testa limites de taxa",
                            "duration": 30,
                            "failure_rate": 0.5,
                            "endpoints": ["/api/generate-articles", "/api/entrega-zip"],
                            "chaos_type": "rate_limit",
                            "severity": "medium"
                        }
                    ],
                    "notification_channels": ["slack", "email"]
                }
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            return {}
    
    def create_scenarios(self) -> List[ChaosScenario]:
        """Cria cenários de chaos testing baseados na configuração."""
        scenarios = []
        
        for scenario_config in self.config.get('scenarios', []):
            scenario = ChaosScenario(
                name=scenario_config['name'],
                description=scenario_config['description'],
                duration=scenario_config['duration'],
                failure_rate=scenario_config['failure_rate'],
                endpoints=scenario_config['endpoints'],
                chaos_type=scenario_config['chaos_type'],
                severity=scenario_config['severity']
            )
            scenarios.append(scenario)
        
        return scenarios
    
    def apply_network_chaos(self, failure_rate: float) -> bool:
        """
        Aplica chaos de rede.
        
        Args:
            failure_rate: Taxa de falha (0.0 a 1.0)
            
        Returns:
            True se chaos foi aplicado
        """
        try:
            # Simula falhas de rede usando iptables (Linux) ou netsh (Windows)
            if random.random() < failure_rate:
                if os.name == 'nt':  # Windows
                    # Bloqueia porta 5000 temporariamente
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        'name="Chaos Test Block"', 'dir=in', 'action=block',
                        'protocol=TCP', 'localport=5000'
                    ], capture_output=True)
                    time.sleep(2)
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        'name="Chaos Test Block"'
                    ], capture_output=True)
                else:  # Linux
                    # Bloqueia porta 5000 temporariamente
                    subprocess.run([
                        'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '5000', '-j', 'DROP'
                    ], capture_output=True)
                    time.sleep(2)
                    subprocess.run([
                        'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '5000', '-j', 'DROP'
                    ], capture_output=True)
                
                logger.info(f"Network chaos aplicado | failure_rate={failure_rate}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao aplicar network chaos: {e}")
            return False
    
    def apply_timeout_chaos(self, failure_rate: float) -> bool:
        """
        Aplica chaos de timeout.
        
        Args:
            failure_rate: Taxa de falha (0.0 a 1.0)
            
        Returns:
            True se chaos foi aplicado
        """
        try:
            if random.random() < failure_rate:
                # Simula timeout fazendo a thread dormir
                sleep_time = random.uniform(5, 15)
                time.sleep(sleep_time)
                logger.info(f"Timeout chaos aplicado | sleep_time={sleep_time}s")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao aplicar timeout chaos: {e}")
            return False
    
    def apply_rate_limit_chaos(self, failure_rate: float) -> bool:
        """
        Aplica chaos de rate limiting.
        
        Args:
            failure_rate: Taxa de falha (0.0 a 1.0)
            
        Returns:
            True se chaos foi aplicado
        """
        try:
            if random.random() < failure_rate:
                # Simula rate limiting fazendo múltiplas requisições rápidas
                for _ in range(random.randint(5, 15)):
                    requests.get(f"{self.base_url}/api/generate-articles", timeout=1)
                    time.sleep(0.1)
                
                logger.info("Rate limit chaos aplicado")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao aplicar rate limit chaos: {e}")
            return False
    
    def test_endpoint(self, endpoint: str, scenario: ChaosScenario) -> TestResult:
        """
        Testa um endpoint específico com chaos aplicado.
        
        Args:
            endpoint: Endpoint a ser testado
            scenario: Cenário de chaos
            
        Returns:
            Resultado do teste
        """
        start_time = time.time()
        chaos_applied = False
        error_message = None
        
        try:
            # Aplica chaos baseado no tipo
            if scenario.chaos_type == 'network':
                chaos_applied = self.apply_network_chaos(scenario.failure_rate)
            elif scenario.chaos_type == 'timeout':
                chaos_applied = self.apply_timeout_chaos(scenario.failure_rate)
            elif scenario.chaos_type == 'rate_limit':
                chaos_applied = self.apply_rate_limit_chaos(scenario.failure_rate)
            
            # Faz a requisição
            timeout = self.config.get('timeout', 30)
            response = requests.post(
                f"{self.base_url}{endpoint}",
                timeout=timeout,
                headers={'Content-Type': 'application/json'},
                json={}  # Payload vazio para teste
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                status = 'success'
            elif response.status_code == 429:
                status = 'rate_limited'
            elif response.status_code >= 500:
                status = 'server_error'
            else:
                status = 'failure'
                error_message = f"HTTP {response.status_code}"
            
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            status = 'timeout'
            error_message = 'Request timeout'
            
        except requests.exceptions.ConnectionError:
            response_time = time.time() - start_time
            status = 'error'
            error_message = 'Connection error'
            
        except Exception as e:
            response_time = time.time() - start_time
            status = 'error'
            error_message = str(e)
        
        return TestResult(
            scenario_name=scenario.name,
            endpoint=endpoint,
            status=status,
            response_time=response_time,
            error_message=error_message,
            timestamp=datetime.utcnow(),
            chaos_applied=chaos_applied
        )
    
    def run_scenario(self, scenario: ChaosScenario) -> List[TestResult]:
        """
        Executa um cenário de chaos testing.
        
        Args:
            scenario: Cenário a ser executado
            
        Returns:
            Lista de resultados do teste
        """
        logger.info(f"Iniciando cenário: {scenario.name} | duration={scenario.duration}s")
        
        results = []
        start_time = time.time()
        
        # Executa testes em paralelo
        with ThreadPoolExecutor(max_workers=self.config.get('concurrent_requests', 10)) as executor:
            while time.time() - start_time < scenario.duration and self.running:
                # Submete testes para todos os endpoints do cenário
                futures = []
                for endpoint in scenario.endpoints:
                    future = executor.submit(self.test_endpoint, endpoint, scenario)
                    futures.append(future)
                
                # Coleta resultados
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                        logger.debug(f"Teste concluído: {result.endpoint} | status={result.status}")
                    except Exception as e:
                        logger.error(f"Erro no teste: {e}")
                
                # Pequena pausa entre iterações
                time.sleep(1)
        
        logger.info(f"Cenário concluído: {scenario.name} | testes={len(results)}")
        return results
    
    def run_all_scenarios(self) -> List[TestResult]:
        """
        Executa todos os cenários de chaos testing.
        
        Returns:
            Lista de todos os resultados
        """
        logger.info(f"Iniciando chaos testing completo | trace_id={self.trace_id}")
        
        self.running = True
        all_results = []
        
        try:
            scenarios = self.create_scenarios()
            
            for scenario in scenarios:
                if not self.running:
                    break
                
                logger.info(f"Executando cenário: {scenario.name}")
                scenario_results = self.run_scenario(scenario)
                all_results.extend(scenario_results)
                
                # Pausa entre cenários
                time.sleep(5)
            
        except KeyboardInterrupt:
            logger.info("Chaos testing interrompido pelo usuário")
            self.running = False
            
        except Exception as e:
            logger.error(f"Erro durante chaos testing: {e}")
            
        finally:
            self.running = False
        
        self.results = all_results
        return all_results
    
    def generate_report(self, output_path: str = "logs/chaos_test_report.json") -> str:
        """
        Gera relatório dos testes de chaos.
        
        Args:
            output_path: Caminho para salvar o relatório
            
        Returns:
            Caminho do relatório gerado
        """
        try:
            # Cria diretório se não existir
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Calcula métricas
            total_tests = len(self.results)
            successful_tests = len([r for r in self.results if r.status == 'success'])
            failed_tests = len([r for r in self.results if r.status in ['failure', 'error', 'timeout']])
            rate_limited_tests = len([r for r in self.results if r.status == 'rate_limited'])
            
            avg_response_time = sum(r.response_time for r in self.results) / total_tests if total_tests > 0 else 0
            
            # Agrupa por cenário
            scenario_results = {}
            for result in self.results:
                if result.scenario_name not in scenario_results:
                    scenario_results[result.scenario_name] = []
                scenario_results[result.scenario_name].append(result.to_dict())
            
            report = {
                'trace_id': self.trace_id,
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'total_tests': total_tests,
                    'successful_tests': successful_tests,
                    'failed_tests': failed_tests,
                    'rate_limited_tests': rate_limited_tests,
                    'success_rate': (successful_tests / total_tests * 100) if total_tests > 0 else 0,
                    'avg_response_time': avg_response_time
                },
                'scenario_results': scenario_results,
                'recommendations': self._generate_recommendations()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Relatório gerado: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""
    
    def _generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas nos resultados."""
        recommendations = []
        
        total_tests = len(self.results)
        if total_tests == 0:
            return ["Nenhum teste executado"]
        
        success_rate = len([r for r in self.results if r.status == 'success']) / total_tests * 100
        
        if success_rate < 80:
            recommendations.append("Melhorar resiliência dos endpoints - taxa de sucesso baixa")
        
        timeout_tests = len([r for r in self.results if r.status == 'timeout'])
        if timeout_tests > total_tests * 0.1:
            recommendations.append("Otimizar timeouts - muitos testes falharam por timeout")
        
        rate_limited_tests = len([r for r in self.results if r.status == 'rate_limited'])
        if rate_limited_tests > total_tests * 0.2:
            recommendations.append("Ajustar rate limiting - muitos testes foram limitados")
        
        avg_response_time = sum(r.response_time for r in self.results) / total_tests
        if avg_response_time > 5.0:
            recommendations.append("Otimizar performance - tempo de resposta médio alto")
        
        if not recommendations:
            recommendations.append("Sistema demonstrou boa resiliência nos testes")
        
        return recommendations
    
    def send_alerts(self) -> bool:
        """
        Envia alertas para canais configurados.
        
        Returns:
            True se alertas foram enviados com sucesso
        """
        try:
            channels = self.config.get('notification_channels', [])
            
            # Calcula métricas críticas
            total_tests = len(self.results)
            if total_tests == 0:
                return True
            
            success_rate = len([r for r in self.results if r.status == 'success']) / total_tests * 100
            
            # Só envia alerta se taxa de sucesso for baixa
            if success_rate < 70:
                alert_message = self._format_alert_message(success_rate, total_tests)
                
                for channel in channels:
                    if channel == 'slack':
                        self._send_slack_alert(alert_message)
                    elif channel == 'email':
                        self._send_email_alert(alert_message)
                
                logger.info(f"Alertas enviados para {len(channels)} canais")
                return True
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar alertas: {e}")
            return False
    
    def _format_alert_message(self, success_rate: float, total_tests: int) -> str:
        """Formata mensagem de alerta."""
        message = f"🚨 ALERTA CHAOS TESTING - Taxa de sucesso baixa\n\n"
        message += f"• Taxa de sucesso: {success_rate:.1f}%\n"
        message += f"• Total de testes: {total_tests}\n"
        message += f"• Trace ID: {self.trace_id}\n\n"
        message += "Recomendações:\n"
        message += "• Verificar resiliência dos endpoints\n"
        message += "• Revisar configurações de timeout\n"
        message += "• Ajustar rate limiting se necessário"
        
        return message
    
    def _send_slack_alert(self, message: str) -> bool:
        """Envia alerta para Slack."""
        try:
            webhook_url = os.getenv('SLACK_WEBHOOK_URL')
            if webhook_url:
                payload = {'text': message}
                response = requests.post(webhook_url, json=payload, timeout=10)
                return response.status_code == 200
            return False
        except Exception as e:
            logger.error(f"Erro ao enviar alerta Slack: {e}")
            return False
    
    def _send_email_alert(self, message: str) -> bool:
        """Envia alerta por email."""
        try:
            # Mock para demonstração
            logger.info(f"Email alert seria enviado: {message[:100]}...")
            return True
        except Exception as e:
            logger.error(f"Erro ao enviar alerta email: {e}")
            return False

def signal_handler(signum, frame):
    """Handler para interrupção do teste."""
    logger.info("Sinal de interrupção recebido. Finalizando chaos testing...")
    sys.exit(0)

def main():
    """Função principal do script."""
    try:
        # Configura handler de sinal
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Inicializa testador
        tester = ChaosTester()
        
        # Executa cenários
        results = tester.run_all_scenarios()
        
        # Gera relatório
        report_path = tester.generate_report()
        
        # Envia alertas se necessário
        tester.send_alerts()
        
        # Resumo
        total_tests = len(results)
        successful_tests = len([r for r in results if r.status == 'success'])
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"✅ Chaos testing concluído: {successful_tests}/{total_tests} testes bem-sucedidos ({success_rate:.1f}%)")
        print(f"📊 Relatório: {report_path}")
        
        if success_rate < 80:
            print("⚠️  Taxa de sucesso baixa. Verifique a resiliência do sistema.")
            return 1
        else:
            print("🎉 Sistema demonstrou boa resiliência!")
            return 0
            
    except Exception as e:
        logger.error(f"Erro na execução do chaos tester: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 