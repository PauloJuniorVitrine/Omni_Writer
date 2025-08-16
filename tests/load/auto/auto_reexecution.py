"""
Auto-reexecution System - Omni Writer
=====================================

Sistema de reexecução automática de testes baseado em detecção de anomalias.
Monitora resultados e reexecuta testes quando detecta problemas.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 11
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T15:50:00Z
"""

import os
import json
import time
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import logging
import schedule
import psutil
import requests
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('auto_reexecution')

@dataclass
class TestResult:
    """Estrutura para armazenar resultados de testes."""
    test_name: str
    timestamp: datetime
    response_time_avg: float
    response_time_p95: float
    error_rate: float
    throughput: float
    status: str  # 'passed', 'failed', 'anomaly'
    anomaly_score: float = 0.0
    reexecution_count: int = 0

@dataclass
class AnomalyTrigger:
    """Configuração de trigger para anomalias."""
    metric: str
    threshold: float
    operator: str  # 'gt', 'lt', 'eq'
    severity: str  # 'low', 'medium', 'high'
    action: str  # 'reexecute', 'alert', 'both'

class AutoReexecutionSystem:
    """
    Sistema de reexecução automática baseado em detecção de anomalias.
    Monitora resultados de testes e reexecuta quando detecta problemas.
    """
    
    def __init__(self, 
                 results_dir: str = "tests/load/results",
                 config_file: str = "tests/load/auto/config.json"):
        """
        Inicializa o sistema de reexecução automática.
        
        Args:
            results_dir: Diretório com resultados dos testes
            config_file: Arquivo de configuração
        """
        self.results_dir = Path(results_dir)
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/auto/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Histórico de resultados
        self.test_history: List[TestResult] = []
        self.anomaly_history: List[Dict[str, Any]] = []
        
        # Configurações padrão baseadas no código real
        self.default_triggers = [
            AnomalyTrigger("response_time_avg", 800, "gt", "medium", "reexecute"),
            AnomalyTrigger("response_time_p95", 1500, "gt", "high", "both"),
            AnomalyTrigger("error_rate", 0.02, "gt", "high", "both"),
            AnomalyTrigger("throughput", 10, "lt", "medium", "reexecute"),
            AnomalyTrigger("anomaly_score", 0.7, "gt", "high", "both")
        ]
        
        # Configurações de reexecução
        self.reexecution_config = {
            "max_reexecutions": 3,
            "cooldown_minutes": 5,
            "auto_stop_on_success": True,
            "notification_channels": ["console", "file"],
            "test_timeout_minutes": 10
        }
        
        # Estado do sistema
        self.is_monitoring = False
        self.monitor_thread = None
        self.last_reexecution = {}
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Diretório de resultados: {self.results_dir}")
        logger.info(f"Triggers configurados: {len(self.triggers)}")

    def load_config(self) -> None:
        """
        Carrega configuração do arquivo ou usa padrões.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Carrega triggers
                self.triggers = []
                for trigger_data in config.get('triggers', []):
                    self.triggers.append(AnomalyTrigger(**trigger_data))
                
                # Carrega configurações de reexecução
                self.reexecution_config.update(config.get('reexecution', {}))
                
                logger.info("Configuração carregada do arquivo")
            else:
                self.triggers = self.default_triggers
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            self.triggers = self.default_triggers

    def save_config(self) -> None:
        """
        Salva configuração atual no arquivo.
        """
        try:
            config = {
                'triggers': [asdict(trigger) for trigger in self.triggers],
                'reexecution': self.reexecution_config,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def detect_anomalies(self, test_result: TestResult) -> List[Dict[str, Any]]:
        """
        Detecta anomalias baseado nos triggers configurados.
        """
        anomalies = []
        
        for trigger in self.triggers:
            try:
                # Obtém valor da métrica
                metric_value = getattr(test_result, trigger.metric, None)
                
                if metric_value is None:
                    continue
                
                # Avalia condição
                is_triggered = False
                if trigger.operator == "gt":
                    is_triggered = metric_value > trigger.threshold
                elif trigger.operator == "lt":
                    is_triggered = metric_value < trigger.threshold
                elif trigger.operator == "eq":
                    is_triggered = abs(metric_value - trigger.threshold) < 0.01
                
                if is_triggered:
                    anomaly = {
                        'trigger': asdict(trigger),
                        'test_name': test_result.test_name,
                        'timestamp': test_result.timestamp.isoformat(),
                        'metric_value': metric_value,
                        'threshold': trigger.threshold,
                        'severity': trigger.severity,
                        'action': trigger.action
                    }
                    anomalies.append(anomaly)
                    
                    logger.warning(f"Anomalia detectada: {trigger.metric} = {metric_value} "
                                 f"({trigger.operator} {trigger.threshold})")
                    
            except Exception as e:
                logger.error(f"Erro ao avaliar trigger {trigger.metric}: {e}")
        
        return anomalies

    def calculate_anomaly_score(self, test_result: TestResult) -> float:
        """
        Calcula score de anomalia baseado em múltiplas métricas.
        """
        try:
            # Normaliza métricas
            normalized_metrics = {}
            
            # Response time (normaliza para 0-1, onde 1 = muito lento)
            if test_result.response_time_avg > 0:
                normalized_metrics['response_time'] = min(test_result.response_time_avg / 2000, 1.0)
            
            # Error rate (normaliza para 0-1, onde 1 = muito alto)
            normalized_metrics['error_rate'] = min(test_result.error_rate * 50, 1.0)
            
            # Throughput (normaliza para 0-1, onde 1 = muito baixo)
            if test_result.throughput > 0:
                normalized_metrics['throughput'] = min(1.0 / test_result.throughput, 1.0)
            
            # Calcula score ponderado
            weights = {
                'response_time': 0.4,
                'error_rate': 0.4,
                'throughput': 0.2
            }
            
            score = sum(normalized_metrics.get(metric, 0) * weight 
                       for metric, weight in weights.items())
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"Erro ao calcular anomaly score: {e}")
            return 0.0

    def should_reexecute(self, test_name: str, anomalies: List[Dict[str, Any]]) -> bool:
        """
        Decide se deve reexecutar o teste baseado nas anomalias.
        """
        # Verifica se já reexecutou muito
        reexecution_count = self.last_reexecution.get(test_name, {}).get('count', 0)
        if reexecution_count >= self.reexecution_config['max_reexecutions']:
            logger.info(f"Teste {test_name} já reexecutou {reexecution_count} vezes - limite atingido")
            return False
        
        # Verifica cooldown
        last_time = self.last_reexecution.get(test_name, {}).get('timestamp')
        if last_time:
            cooldown_seconds = self.reexecution_config['cooldown_minutes'] * 60
            if (datetime.now() - last_time).total_seconds() < cooldown_seconds:
                logger.info(f"Teste {test_name} em cooldown")
                return False
        
        # Verifica se há anomalias que requerem reexecução
        for anomaly in anomalies:
            if anomaly['action'] in ['reexecute', 'both']:
                if anomaly['severity'] in ['medium', 'high']:
                    logger.info(f"Reexecução necessária para {test_name} - {anomaly['trigger']['metric']}")
                    return True
        
        return False

    def execute_load_test(self, test_name: str) -> TestResult:
        """
        Executa teste de carga específico.
        """
        logger.info(f"Executando teste: {test_name}")
        
        start_time = datetime.now()
        
        try:
            # Determina arquivo Locust baseado no nome do teste
            locust_file = self._get_locust_file(test_name)
            
            if not locust_file:
                logger.error(f"Arquivo Locust não encontrado para {test_name}")
                return TestResult(
                    test_name=test_name,
                    timestamp=start_time,
                    response_time_avg=0,
                    response_time_p95=0,
                    error_rate=1.0,
                    throughput=0,
                    status='failed'
                )
            
            # Executa teste
            cmd = [
                'locust',
                '-f', str(locust_file),
                '--headless',
                '-u', '50',  # 50 usuários
                '-r', '5',   # 5 usuários/segundo
                '-t', '2m',  # 2 minutos
                '--host', 'http://localhost:5000',
                '--csv', str(self.results_dir / f"{test_name}_auto_{start_time.strftime('%Y%m%d_%H%M%S')}")
            ]
            
            # Executa com timeout
            timeout = self.reexecution_config['test_timeout_minutes'] * 60
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            # Analisa resultados
            test_result = self._analyze_test_output(test_name, start_time, result)
            
            logger.info(f"Teste {test_name} concluído - Status: {test_result.status}")
            return test_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Teste {test_name} expirou")
            return TestResult(
                test_name=test_name,
                timestamp=start_time,
                response_time_avg=0,
                response_time_p95=0,
                error_rate=1.0,
                throughput=0,
                status='timeout'
            )
        except Exception as e:
            logger.error(f"Erro ao executar teste {test_name}: {e}")
            return TestResult(
                test_name=test_name,
                timestamp=start_time,
                response_time_avg=0,
                response_time_p95=0,
                error_rate=1.0,
                throughput=0,
                status='failed'
            )

    def _get_locust_file(self, test_name: str) -> Optional[Path]:
        """
        Determina arquivo Locust baseado no nome do teste.
        """
        locust_files = {
            'generate': 'tests/load/locustfile_generate.py',
            'download': 'tests/load/locustfile_download.py',
            'feedback': 'tests/load/locustfile_feedback.py',
            'webhook': 'tests/load/locustfile_webhook.py',
            'status': 'tests/load/locustfile_status.py',
            'events': 'tests/load/locustfile_events.py'
        }
        
        for key, file_path in locust_files.items():
            if key in test_name.lower():
                path = Path(file_path)
                if path.exists():
                    return path
        
        return None

    def _analyze_test_output(self, test_name: str, start_time: datetime, 
                           result: subprocess.CompletedProcess) -> TestResult:
        """
        Analisa saída do teste para extrair métricas.
        """
        try:
            # Busca arquivo CSV gerado
            csv_pattern = f"{test_name}_auto_{start_time.strftime('%Y%m%d_%H%M%S')}_stats.csv"
            csv_files = list(self.results_dir.glob(csv_pattern))
            
            if not csv_files:
                logger.warning(f"Arquivo CSV não encontrado para {test_name}")
                return TestResult(
                    test_name=test_name,
                    timestamp=start_time,
                    response_time_avg=0,
                    response_time_p95=0,
                    error_rate=1.0,
                    throughput=0,
                    status='failed'
                )
            
            # Lê dados CSV
            df = pd.read_csv(csv_files[0])
            
            # Extrai métricas
            response_time_avg = df['Average Response Time'].iloc[-1] if 'Average Response Time' in df.columns else 0
            response_time_p95 = df['95% Response Time'].iloc[-1] if '95% Response Time' in df.columns else 0
            error_rate = df['Failure Count'].iloc[-1] / df['Request Count'].iloc[-1] if 'Failure Count' in df.columns else 0
            throughput = df['Requests/s'].iloc[-1] if 'Requests/s' in df.columns else 0
            
            # Determina status
            status = 'passed'
            if error_rate > 0.05:  # > 5% de erro
                status = 'failed'
            elif response_time_avg > 1000:  # > 1s
                status = 'anomaly'
            
            # Calcula anomaly score
            test_result = TestResult(
                test_name=test_name,
                timestamp=start_time,
                response_time_avg=response_time_avg,
                response_time_p95=response_time_p95,
                error_rate=error_rate,
                throughput=throughput,
                status=status
            )
            
            test_result.anomaly_score = self.calculate_anomaly_score(test_result)
            
            return test_result
            
        except Exception as e:
            logger.error(f"Erro ao analisar saída do teste {test_name}: {e}")
            return TestResult(
                test_name=test_name,
                timestamp=start_time,
                response_time_avg=0,
                response_time_p95=0,
                error_rate=1.0,
                throughput=0,
                status='failed'
            )

    def reexecute_test(self, test_name: str, anomalies: List[Dict[str, Any]]) -> TestResult:
        """
        Reexecuta teste específico.
        """
        logger.info(f"Iniciando reexecução de {test_name}")
        
        # Atualiza contador de reexecução
        if test_name not in self.last_reexecution:
            self.last_reexecution[test_name] = {'count': 0, 'timestamp': None}
        
        self.last_reexecution[test_name]['count'] += 1
        self.last_reexecution[test_name]['timestamp'] = datetime.now()
        
        # Executa teste
        test_result = self.execute_load_test(test_name)
        test_result.reexecution_count = self.last_reexecution[test_name]['count']
        
        # Adiciona ao histórico
        self.test_history.append(test_result)
        
        # Detecta novas anomalias
        new_anomalies = self.detect_anomalies(test_result)
        
        # Registra anomalias
        for anomaly in new_anomalies:
            anomaly['reexecution_count'] = test_result.reexecution_count
            self.anomaly_history.append(anomaly)
        
        # Verifica se deve parar
        if (self.reexecution_config['auto_stop_on_success'] and 
            test_result.status == 'passed' and 
            len(new_anomalies) == 0):
            logger.info(f"Reexecução bem-sucedida para {test_name} - parando")
        elif test_result.reexecution_count >= self.reexecution_config['max_reexecutions']:
            logger.warning(f"Máximo de reexecuções atingido para {test_name}")
        
        return test_result

    def monitor_results(self) -> None:
        """
        Monitora resultados de testes em tempo real.
        """
        logger.info("Iniciando monitoramento de resultados...")
        
        while self.is_monitoring:
            try:
                # Busca novos arquivos CSV
                csv_files = list(self.results_dir.glob("*.csv"))
                
                for csv_file in csv_files:
                    # Verifica se é um arquivo recente (últimos 5 minutos)
                    file_age = time.time() - csv_file.stat().st_mtime
                    if file_age < 300:  # 5 minutos
                        self._process_new_result(csv_file)
                
                # Aguarda antes da próxima verificação
                time.sleep(30)  # 30 segundos
                
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
                time.sleep(60)  # 1 minuto em caso de erro

    def _process_new_result(self, csv_file: Path) -> None:
        """
        Processa novo resultado de teste.
        """
        try:
            # Extrai nome do teste do arquivo
            test_name = csv_file.stem.split('_')[0]
            
            # Analisa resultado
            df = pd.read_csv(csv_file)
            
            if df.empty:
                return
            
            # Cria TestResult
            test_result = TestResult(
                test_name=test_name,
                timestamp=datetime.fromtimestamp(csv_file.stat().st_mtime),
                response_time_avg=df['Average Response Time'].iloc[-1] if 'Average Response Time' in df.columns else 0,
                response_time_p95=df['95% Response Time'].iloc[-1] if '95% Response Time' in df.columns else 0,
                error_rate=df['Failure Count'].iloc[-1] / df['Request Count'].iloc[-1] if 'Failure Count' in df.columns else 0,
                throughput=df['Requests/s'].iloc[-1] if 'Requests/s' in df.columns else 0,
                status='passed'
            )
            
            test_result.anomaly_score = self.calculate_anomaly_score(test_result)
            
            # Detecta anomalias
            anomalies = self.detect_anomalies(test_result)
            
            # Adiciona ao histórico
            self.test_history.append(test_result)
            
            # Registra anomalias
            for anomaly in anomalies:
                self.anomaly_history.append(anomaly)
            
            # Verifica se deve reexecutar
            if anomalies and self.should_reexecute(test_name, anomalies):
                logger.warning(f"Anomalias detectadas em {test_name} - iniciando reexecução")
                
                # Executa reexecução em thread separada
                reexecution_thread = threading.Thread(
                    target=self.reexecute_test,
                    args=(test_name, anomalies)
                )
                reexecution_thread.start()
            
        except Exception as e:
            logger.error(f"Erro ao processar resultado {csv_file}: {e}")

    def start_monitoring(self) -> None:
        """
        Inicia monitoramento contínuo.
        """
        if self.is_monitoring:
            logger.warning("Monitoramento já está ativo")
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_results)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Monitoramento iniciado")

    def stop_monitoring(self) -> None:
        """
        Para monitoramento contínuo.
        """
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Monitoramento parado")

    def generate_report(self) -> str:
        """
        Gera relatório de reexecuções e anomalias.
        """
        try:
            report_file = self.output_dir / f"reexecution_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Reexecução Automática - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de testes executados:** {len(self.test_history)}\n")
                f.write(f"- **Total de anomalias detectadas:** {len(self.anomaly_history)}\n")
                f.write(f"- **Total de reexecuções:** {sum(1 for r in self.test_history if r.reexecution_count > 0)}\n\n")
                
                f.write("## Anomalias Detectadas\n\n")
                
                if self.anomaly_history:
                    f.write("| Teste | Métrica | Valor | Threshold | Severidade | Ação |\n")
                    f.write("|-------|---------|-------|-----------|------------|------|\n")
                    
                    for anomaly in self.anomaly_history[-10:]:  # Últimas 10 anomalias
                        f.write(f"| {anomaly['test_name']} | {anomaly['trigger']['metric']} | "
                               f"{anomaly['metric_value']:.2f} | {anomaly['threshold']} | "
                               f"{anomaly['severity']} | {anomaly['action']} |\n")
                else:
                    f.write("Nenhuma anomalia detectada.\n")
                
                f.write("\n## Histórico de Reexecuções\n\n")
                
                reexecutions = [r for r in self.test_history if r.reexecution_count > 0]
                if reexecutions:
                    f.write("| Teste | Reexecuções | Status Final | Anomaly Score |\n")
                    f.write("|-------|-------------|--------------|---------------|\n")
                    
                    for result in reexecutions:
                        f.write(f"| {result.test_name} | {result.reexecution_count} | "
                               f"{result.status} | {result.anomaly_score:.3f} |\n")
                else:
                    f.write("Nenhuma reexecução realizada.\n")
                
                f.write("\n## Configurações Ativas\n\n")
                f.write(f"- **Máximo de reexecuções:** {self.reexecution_config['max_reexecutions']}\n")
                f.write(f"- **Cooldown:** {self.reexecution_config['cooldown_minutes']} minutos\n")
                f.write(f"- **Auto-stop:** {self.reexecution_config['auto_stop_on_success']}\n")
                f.write(f"- **Triggers ativos:** {len(self.triggers)}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Auto Reexecution System...")
    
    system = AutoReexecutionSystem()
    
    try:
        # Inicia monitoramento
        system.start_monitoring()
        
        # Executa por 1 hora (para demonstração)
        logger.info("Sistema ativo por 1 hora...")
        time.sleep(3600)  # 1 hora
        
    except KeyboardInterrupt:
        logger.info("Interrupção recebida")
    finally:
        # Para monitoramento
        system.stop_monitoring()
        
        # Gera relatório final
        report_file = system.generate_report()
        logger.info(f"Relatório final: {report_file}")
        
        logger.info("Sistema finalizado")


if __name__ == "__main__":
    main() 