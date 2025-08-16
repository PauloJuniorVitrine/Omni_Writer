"""
Duration Control Enhancement - Omni Writer
==========================================

Sistema de controle de duração aprimorado para testes de carga.
Limites configuráveis, parada automática e análise de eficiência.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 19
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:35:00Z
"""

import os
import json
import time
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Callable
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import signal
import psutil
import gc
import numpy as np

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('enhanced_duration')

class DurationLimitType(Enum):
    """Tipos de limite de duração."""
    TIME_BASED = "time_based"
    REQUEST_BASED = "request_based"
    MEMORY_BASED = "memory_based"
    CPU_BASED = "cpu_based"
    ERROR_BASED = "error_based"
    CUSTOM = "custom"

class StopReason(Enum):
    """Razões para parada."""
    TIME_LIMIT = "time_limit"
    REQUEST_LIMIT = "request_limit"
    MEMORY_LIMIT = "memory_limit"
    CPU_LIMIT = "cpu_limit"
    ERROR_LIMIT = "error_limit"
    MANUAL = "manual"
    SYSTEM_OVERLOAD = "system_overload"
    CUSTOM_CONDITION = "custom_condition"

@dataclass
class DurationLimit:
    """Configuração de limite de duração."""
    limit_id: str
    limit_type: DurationLimitType
    value: float
    unit: str  # 'seconds', 'requests', 'percentage', 'count'
    enabled: bool = True
    description: str = ""

@dataclass
class DurationMetrics:
    """Métricas de duração."""
    start_time: datetime
    current_time: datetime
    elapsed_seconds: float
    requests_completed: int
    requests_failed: int
    memory_usage_mb: float
    cpu_usage_percent: float
    error_rate: float
    efficiency_score: float

@dataclass
class StopCondition:
    """Condição de parada."""
    condition_id: str
    limit_id: str
    triggered: bool
    trigger_time: datetime
    trigger_value: float
    stop_reason: StopReason
    description: str

class EnhancedDurationController:
    """
    Controlador de duração aprimorado para testes de carga.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/duration/config.json"):
        """
        Inicializa o controlador de duração.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/duration/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações de duração
        self.duration_config = {
            "default_limits": {
                "max_duration_minutes": 60,
                "max_requests": 10000,
                "max_memory_mb": 2048,
                "max_cpu_percent": 90,
                "max_error_rate": 0.05,
                "grace_period_seconds": 30
            },
            "auto_stop": True,
            "enable_notifications": True,
            "enable_efficiency_analysis": True,
            "enable_resource_monitoring": True,
            "enable_graceful_shutdown": True,
            "notification_channels": ["console", "log", "file"]
        }
        
        # Limites configurados
        self.duration_limits: List[DurationLimit] = []
        self.active_limits: Dict[str, DurationLimit] = {}
        
        # Estado do controlador
        self.is_running = False
        self.start_time = None
        self.stop_time = None
        self.stop_reason = None
        
        # Métricas
        self.duration_metrics: DurationMetrics = None
        self.metrics_history: List[DurationMetrics] = []
        
        # Condições de parada
        self.stop_conditions: List[StopCondition] = []
        self.triggered_conditions: List[StopCondition] = []
        
        # Callbacks
        self.stop_callbacks: List[Callable] = []
        self.metric_callbacks: List[Callable] = []
        
        # Threads de monitoramento
        self.monitor_thread = None
        self.metrics_thread = None
        
        # Sinais de sistema
        self._setup_signal_handlers()
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")

    def load_config(self) -> None:
        """
        Carrega configuração de duração.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                self.duration_config.update(config.get('duration_config', {}))
                logger.info("Configuração carregada do arquivo")
            else:
                self._create_default_limits()
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            self._create_default_limits()

    def _create_default_limits(self) -> None:
        """
        Cria limites padrão baseados no código real.
        """
        default_limits = [
            DurationLimit(
                limit_id="time_limit",
                limit_type=DurationLimitType.TIME_BASED,
                value=self.duration_config["default_limits"]["max_duration_minutes"],
                unit="minutes",
                description="Limite máximo de tempo de execução"
            ),
            DurationLimit(
                limit_id="request_limit",
                limit_type=DurationLimitType.REQUEST_BASED,
                value=self.duration_config["default_limits"]["max_requests"],
                unit="requests",
                description="Limite máximo de requisições"
            ),
            DurationLimit(
                limit_id="memory_limit",
                limit_type=DurationLimitType.MEMORY_BASED,
                value=self.duration_config["default_limits"]["max_memory_mb"],
                unit="mb",
                description="Limite máximo de uso de memória"
            ),
            DurationLimit(
                limit_id="cpu_limit",
                limit_type=DurationLimitType.CPU_BASED,
                value=self.duration_config["default_limits"]["max_cpu_percent"],
                unit="percentage",
                description="Limite máximo de uso de CPU"
            ),
            DurationLimit(
                limit_id="error_limit",
                limit_type=DurationLimitType.ERROR_BASED,
                value=self.duration_config["default_limits"]["max_error_rate"],
                unit="percentage",
                description="Limite máximo de taxa de erro"
            )
        ]
        
        self.duration_limits = default_limits
        
        # Ativa todos os limites
        for limit in self.duration_limits:
            self.active_limits[limit.limit_id] = limit

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'duration_config': self.duration_config,
                'duration_limits': [asdict(limit) for limit in self.duration_limits],
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def _setup_signal_handlers(self) -> None:
        """
        Configura handlers para sinais do sistema.
        """
        def signal_handler(signum, frame):
            logger.warning(f"Sinal {signum} recebido. Iniciando parada graciosa...")
            self.stop(StopReason.MANUAL, "Sinal do sistema recebido")
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def add_limit(self, limit: DurationLimit) -> None:
        """
        Adiciona um novo limite de duração.
        """
        self.duration_limits.append(limit)
        if limit.enabled:
            self.active_limits[limit.limit_id] = limit
        
        logger.info(f"Limite adicionado: {limit.limit_id} ({limit.limit_type.value})")

    def remove_limit(self, limit_id: str) -> bool:
        """
        Remove um limite de duração.
        """
        for i, limit in enumerate(self.duration_limits):
            if limit.limit_id == limit_id:
                del self.duration_limits[i]
                if limit_id in self.active_limits:
                    del self.active_limits[limit_id]
                
                logger.info(f"Limite removido: {limit_id}")
                return True
        
        return False

    def enable_limit(self, limit_id: str) -> bool:
        """
        Habilita um limite de duração.
        """
        for limit in self.duration_limits:
            if limit.limit_id == limit_id:
                limit.enabled = True
                self.active_limits[limit_id] = limit
                logger.info(f"Limite habilitado: {limit_id}")
                return True
        
        return False

    def disable_limit(self, limit_id: str) -> bool:
        """
        Desabilita um limite de duração.
        """
        for limit in self.duration_limits:
            if limit.limit_id == limit_id:
                limit.enabled = False
                if limit_id in self.active_limits:
                    del self.active_limits[limit_id]
                
                logger.info(f"Limite desabilitado: {limit_id}")
                return True
        
        return False

    def start(self) -> None:
        """
        Inicia o controlador de duração.
        """
        if self.is_running:
            logger.warning("Controlador já está em execução")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.stop_time = None
        self.stop_reason = None
        
        # Inicializa métricas
        self.duration_metrics = DurationMetrics(
            start_time=self.start_time,
            current_time=self.start_time,
            elapsed_seconds=0.0,
            requests_completed=0,
            requests_failed=0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0,
            error_rate=0.0,
            efficiency_score=1.0
        )
        
        # Inicia threads de monitoramento
        self._start_monitoring_threads()
        
        logger.info(f"Controlador iniciado em {self.start_time}")

    def stop(self, reason: StopReason = StopReason.MANUAL, description: str = "") -> None:
        """
        Para o controlador de duração.
        """
        if not self.is_running:
            logger.warning("Controlador não está em execução")
            return
        
        self.is_running = False
        self.stop_time = datetime.now()
        self.stop_reason = reason
        
        # Para threads de monitoramento
        self._stop_monitoring_threads()
        
        # Executa callbacks de parada
        for callback in self.stop_callbacks:
            try:
                callback(reason, description)
            except Exception as e:
                logger.error(f"Erro em callback de parada: {e}")
        
        # Notifica parada
        self._notify_stop(reason, description)
        
        logger.info(f"Controlador parado: {reason.value} - {description}")

    def _start_monitoring_threads(self) -> None:
        """
        Inicia threads de monitoramento.
        """
        # Thread de monitoramento de limites
        self.monitor_thread = threading.Thread(
            target=self._monitor_limits,
            daemon=True
        )
        self.monitor_thread.start()
        
        # Thread de coleta de métricas
        if self.duration_config["enable_resource_monitoring"]:
            self.metrics_thread = threading.Thread(
                target=self._collect_metrics,
                daemon=True
            )
            self.metrics_thread.start()

    def _stop_monitoring_threads(self) -> None:
        """
        Para threads de monitoramento.
        """
        # As threads são daemon, então param automaticamente quando o programa principal para

    def _monitor_limits(self) -> None:
        """
        Monitora limites de duração.
        """
        while self.is_running:
            try:
                # Verifica cada limite ativo
                for limit_id, limit in self.active_limits.items():
                    if self._check_limit_violation(limit):
                        self._trigger_stop_condition(limit)
                
                # Aguarda antes da próxima verificação
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Erro no monitoramento de limites: {e}")
                time.sleep(5)

    def _collect_metrics(self) -> None:
        """
        Coleta métricas de recursos.
        """
        while self.is_running:
            try:
                # Atualiza métricas
                self._update_metrics()
                
                # Adiciona ao histórico
                if self.duration_metrics:
                    self.metrics_history.append(self.duration_metrics)
                
                # Executa callbacks de métricas
                for callback in self.metric_callbacks:
                    try:
                        callback(self.duration_metrics)
                    except Exception as e:
                        logger.error(f"Erro em callback de métricas: {e}")
                
                # Aguarda antes da próxima coleta
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Erro na coleta de métricas: {e}")
                time.sleep(10)

    def _update_metrics(self) -> None:
        """
        Atualiza métricas atuais.
        """
        if not self.duration_metrics:
            return
        
        current_time = datetime.now()
        
        # Calcula tempo decorrido
        elapsed = (current_time - self.duration_metrics.start_time).total_seconds()
        
        # Coleta métricas de sistema
        memory_usage = psutil.virtual_memory().percent
        cpu_usage = psutil.cpu_percent(interval=1)
        
        # Calcula taxa de erro
        total_requests = self.duration_metrics.requests_completed + self.duration_metrics.requests_failed
        error_rate = self.duration_metrics.requests_failed / total_requests if total_requests > 0 else 0.0
        
        # Calcula score de eficiência
        efficiency_score = self._calculate_efficiency_score()
        
        # Atualiza métricas
        self.duration_metrics.current_time = current_time
        self.duration_metrics.elapsed_seconds = elapsed
        self.duration_metrics.memory_usage_mb = memory_usage
        self.duration_metrics.cpu_usage_percent = cpu_usage
        self.duration_metrics.error_rate = error_rate
        self.duration_metrics.efficiency_score = efficiency_score

    def _calculate_efficiency_score(self) -> float:
        """
        Calcula score de eficiência baseado em múltiplos fatores.
        """
        if not self.duration_metrics:
            return 1.0
        
        # Fatores de eficiência
        factors = []
        
        # Fator de tempo (quanto mais tempo, menor a eficiência)
        if self.duration_metrics.elapsed_seconds > 0:
            time_factor = min(1.0, 3600 / self.duration_metrics.elapsed_seconds)  # Normalizado para 1 hora
            factors.append(time_factor)
        
        # Fator de memória (quanto menos memória, melhor)
        memory_factor = max(0.0, 1.0 - (self.duration_metrics.memory_usage_mb / 100))
        factors.append(memory_factor)
        
        # Fator de CPU (quanto menos CPU, melhor)
        cpu_factor = max(0.0, 1.0 - (self.duration_metrics.cpu_usage_percent / 100))
        factors.append(cpu_factor)
        
        # Fator de erro (quanto menos erros, melhor)
        error_factor = 1.0 - self.duration_metrics.error_rate
        factors.append(error_factor)
        
        # Fator de throughput (quanto mais requisições por segundo, melhor)
        if self.duration_metrics.elapsed_seconds > 0:
            throughput = self.duration_metrics.requests_completed / self.duration_metrics.elapsed_seconds
            throughput_factor = min(1.0, throughput / 100)  # Normalizado para 100 req/s
            factors.append(throughput_factor)
        
        # Calcula média ponderada
        if factors:
            return sum(factors) / len(factors)
        else:
            return 1.0

    def _check_limit_violation(self, limit: DurationLimit) -> bool:
        """
        Verifica se um limite foi violado.
        """
        if not self.duration_metrics:
            return False
        
        try:
            if limit.limit_type == DurationLimitType.TIME_BASED:
                # Converte para segundos se necessário
                if limit.unit == "minutes":
                    max_seconds = limit.value * 60
                elif limit.unit == "hours":
                    max_seconds = limit.value * 3600
                else:
                    max_seconds = limit.value
                
                return self.duration_metrics.elapsed_seconds >= max_seconds
            
            elif limit.limit_type == DurationLimitType.REQUEST_BASED:
                total_requests = self.duration_metrics.requests_completed + self.duration_metrics.requests_failed
                return total_requests >= limit.value
            
            elif limit.limit_type == DurationLimitType.MEMORY_BASED:
                return self.duration_metrics.memory_usage_mb >= limit.value
            
            elif limit.limit_type == DurationLimitType.CPU_BASED:
                return self.duration_metrics.cpu_usage_percent >= limit.value
            
            elif limit.limit_type == DurationLimitType.ERROR_BASED:
                return self.duration_metrics.error_rate >= (limit.value / 100)
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao verificar limite {limit.limit_id}: {e}")
            return False

    def _trigger_stop_condition(self, limit: DurationLimit) -> None:
        """
        Dispara condição de parada.
        """
        # Mapeia tipo de limite para razão de parada
        reason_mapping = {
            DurationLimitType.TIME_BASED: StopReason.TIME_LIMIT,
            DurationLimitType.REQUEST_BASED: StopReason.REQUEST_LIMIT,
            DurationLimitType.MEMORY_BASED: StopReason.MEMORY_LIMIT,
            DurationLimitType.CPU_BASED: StopReason.CPU_LIMIT,
            DurationLimitType.ERROR_BASED: StopReason.ERROR_LIMIT
        }
        
        stop_reason = reason_mapping.get(limit.limit_type, StopReason.CUSTOM_CONDITION)
        
        # Cria condição de parada
        condition = StopCondition(
            condition_id=f"condition_{int(time.time())}",
            limit_id=limit.limit_id,
            triggered=True,
            trigger_time=datetime.now(),
            trigger_value=self._get_current_value(limit),
            stop_reason=stop_reason,
            description=f"Limite {limit.limit_id} violado: {limit.description}"
        )
        
        self.triggered_conditions.append(condition)
        
        # Para o controlador
        self.stop(stop_reason, condition.description)

    def _get_current_value(self, limit: DurationLimit) -> float:
        """
        Obtém valor atual para um limite.
        """
        if not self.duration_metrics:
            return 0.0
        
        if limit.limit_type == DurationLimitType.TIME_BASED:
            return self.duration_metrics.elapsed_seconds
        elif limit.limit_type == DurationLimitType.REQUEST_BASED:
            return self.duration_metrics.requests_completed + self.duration_metrics.requests_failed
        elif limit.limit_type == DurationLimitType.MEMORY_BASED:
            return self.duration_metrics.memory_usage_mb
        elif limit.limit_type == DurationLimitType.CPU_BASED:
            return self.duration_metrics.cpu_usage_percent
        elif limit.limit_type == DurationLimitType.ERROR_BASED:
            return self.duration_metrics.error_rate * 100
        
        return 0.0

    def update_request_metrics(self, completed: int = 0, failed: int = 0) -> None:
        """
        Atualiza métricas de requisições.
        """
        if self.duration_metrics:
            self.duration_metrics.requests_completed += completed
            self.duration_metrics.requests_failed += failed

    def add_stop_callback(self, callback: Callable) -> None:
        """
        Adiciona callback para eventos de parada.
        """
        self.stop_callbacks.append(callback)

    def add_metric_callback(self, callback: Callable) -> None:
        """
        Adiciona callback para eventos de métricas.
        """
        self.metric_callbacks.append(callback)

    def _notify_stop(self, reason: StopReason, description: str) -> None:
        """
        Notifica parada através dos canais configurados.
        """
        if not self.duration_config["enable_notifications"]:
            return
        
        message = f"Teste parado: {reason.value} - {description}"
        
        for channel in self.duration_config["notification_channels"]:
            try:
                if channel == "console":
                    logger.warning(message)
                elif channel == "log":
                    self._log_notification(message)
                elif channel == "file":
                    self._file_notification(message)
            except Exception as e:
                logger.error(f"Erro ao enviar notificação via {channel}: {e}")

    def _log_notification(self, message: str) -> None:
        """
        Registra notificação no log.
        """
        logger.info(f"[NOTIFICATION] {message}")

    def _file_notification(self, message: str) -> None:
        """
        Salva notificação em arquivo.
        """
        try:
            notification_file = self.output_dir / "notifications.log"
            with open(notification_file, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} - {message}\n")
        except Exception as e:
            logger.error(f"Erro ao salvar notificação em arquivo: {e}")

    def get_current_metrics(self) -> DurationMetrics:
        """
        Obtém métricas atuais.
        """
        return self.duration_metrics

    def get_metrics_history(self) -> List[DurationMetrics]:
        """
        Obtém histórico de métricas.
        """
        return self.metrics_history.copy()

    def get_triggered_conditions(self) -> List[StopCondition]:
        """
        Obtém condições de parada disparadas.
        """
        return self.triggered_conditions.copy()

    def analyze_efficiency(self) -> Dict[str, Any]:
        """
        Analisa eficiência do teste.
        """
        if not self.metrics_history:
            return {"error": "Nenhuma métrica disponível"}
        
        try:
            # Calcula estatísticas
            efficiency_scores = [m.efficiency_score for m in self.metrics_history]
            memory_usage = [m.memory_usage_mb for m in self.metrics_history]
            cpu_usage = [m.cpu_usage_percent for m in self.metrics_history]
            error_rates = [m.error_rate for m in self.metrics_history]
            
            analysis = {
                "total_duration_seconds": self.metrics_history[-1].elapsed_seconds if self.metrics_history else 0,
                "average_efficiency": np.mean(efficiency_scores),
                "min_efficiency": np.min(efficiency_scores),
                "max_efficiency": np.max(efficiency_scores),
                "average_memory_usage": np.mean(memory_usage),
                "peak_memory_usage": np.max(memory_usage),
                "average_cpu_usage": np.mean(cpu_usage),
                "peak_cpu_usage": np.max(cpu_usage),
                "average_error_rate": np.mean(error_rates),
                "peak_error_rate": np.max(error_rates),
                "total_requests": sum(m.requests_completed + m.requests_failed for m in self.metrics_history),
                "successful_requests": sum(m.requests_completed for m in self.metrics_history),
                "failed_requests": sum(m.requests_failed for m in self.metrics_history),
                "requests_per_second": self._calculate_requests_per_second(),
                "stop_reason": self.stop_reason.value if self.stop_reason else None,
                "triggered_conditions": len(self.triggered_conditions)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erro ao analisar eficiência: {e}")
            return {"error": str(e)}

    def _calculate_requests_per_second(self) -> float:
        """
        Calcula requisições por segundo.
        """
        if not self.metrics_history:
            return 0.0
        
        total_requests = sum(m.requests_completed + m.requests_failed for m in self.metrics_history)
        total_time = self.metrics_history[-1].elapsed_seconds
        
        return total_requests / total_time if total_time > 0 else 0.0

    def generate_duration_report(self) -> str:
        """
        Gera relatório de duração.
        """
        try:
            report_file = self.output_dir / f"duration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Controle de Duração - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                
                if self.duration_metrics:
                    f.write(f"- **Duração total:** {self.duration_metrics.elapsed_seconds:.2f} segundos\n")
                    f.write(f"- **Requisições completadas:** {self.duration_metrics.requests_completed:,}\n")
                    f.write(f"- **Requisições falharam:** {self.duration_metrics.requests_failed:,}\n")
                    f.write(f"- **Taxa de erro:** {self.duration_metrics.error_rate:.2%}\n")
                    f.write(f"- **Score de eficiência:** {self.duration_metrics.efficiency_score:.3f}\n")
                    f.write(f"- **Razão da parada:** {self.stop_reason.value if self.stop_reason else 'N/A'}\n\n")
                
                f.write("## Limites Configurados\n\n")
                
                f.write("| ID | Tipo | Valor | Unidade | Status |\n")
                f.write("|----|------|-------|---------|--------|\n")
                
                for limit in self.duration_limits:
                    status = "Ativo" if limit.enabled else "Inativo"
                    f.write(f"| {limit.limit_id} | {limit.limit_type.value} | {limit.value} | {limit.unit} | {status} |\n")
                
                f.write("\n## Análise de Eficiência\n\n")
                
                efficiency_analysis = self.analyze_efficiency()
                if "error" not in efficiency_analysis:
                    f.write(f"- **Eficiência média:** {efficiency_analysis['average_efficiency']:.3f}\n")
                    f.write(f"- **Uso médio de memória:** {efficiency_analysis['average_memory_usage']:.1f}%\n")
                    f.write(f"- **Uso médio de CPU:** {efficiency_analysis['average_cpu_usage']:.1f}%\n")
                    f.write(f"- **Requisições por segundo:** {efficiency_analysis['requests_per_second']:.2f}\n")
                    f.write(f"- **Taxa de erro média:** {efficiency_analysis['average_error_rate']:.2%}\n\n")
                else:
                    f.write(f"Erro na análise: {efficiency_analysis['error']}\n\n")
                
                f.write("## Condições de Parada Disparadas\n\n")
                
                if self.triggered_conditions:
                    f.write("| ID | Limite | Razão | Valor | Tempo |\n")
                    f.write("|----|--------|-------|-------|-------|\n")
                    
                    for condition in self.triggered_conditions:
                        f.write(f"| {condition.condition_id} | {condition.limit_id} | {condition.stop_reason.value} | {condition.trigger_value:.2f} | {condition.trigger_time.strftime('%H:%M:%S')} |\n")
                else:
                    f.write("Nenhuma condição de parada foi disparada.\n")
                
                f.write("\n## Configurações\n\n")
                f.write(f"- **Parada automática:** {self.duration_config['auto_stop']}\n")
                f.write(f"- **Notificações:** {self.duration_config['enable_notifications']}\n")
                f.write(f"- **Análise de eficiência:** {self.duration_config['enable_efficiency_analysis']}\n")
                f.write(f"- **Monitoramento de recursos:** {self.duration_config['enable_resource_monitoring']}\n")
                f.write(f"- **Parada graciosa:** {self.duration_config['enable_graceful_shutdown']}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório de duração gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório de duração: {e}")
            return ""


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Enhanced Duration Controller...")
    
    controller = EnhancedDurationController()
    
    try:
        # Adiciona callback de exemplo
        def stop_callback(reason, description):
            logger.info(f"Callback de parada executado: {reason.value} - {description}")
        
        controller.add_stop_callback(stop_callback)
        
        # Inicia controlador
        controller.start()
        
        # Simula execução de teste
        logger.info("Simulando execução de teste...")
        
        for i in range(100):
            if not controller.is_running:
                break
            
            # Simula requisições
            controller.update_request_metrics(completed=10, failed=1)
            
            # Aguarda um pouco
            await asyncio.sleep(1)
            
            # Log a cada 10 iterações
            if i % 10 == 0:
                metrics = controller.get_current_metrics()
                logger.info(f"Iteração {i}: {metrics.requests_completed} req, {metrics.elapsed_seconds:.1f}s")
        
        # Para controlador
        controller.stop(StopReason.MANUAL, "Teste concluído")
        
        # Analisa eficiência
        efficiency = controller.analyze_efficiency()
        logger.info(f"Análise de eficiência: {efficiency}")
        
        # Gera relatório
        report_file = controller.generate_duration_report()
        
        logger.info("Enhanced Duration Controller testado com sucesso!")
        logger.info(f"Relatório: {report_file}")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 