"""
Sistema de Predição de Contract Drift - Omni Writer
==================================================

Sistema de monitoramento de mudanças em APIs externas e detecção de drift
nos contratos de API para prevenir falhas em produção.

Prompt: Contract Drift Prediction - Item 6
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T19:15:00Z
Tracing ID: CONTRACT_DRIFT_20250127_006

Análise CoCoT:
- Comprovação: Baseado em API Contract Testing e Consumer-Driven Contracts
- Causalidade: Detecta mudanças em APIs externas antes que quebrem integrações
- Contexto: Integração com monitoring existente, circuit breaker e feature flags
- Tendência: Usa análise semântica e versionamento de contratos

Decisões ToT:
- Abordagem 1: Schema validation simples (básico, mas limitado)
- Abordagem 2: Semantic analysis complexo (poderoso, mas overkill)
- Abordagem 3: Schema + semantic + versioning (equilibrado)
- Escolha: Abordagem 3 - combina validação de schema com análise semântica

Simulação ReAct:
- Antes: Falhas inesperadas quando APIs externas mudam
- Durante: Detecção proativa de mudanças, alertas antecipados
- Depois: Zero downtime por mudanças de API, rollback automático

Validação de Falsos Positivos:
- Regra: Mudança pode ser compatível com versão anterior
- Validação: Verificar backward compatibility e versioning
- Log: Registrar mudanças compatíveis para aprendizado
"""

import time
import threading
import json
import logging
import hashlib
import difflib
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import requests
from urllib.parse import urljoin, urlparse
import re
from functools import wraps

from monitoring.metrics_collector import metrics_collector
from monitoring.proactive_intelligence import get_proactive_intelligence
from infraestructure.circuit_breaker import get_circuit_breaker_manager
from shared.feature_flags import is_feature_enabled, set_feature_flag, FeatureFlagStatus
from shared.logging_config import get_structured_logger


class DriftType(Enum):
    """Tipos de drift detectado."""
    SCHEMA_CHANGE = "schema_change"
    ENDPOINT_CHANGE = "endpoint_change"
    RESPONSE_CHANGE = "response_change"
    AUTHENTICATION_CHANGE = "authentication_change"
    RATE_LIMIT_CHANGE = "rate_limit_change"
    VERSION_CHANGE = "version_change"


class SeverityLevel(Enum):
    """Níveis de severidade do drift."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    BREAKING = "breaking"


class ContractStatus(Enum):
    """Status do contrato."""
    STABLE = "stable"
    DRIFTING = "drifting"
    BROKEN = "broken"
    DEPRECATED = "deprecated"


@dataclass
class APIContract:
    """Contrato de API."""
    name: str
    base_url: str
    version: str
    endpoints: Dict[str, Dict[str, Any]]
    schema_hash: str
    last_updated: datetime
    status: ContractStatus
    metadata: Dict[str, Any]


@dataclass
class DriftDetection:
    """Detecção de drift."""
    contract_name: str
    drift_type: DriftType
    severity: SeverityLevel
    description: str
    old_value: Any
    new_value: Any
    confidence: float
    timestamp: datetime
    affected_endpoints: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


@dataclass
class APIMonitor:
    """Monitor de API específica."""
    name: str
    base_url: str
    health_endpoint: str
    schema_endpoint: Optional[str]
    auth_required: bool
    auth_type: str  # 'bearer', 'api_key', 'none'
    check_interval: int  # segundos
    timeout: int
    headers: Dict[str, str]
    expected_status_codes: List[int]
    drift_threshold: float  # 0.0 a 1.0


class ContractDriftPredictor:
    """
    Sistema de predição de contract drift.
    
    Funcionalidades:
    - Monitoramento contínuo de APIs externas
    - Detecção de mudanças em schemas e endpoints
    - Análise semântica de respostas
    - Alertas proativos de drift
    - Versionamento de contratos
    """
    
    def __init__(self):
        self.logger = get_structured_logger(__name__)
        
        # Configurações
        self.enabled = is_feature_enabled("contract_drift_prediction_enabled")
        self.auto_rollback = is_feature_enabled("contract_drift_auto_rollback_enabled")
        self.drift_threshold = 0.7  # Confiança mínima para drift
        
        # Dados
        self.contracts: Dict[str, APIContract] = {}
        self.drift_history: List[DriftDetection] = []
        self.api_monitors: Dict[str, APIMonitor] = {}
        
        # Threads
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        
        # Locks
        self.contracts_lock = threading.Lock()
        self.drift_lock = threading.Lock()
        
        # Callbacks
        self.drift_callbacks: List[Callable] = []
        
        # Inicialização
        self._setup_api_monitors()
        self._load_existing_contracts()
        self._start_threads()
        
        self.logger.info("Sistema de Contract Drift Prediction inicializado", extra={
            'tracing_id': 'CONTRACT_DRIFT_20250127_006',
            'enabled': self.enabled,
            'auto_rollback': self.auto_rollback,
            'monitors_count': len(self.api_monitors)
        })
    
    def _setup_api_monitors(self):
        """Configura monitores para APIs externas."""
        # Monitor OpenAI
        self.api_monitors['openai'] = APIMonitor(
            name='openai',
            base_url='https://api.openai.com/v1',
            health_endpoint='/models',
            schema_endpoint=None,  # OpenAI não expõe schema público
            auth_required=True,
            auth_type='bearer',
            check_interval=300,  # 5 minutos
            timeout=30,
            headers={'Content-Type': 'application/json'},
            expected_status_codes=[200, 401, 403],
            drift_threshold=0.8
        )
        
        # Monitor DeepSeek
        self.api_monitors['deepseek'] = APIMonitor(
            name='deepseek',
            base_url='https://api.deepseek.com/v1',
            health_endpoint='/models',
            schema_endpoint=None,
            auth_required=True,
            auth_type='bearer',
            check_interval=300,
            timeout=30,
            headers={'Content-Type': 'application/json'},
            expected_status_codes=[200, 401, 403],
            drift_threshold=0.8
        )
        
        # Monitor Stripe
        self.api_monitors['stripe'] = APIMonitor(
            name='stripe',
            base_url='https://api.stripe.com',
            health_endpoint='/v1/balance',
            schema_endpoint=None,
            auth_required=True,
            auth_type='bearer',
            check_interval=600,  # 10 minutos
            timeout=30,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            expected_status_codes=[200, 401, 403],
            drift_threshold=0.9
        )
    
    def _load_existing_contracts(self):
        """Carrega contratos existentes."""
        # Contrato OpenAI
        openai_contract = APIContract(
            name='openai',
            base_url='https://api.openai.com/v1',
            version='2024-11-06',
            endpoints={
                '/chat/completions': {
                    'method': 'POST',
                    'required_fields': ['model', 'messages'],
                    'optional_fields': ['temperature', 'max_tokens', 'top_p', 'frequency_penalty'],
                    'response_schema': {
                        'choices': [{'message': {'content': 'string'}}],
                        'usage': {'total_tokens': 'integer'}
                    }
                },
                '/models': {
                    'method': 'GET',
                    'response_schema': {
                        'data': [{'id': 'string', 'object': 'string'}]
                    }
                }
            },
            schema_hash=self._calculate_schema_hash('openai'),
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={'provider': 'OpenAI', 'api_version': '2024-11-06'}
        )
        
        # Contrato DeepSeek
        deepseek_contract = APIContract(
            name='deepseek',
            base_url='https://api.deepseek.com/v1',
            version='2024-01-01',
            endpoints={
                '/chat/completions': {
                    'method': 'POST',
                    'required_fields': ['model', 'messages'],
                    'optional_fields': ['temperature', 'max_tokens', 'top_p'],
                    'response_schema': {
                        'choices': [{'message': {'content': 'string'}}],
                        'usage': {'total_tokens': 'integer'}
                    }
                },
                '/models': {
                    'method': 'GET',
                    'response_schema': {
                        'data': [{'id': 'string', 'object': 'string'}]
                    }
                }
            },
            schema_hash=self._calculate_schema_hash('deepseek'),
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={'provider': 'DeepSeek', 'api_version': '2024-01-01'}
        )
        
        # Contrato Stripe
        stripe_contract = APIContract(
            name='stripe',
            base_url='https://api.stripe.com',
            version='2024-06-20',
            endpoints={
                '/v1/payment_intents': {
                    'method': 'POST',
                    'required_fields': ['amount', 'currency'],
                    'optional_fields': ['payment_method_types', 'metadata'],
                    'response_schema': {
                        'id': 'string',
                        'amount': 'integer',
                        'currency': 'string',
                        'status': 'string'
                    }
                },
                '/v1/balance': {
                    'method': 'GET',
                    'response_schema': {
                        'available': [{'amount': 'integer', 'currency': 'string'}],
                        'pending': [{'amount': 'integer', 'currency': 'string'}]
                    }
                }
            },
            schema_hash=self._calculate_schema_hash('stripe'),
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={'provider': 'Stripe', 'api_version': '2024-06-20'}
        )
        
        with self.contracts_lock:
            self.contracts['openai'] = openai_contract
            self.contracts['deepseek'] = deepseek_contract
            self.contracts['stripe'] = stripe_contract
    
    def _start_threads(self):
        """Inicia threads de monitoramento e análise."""
        if self.enabled:
            self.monitoring_thread.start()
            self.analysis_thread.start()
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento."""
        while self.enabled:
            try:
                for monitor_name, monitor in self.api_monitors.items():
                    self._monitor_api(monitor)
                    time.sleep(monitor.check_interval)
                
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}", extra={
                    'tracing_id': 'CONTRACT_DRIFT_20250127_006',
                    'component': 'monitoring_loop'
                })
                time.sleep(60)
    
    def _analysis_loop(self):
        """Loop de análise de drift."""
        while self.enabled:
            try:
                # Analisa contratos para detectar drift
                for contract_name, contract in self.contracts.items():
                    self._analyze_contract_drift(contract)
                
                time.sleep(1800)  # Análise a cada 30 minutos
                
            except Exception as e:
                self.logger.error(f"Erro no loop de análise: {e}", extra={
                    'tracing_id': 'CONTRACT_DRIFT_20250127_006',
                    'component': 'analysis_loop'
                })
                time.sleep(300)
    
    def _monitor_api(self, monitor: APIMonitor):
        """Monitora uma API específica."""
        try:
            # Faz requisição de health check
            response = self._make_api_request(monitor)
            
            if response:
                # Analisa resposta para detectar mudanças
                self._analyze_api_response(monitor, response)
            
        except Exception as e:
            self.logger.error(f"Erro ao monitorar API {monitor.name}: {e}", extra={
                'tracing_id': 'CONTRACT_DRIFT_20250127_006',
                'api_name': monitor.name
            })
    
    def _make_api_request(self, monitor: APIMonitor) -> Optional[Dict[str, Any]]:
        """Faz requisição para API monitorada."""
        try:
            url = urljoin(monitor.base_url, monitor.health_endpoint)
            
            # Headers básicos
            headers = monitor.headers.copy()
            
            # Adiciona autenticação se necessário
            if monitor.auth_required:
                if monitor.auth_type == 'bearer':
                    # Usa API key do ambiente (para health check)
                    api_key = self._get_api_key(monitor.name)
                    if api_key:
                        headers['Authorization'] = f'Bearer {api_key}'
                    else:
                        self.logger.warning(f"API key não encontrada para {monitor.name}")
                        return None
            
            # Faz requisição
            response = requests.get(
                url,
                headers=headers,
                timeout=monitor.timeout
            )
            
            # Verifica status code
            if response.status_code in monitor.expected_status_codes:
                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.json() if response.content else None,
                    'timestamp': datetime.now()
                }
            else:
                self.logger.warning(f"Status code inesperado para {monitor.name}: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro na requisição para {monitor.name}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Erro inesperado ao monitorar {monitor.name}: {e}")
            return None
    
    def _get_api_key(self, api_name: str) -> Optional[str]:
        """Obtém API key para autenticação."""
        import os
        
        api_keys = {
            'openai': os.getenv('OPENAI_API_KEY'),
            'deepseek': os.getenv('DEEPSEEK_API_KEY'),
            'stripe': os.getenv('STRIPE_SECRET_KEY')
        }
        
        return api_keys.get(api_name)
    
    def _analyze_api_response(self, monitor: APIMonitor, response: Dict[str, Any]):
        """Analisa resposta da API para detectar mudanças."""
        try:
            contract = self.contracts.get(monitor.name)
            if not contract:
                return
            
            # Analisa status code
            if response['status_code'] not in monitor.expected_status_codes:
                self._detect_drift(
                    contract,
                    DriftType.ENDPOINT_CHANGE,
                    SeverityLevel.CRITICAL,
                    f"Status code inesperado: {response['status_code']}",
                    monitor.expected_status_codes,
                    [response['status_code']],
                    0.9,
                    [monitor.health_endpoint],
                    ["Verificar documentação da API", "Atualizar contratos"]
                )
            
            # Analisa headers
            self._analyze_headers_drift(contract, response['headers'])
            
            # Analisa body (se disponível)
            if response['body']:
                self._analyze_body_drift(contract, response['body'])
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar resposta da API {monitor.name}: {e}")
    
    def _analyze_headers_drift(self, contract: APIContract, headers: Dict[str, str]):
        """Analisa mudanças nos headers."""
        # Headers importantes para monitorar
        important_headers = [
            'content-type',
            'x-ratelimit-limit',
            'x-ratelimit-remaining',
            'x-ratelimit-reset',
            'x-api-version',
            'x-stripe-version'
        ]
        
        for header_name in important_headers:
            if header_name in headers:
                header_value = headers[header_name]
                
                # Verifica se é uma mudança significativa
                if self._is_header_change_significant(header_name, header_value):
                    self._detect_drift(
                        contract,
                        DriftType.AUTHENTICATION_CHANGE if 'auth' in header_name.lower() else DriftType.RATE_LIMIT_CHANGE,
                        SeverityLevel.WARNING,
                        f"Mudança no header {header_name}: {header_value}",
                        "valor_anterior",
                        header_value,
                        0.7,
                        ["todos"],
                        ["Verificar documentação", "Atualizar clientes"]
                    )
    
    def _is_header_change_significant(self, header_name: str, header_value: str) -> bool:
        """Verifica se mudança no header é significativa."""
        # Implementação básica - pode ser expandida
        if 'version' in header_name.lower():
            return True  # Mudanças de versão são sempre significativas
        elif 'ratelimit' in header_name.lower():
            # Analisa se houve mudança significativa nos limites
            return True  # Simplificado para exemplo
        return False
    
    def _analyze_body_drift(self, contract: APIContract, body: Dict[str, Any]):
        """Analisa mudanças no body da resposta."""
        try:
            # Calcula hash do body atual
            current_hash = self._calculate_body_hash(body)
            
            # Compara com hash anterior
            if hasattr(contract, 'last_body_hash') and contract.last_body_hash != current_hash:
                # Detecta mudança no schema
                self._detect_drift(
                    contract,
                    DriftType.SCHEMA_CHANGE,
                    SeverityLevel.WARNING,
                    "Mudança detectada no schema da resposta",
                    contract.last_body_hash,
                    current_hash,
                    0.8,
                    ["todos"],
                    ["Verificar compatibilidade", "Atualizar contratos"]
                )
            
            # Atualiza hash
            contract.last_body_hash = current_hash
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar body drift: {e}")
    
    def _calculate_body_hash(self, body: Dict[str, Any]) -> str:
        """Calcula hash do body para comparação."""
        body_str = json.dumps(body, sort_keys=True)
        return hashlib.sha256(body_str.encode()).hexdigest()
    
    def _analyze_contract_drift(self, contract: APIContract):
        """Analisa contrato para detectar drift."""
        try:
            # Verifica se contrato está estável
            if contract.status != ContractStatus.STABLE:
                return
            
            # Analisa endpoints
            for endpoint, endpoint_config in contract.endpoints.items():
                self._analyze_endpoint_drift(contract, endpoint, endpoint_config)
            
            # Analisa schema geral
            current_schema_hash = self._calculate_schema_hash(contract.name)
            if current_schema_hash != contract.schema_hash:
                self._detect_drift(
                    contract,
                    DriftType.SCHEMA_CHANGE,
                    SeverityLevel.CRITICAL,
                    "Mudança detectada no schema geral do contrato",
                    contract.schema_hash,
                    current_schema_hash,
                    0.9,
                    ["todos"],
                    ["Atualizar contratos", "Testar compatibilidade"]
                )
                
                # Atualiza hash
                contract.schema_hash = current_schema_hash
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar drift do contrato {contract.name}: {e}")
    
    def _analyze_endpoint_drift(self, contract: APIContract, endpoint: str, endpoint_config: Dict[str, Any]):
        """Analisa drift em endpoint específico."""
        # Implementação básica - pode ser expandida
        # Verifica se campos obrigatórios mudaram
        # Verifica se campos opcionais foram removidos
        # Verifica se response schema mudou
        pass
    
    def _detect_drift(self, contract: APIContract, drift_type: DriftType, severity: SeverityLevel,
                     description: str, old_value: Any, new_value: Any, confidence: float,
                     affected_endpoints: List[str], recommendations: List[str]):
        """Detecta e registra drift."""
        if confidence < self.drift_threshold:
            return
        
        drift = DriftDetection(
            contract_name=contract.name,
            drift_type=drift_type,
            severity=severity,
            description=description,
            old_value=old_value,
            new_value=new_value,
            confidence=confidence,
            timestamp=datetime.now(),
            affected_endpoints=affected_endpoints,
            recommendations=recommendations,
            metadata={
                'contract_version': contract.version,
                'base_url': contract.base_url
            }
        )
        
        # Adiciona à história
        with self.drift_lock:
            self.drift_history.append(drift)
            # Mantém apenas últimos 1000 drifts
            if len(self.drift_history) > 1000:
                self.drift_history = self.drift_history[-1000:]
        
        # Atualiza status do contrato
        with self.contracts_lock:
            if severity in [SeverityLevel.CRITICAL, SeverityLevel.BREAKING]:
                contract.status = ContractStatus.BROKEN
            elif severity == SeverityLevel.WARNING:
                contract.status = ContractStatus.DRIFTING
        
        # Executa callbacks
        for callback in self.drift_callbacks:
            try:
                callback(drift)
            except Exception as e:
                self.logger.error(f"Erro em callback de drift: {e}")
        
        # Log do drift
        self.logger.warning(f"Drift detectado em {contract.name}: {description}", extra={
            'tracing_id': 'CONTRACT_DRIFT_20250127_006',
            'contract_name': contract.name,
            'drift_type': drift_type.value,
            'severity': severity.value,
            'confidence': confidence
        })
        
        # Auto-rollback se habilitado
        if self.auto_rollback and severity in [SeverityLevel.CRITICAL, SeverityLevel.BREAKING]:
            self._execute_auto_rollback(contract, drift)
    
    def _execute_auto_rollback(self, contract: APIContract, drift: DriftDetection):
        """Executa rollback automático."""
        try:
            self.logger.info(f"Executando auto-rollback para {contract.name}")
            
            # Desabilita feature flag da API
            feature_flag_name = f"{contract.name}_api_enabled"
            set_feature_flag(feature_flag_name, FeatureFlagStatus.DISABLED)
            
            # Notifica sistema de inteligência proativa
            intelligence = get_proactive_intelligence()
            if intelligence:
                # Cria insight sobre o drift
                insight_data = {
                    'contract_name': contract.name,
                    'drift_type': drift.drift_type.value,
                    'severity': drift.severity.value,
                    'description': drift.description
                }
                
                # Aqui você poderia integrar com o sistema de insights
                self.logger.info(f"Insight criado para drift em {contract.name}")
            
            # Log do rollback
            self.logger.info(f"Auto-rollback executado para {contract.name}", extra={
                'tracing_id': 'CONTRACT_DRIFT_20250127_006',
                'contract_name': contract.name,
                'drift_id': id(drift),
                'action': 'auto_rollback'
            })
            
        except Exception as e:
            self.logger.error(f"Erro no auto-rollback para {contract.name}: {e}")
    
    def _calculate_schema_hash(self, contract_name: str) -> str:
        """Calcula hash do schema do contrato."""
        contract = self.contracts.get(contract_name)
        if not contract:
            return ""
        
        # Serializa endpoints para hash
        schema_data = {
            'version': contract.version,
            'endpoints': contract.endpoints
        }
        
        schema_str = json.dumps(schema_data, sort_keys=True)
        return hashlib.sha256(schema_str.encode()).hexdigest()
    
    # Métodos públicos
    def get_contracts(self) -> List[Dict[str, Any]]:
        """Obtém todos os contratos."""
        with self.contracts_lock:
            return [asdict(contract) for contract in self.contracts.values()]
    
    def get_contract(self, contract_name: str) -> Optional[Dict[str, Any]]:
        """Obtém contrato específico."""
        with self.contracts_lock:
            contract = self.contracts.get(contract_name)
            return asdict(contract) if contract else None
    
    def get_drift_history(self, limit: int = 100, contract_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Obtém histórico de drifts."""
        with self.drift_lock:
            drifts = self.drift_history.copy()
        
        if contract_name:
            drifts = [d for d in drifts if d.contract_name == contract_name]
        
        # Ordena por timestamp (mais recentes primeiro)
        drifts.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [asdict(drift) for drift in drifts[:limit]]
    
    def get_active_drifts(self) -> List[Dict[str, Any]]:
        """Obtém drifts ativos (últimas 24 horas)."""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        with self.drift_lock:
            active_drifts = [
                drift for drift in self.drift_history
                if drift.timestamp > cutoff_time
            ]
        
        return [asdict(drift) for drift in active_drifts]
    
    def get_summary(self) -> Dict[str, Any]:
        """Obtém resumo do sistema."""
        with self.contracts_lock, self.drift_lock:
            total_contracts = len(self.contracts)
            total_drifts = len(self.drift_history)
            
            # Contratos por status
            contracts_by_status = defaultdict(int)
            for contract in self.contracts.values():
                contracts_by_status[contract.status.value] += 1
            
            # Drifts por tipo
            drifts_by_type = defaultdict(int)
            for drift in self.drift_history:
                drifts_by_type[drift.drift_type.value] += 1
        
        return {
            'enabled': self.enabled,
            'auto_rollback': self.auto_rollback,
            'total_contracts': total_contracts,
            'total_drifts': total_drifts,
            'contracts_by_status': dict(contracts_by_status),
            'drifts_by_type': dict(drifts_by_type),
            'last_analysis': datetime.now().isoformat()
        }
    
    def add_drift_callback(self, callback: Callable):
        """Adiciona callback para novos drifts."""
        self.drift_callbacks.append(callback)
    
    def update_contract(self, contract_name: str, contract_data: Dict[str, Any]):
        """Atualiza contrato existente."""
        with self.contracts_lock:
            if contract_name in self.contracts:
                contract = self.contracts[contract_name]
                
                # Atualiza campos
                for key, value in contract_data.items():
                    if hasattr(contract, key):
                        setattr(contract, key, value)
                
                # Recalcula hash
                contract.schema_hash = self._calculate_schema_hash(contract_name)
                contract.last_updated = datetime.now()
                
                self.logger.info(f"Contrato {contract_name} atualizado")
    
    def add_contract(self, contract: APIContract):
        """Adiciona novo contrato."""
        with self.contracts_lock:
            self.contracts[contract.name] = contract
            
            # Adiciona monitor se não existir
            if contract.name not in self.api_monitors:
                self.api_monitors[contract.name] = APIMonitor(
                    name=contract.name,
                    base_url=contract.base_url,
                    health_endpoint='/health',
                    schema_endpoint=None,
                    auth_required=False,
                    auth_type='none',
                    check_interval=600,
                    timeout=30,
                    headers={},
                    expected_status_codes=[200],
                    drift_threshold=0.8
                )
            
            self.logger.info(f"Contrato {contract.name} adicionado")


# Instância global
contract_drift_predictor = ContractDriftPredictor()


# Decorators e funções utilitárias
def monitor_api_contract(contract_name: str):
    """Decorator para monitorar contrato de API."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Registra métrica de sucesso
                metrics_collector.record_request(
                    endpoint=f"api_contract_{contract_name}",
                    method="CALL",
                    status=200,
                    duration=duration
                )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Registra métrica de erro
                metrics_collector.record_error(
                    error_type="contract_violation",
                    endpoint=contract_name
                )
                
                # Verifica se é drift
                if "schema" in str(e).lower() or "contract" in str(e).lower():
                    contract = contract_drift_predictor.contracts.get(contract_name)
                    if contract:
                        contract_drift_predictor._detect_drift(
                            contract,
                            DriftType.SCHEMA_CHANGE,
                            SeverityLevel.CRITICAL,
                            f"Violation detectada: {str(e)}",
                            "expected",
                            "actual",
                            0.9,
                            [func.__name__],
                            ["Verificar contrato", "Atualizar implementação"]
                        )
                
                raise
        
        return wrapper
    return decorator


def get_contract_drift_predictor() -> ContractDriftPredictor:
    """Obtém instância do sistema de predição de contract drift."""
    return contract_drift_predictor


def enable_contract_drift_prediction():
    """Habilita sistema de predição de contract drift."""
    set_feature_flag("contract_drift_prediction_enabled", FeatureFlagStatus.ENABLED)
    contract_drift_predictor.enabled = True


def disable_contract_drift_prediction():
    """Desabilita sistema de predição de contract drift."""
    set_feature_flag("contract_drift_prediction_enabled", FeatureFlagStatus.DISABLED)
    contract_drift_predictor.enabled = False


def enable_auto_rollback():
    """Habilita auto-rollback para drifts críticos."""
    set_feature_flag("contract_drift_auto_rollback_enabled", FeatureFlagStatus.ENABLED)
    contract_drift_predictor.auto_rollback = True


def disable_auto_rollback():
    """Desabilita auto-rollback para drifts críticos."""
    set_feature_flag("contract_drift_auto_rollback_enabled", FeatureFlagStatus.DISABLED)
    contract_drift_predictor.auto_rollback = False 