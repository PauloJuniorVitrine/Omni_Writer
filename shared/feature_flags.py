"""
Feature Flags System - Omni Writer
==================================

Sistema de feature flags para controle granular de funcionalidades de integração.
Implementa padrões de Feature Toggle e Continuous Delivery para rollouts seguros.

Prompt: Feature Flags para Integrações - Item 2
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T16:20:00Z
Tracing ID: FEATURE_FLAGS_20250127_002

Análise CoCoT:
- Comprovação: Baseado em Feature Toggle Patterns (Martin Fowler) e Continuous Delivery
- Causalidade: Permite rollouts graduais, A/B testing e rollback rápido sem deploy
- Contexto: Integração com sistema existente de configuração e logging
- Tendência: Usa Redis para persistência distribuída e env vars para configuração

Decisões ToT:
- Abordagem 1: Env vars (simples, mas limitado)
- Abordagem 2: Redis (distribuído, mas complexo)
- Abordagem 3: Database (persistente, mas lento)
- Escolha: Híbrido - env vars para defaults, Redis para runtime, database para audit

Simulação ReAct:
- Antes: Funcionalidades hardcoded, rollback requer deploy
- Durante: Rollout gradual, monitoramento de métricas, rollback instantâneo
- Depois: Maior agilidade, menor risco, melhor observabilidade

Validação de Falsos Positivos:
- Regra: Feature flag pode ser desnecessária se funcionalidade é sempre ativa
- Validação: Verificar uso real da flag antes de bloquear
- Log: Registrar quando flag é sempre true/false para otimização
"""

import os
import json
import logging
import threading
from typing import Dict, Any, Optional, List, Union, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from contextlib import contextmanager
import redis
from functools import wraps

# Configuração de logging estruturado
feature_logger = logging.getLogger("feature_flags")
feature_logger.setLevel(logging.INFO)

# Configurações
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
FEATURE_FLAGS_PREFIX = "feature_flags:"
FEATURE_FLAGS_DEFAULT_TTL = 3600  # 1 hora
FEATURE_FLAGS_AUDIT_TTL = 86400 * 7  # 7 dias

# Verificação de disponibilidade do Redis
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
except Exception as e:
    feature_logger.warning(f"Redis não disponível para feature flags: {e}")
    REDIS_AVAILABLE = False
    redis_client = None


class FeatureFlagType(Enum):
    """Tipos de feature flags."""
    RELEASE = "release"  # Rollout gradual
    EXPERIMENT = "experiment"  # A/B testing
    OPERATIONAL = "operational"  # Controle operacional
    PERMISSION = "permission"  # Controle de acesso


class FeatureFlagStatus(Enum):
    """Status de feature flags."""
    ENABLED = "enabled"
    DISABLED = "disabled"
    PARTIAL = "partial"  # Rollout parcial


@dataclass
class FeatureFlagConfig:
    """Configuração de uma feature flag."""
    name: str
    type: FeatureFlagType
    status: FeatureFlagStatus
    description: str
    percentage: float = 100.0  # Porcentagem de usuários (0-100)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    conditions: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = {}
        if self.metadata is None:
            self.metadata = {}
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()


@dataclass
class FeatureFlagAudit:
    """Auditoria de uso de feature flags."""
    flag_name: str
    user_id: Optional[str]
    session_id: Optional[str]
    enabled: bool
    timestamp: datetime
    context: Dict[str, Any]
    trace_id: Optional[str] = None


class FeatureFlagsManager:
    """
    Gerenciador central de feature flags.
    
    Funcionalidades:
    - Controle granular de funcionalidades
    - Rollout gradual com porcentagens
    - A/B testing com métricas
    - Rollback instantâneo
    - Auditoria completa de uso
    - Integração com sistema de logging
    """
    
    def __init__(self):
        self.flags: Dict[str, FeatureFlagConfig] = {}
        self.audit_log: List[FeatureFlagAudit] = []
        self.audit_lock = threading.Lock()
        self.flags_lock = threading.Lock()
        
        # Configurações
        self.enabled = os.getenv('FEATURE_FLAGS_ENABLED', 'true').lower() == 'true'
        self.audit_enabled = os.getenv('FEATURE_FLAGS_AUDIT_ENABLED', 'true').lower() == 'true'
        self.max_audit_log_size = int(os.getenv('FEATURE_FLAGS_MAX_AUDIT_SIZE', '10000'))
        
        # Carrega flags padrão
        self._load_default_flags()
        
        # Carrega flags do ambiente
        self._load_environment_flags()
        
        # Carrega flags do Redis se disponível
        if REDIS_AVAILABLE:
            self._load_redis_flags()
        
        feature_logger.info(f"FeatureFlagsManager inicializado | flags={len(self.flags)} | audit={self.audit_enabled}")
    
    def _load_default_flags(self):
        """Carrega feature flags padrão do sistema."""
        default_flags = {
            # Flags de integração externa
            "stripe_payment_enabled": FeatureFlagConfig(
                name="stripe_payment_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita integração com Stripe para pagamentos",
                percentage=0.0
            ),
            "service_mesh_enabled": FeatureFlagConfig(
                name="service_mesh_enabled",
                type=FeatureFlagType.OPERATIONAL,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita awareness de service mesh (Istio/Linkerd)",
                percentage=0.0
            ),
            "proactive_intelligence_enabled": FeatureFlagConfig(
                name="proactive_intelligence_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita inteligência proativa e mitigação automática",
                percentage=0.0
            ),
            "contract_drift_prediction_enabled": FeatureFlagConfig(
                name="contract_drift_prediction_enabled",
                type=FeatureFlagType.OPERATIONAL,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita predição de drift em contratos de API",
                percentage=0.0
            ),
            "multi_region_enabled": FeatureFlagConfig(
                name="multi_region_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita suporte multi-região",
                percentage=0.0
            ),
            
            # Flags de performance
            "advanced_caching_enabled": FeatureFlagConfig(
                name="advanced_caching_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.ENABLED,
                description="Habilita cache avançado com ML",
                percentage=100.0
            ),
            "parallel_processing_enabled": FeatureFlagConfig(
                name="parallel_processing_enabled",
                type=FeatureFlagType.OPERATIONAL,
                status=FeatureFlagStatus.ENABLED,
                description="Habilita processamento paralelo",
                percentage=100.0
            ),
            
            # Flags de segurança
            "enhanced_security_enabled": FeatureFlagConfig(
                name="enhanced_security_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.ENABLED,
                description="Habilita recursos de segurança avançados",
                percentage=100.0
            ),
            "rate_limiting_strict_enabled": FeatureFlagConfig(
                name="rate_limiting_strict_enabled",
                type=FeatureFlagType.OPERATIONAL,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita rate limiting mais restritivo",
                percentage=0.0
            ),
            
            # Flags de monitoramento
            "detailed_metrics_enabled": FeatureFlagConfig(
                name="detailed_metrics_enabled",
                type=FeatureFlagType.OPERATIONAL,
                status=FeatureFlagStatus.ENABLED,
                description="Habilita métricas detalhadas",
                percentage=100.0
            ),
            "circuit_breaker_metrics_enabled": FeatureFlagConfig(
                name="circuit_breaker_metrics_enabled",
                type=FeatureFlagType.RELEASE,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita métricas detalhadas de circuit breakers",
                percentage=0.0
            ),
            
            # Flags de experimentação
            "new_ui_enabled": FeatureFlagConfig(
                name="new_ui_enabled",
                type=FeatureFlagType.EXPERIMENT,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita nova interface de usuário",
                percentage=0.0
            ),
            "ml_optimization_enabled": FeatureFlagConfig(
                name="ml_optimization_enabled",
                type=FeatureFlagType.EXPERIMENT,
                status=FeatureFlagStatus.DISABLED,
                description="Habilita otimização baseada em ML",
                percentage=0.0
            )
        }
        
        with self.flags_lock:
            self.flags.update(default_flags)
    
    def _load_environment_flags(self):
        """Carrega feature flags do ambiente."""
        for key, value in os.environ.items():
            if key.startswith('FEATURE_FLAG_'):
                flag_name = key[13:].lower()  # Remove 'FEATURE_FLAG_' prefix
                
                # Parse do valor
                if value.lower() in ['true', '1', 'enabled']:
                    status = FeatureFlagStatus.ENABLED
                    percentage = 100.0
                elif value.lower() in ['false', '0', 'disabled']:
                    status = FeatureFlagStatus.DISABLED
                    percentage = 0.0
                else:
                    # Tenta parsear como porcentagem
                    try:
                        percentage = float(value)
                        status = FeatureFlagStatus.PARTIAL if percentage < 100 else FeatureFlagStatus.ENABLED
                    except ValueError:
                        continue
                
                # Cria ou atualiza flag
                if flag_name in self.flags:
                    self.flags[flag_name].status = status
                    self.flags[flag_name].percentage = percentage
                    self.flags[flag_name].updated_at = datetime.utcnow()
                else:
                    self.flags[flag_name] = FeatureFlagConfig(
                        name=flag_name,
                        type=FeatureFlagType.RELEASE,
                        status=status,
                        description=f"Feature flag carregada do ambiente: {flag_name}",
                        percentage=percentage
                    )
    
    def _load_redis_flags(self):
        """Carrega feature flags do Redis."""
        try:
            keys = redis_client.keys(f"{FEATURE_FLAGS_PREFIX}*")
            for key in keys:
                flag_name = key[len(FEATURE_FLAGS_PREFIX):]
                flag_data = redis_client.get(key)
                
                if flag_data:
                    try:
                        flag_dict = json.loads(flag_data)
                        flag_config = FeatureFlagConfig(
                            name=flag_dict.get('name', flag_name),
                            type=FeatureFlagType(flag_dict.get('type', 'release')),
                            status=FeatureFlagStatus(flag_dict.get('status', 'disabled')),
                            description=flag_dict.get('description', ''),
                            percentage=flag_dict.get('percentage', 0.0),
                            conditions=flag_dict.get('conditions', {}),
                            metadata=flag_dict.get('metadata', {}),
                            created_at=datetime.fromisoformat(flag_dict.get('created_at', datetime.utcnow().isoformat())),
                            updated_at=datetime.fromisoformat(flag_dict.get('updated_at', datetime.utcnow().isoformat()))
                        )
                        
                        with self.flags_lock:
                            self.flags[flag_name] = flag_config
                            
                    except (json.JSONDecodeError, ValueError) as e:
                        feature_logger.warning(f"Erro ao carregar flag {flag_name} do Redis: {e}")
                        
        except Exception as e:
            feature_logger.error(f"Erro ao carregar flags do Redis: {e}")
    
    def is_enabled(self, flag_name: str, user_id: Optional[str] = None, 
                   session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Verifica se uma feature flag está habilitada.
        
        Args:
            flag_name: Nome da feature flag
            user_id: ID do usuário (opcional)
            session_id: ID da sessão (opcional)
            context: Contexto adicional (opcional)
            
        Returns:
            True se a flag está habilitada, False caso contrário
        """
        if not self.enabled:
            return False
        
        with self.flags_lock:
            flag = self.flags.get(flag_name)
            
            if not flag:
                # Flag não encontrada - comportamento conservador
                self._audit_flag_usage(flag_name, user_id, session_id, False, context)
                return False
            
            # Verifica se a flag está dentro do período válido
            now = datetime.utcnow()
            if flag.start_date and now < flag.start_date:
                self._audit_flag_usage(flag_name, user_id, session_id, False, context)
                return False
            
            if flag.end_date and now > flag.end_date:
                self._audit_flag_usage(flag_name, user_id, session_id, False, context)
                return False
            
            # Verifica status da flag
            if flag.status == FeatureFlagStatus.DISABLED:
                self._audit_flag_usage(flag_name, user_id, session_id, False, context)
                return False
            
            if flag.status == FeatureFlagStatus.ENABLED:
                self._audit_flag_usage(flag_name, user_id, session_id, True, context)
                return True
            
            # Status PARTIAL - verifica porcentagem
            if flag.status == FeatureFlagStatus.PARTIAL:
                enabled = self._check_percentage(flag, user_id, session_id)
                self._audit_flag_usage(flag_name, user_id, session_id, enabled, context)
                return enabled
            
            # Comportamento conservador
            self._audit_flag_usage(flag_name, user_id, session_id, False, context)
            return False
    
    def _check_percentage(self, flag: FeatureFlagConfig, user_id: Optional[str], 
                         session_id: Optional[str]) -> bool:
        """Verifica se usuário/sessão está na porcentagem habilitada."""
        if flag.percentage >= 100.0:
            return True
        
        if flag.percentage <= 0.0:
            return False
        
        # Usa user_id ou session_id para determinar consistência
        identifier = user_id or session_id or "anonymous"
        
        # Hash simples para distribuição consistente
        hash_value = hash(identifier + flag.name) % 100
        return hash_value < flag.percentage
    
    def _audit_flag_usage(self, flag_name: str, user_id: Optional[str], 
                         session_id: Optional[str], enabled: bool, 
                         context: Optional[Dict[str, Any]]):
        """Registra uso de feature flag para auditoria."""
        if not self.audit_enabled:
            return
        
        audit_entry = FeatureFlagAudit(
            flag_name=flag_name,
            user_id=user_id,
            session_id=session_id,
            enabled=enabled,
            timestamp=datetime.utcnow(),
            context=context or {},
            trace_id=context.get('trace_id') if context else None
        )
        
        with self.audit_lock:
            self.audit_log.append(audit_entry)
            
            # Limita tamanho do log
            if len(self.audit_log) > self.max_audit_log_size:
                self.audit_log = self.audit_log[-self.max_audit_log_size:]
            
            # Salva no Redis se disponível
            if REDIS_AVAILABLE:
                self._save_audit_to_redis(audit_entry)
    
    def _save_audit_to_redis(self, audit_entry: FeatureFlagAudit):
        """Salva entrada de auditoria no Redis."""
        try:
            audit_key = f"feature_audit:{audit_entry.flag_name}:{audit_entry.timestamp.isoformat()}"
            audit_data = {
                'flag_name': audit_entry.flag_name,
                'user_id': audit_entry.user_id,
                'session_id': audit_entry.session_id,
                'enabled': audit_entry.enabled,
                'timestamp': audit_entry.timestamp.isoformat(),
                'context': audit_entry.context,
                'trace_id': audit_entry.trace_id
            }
            
            redis_client.setex(
                audit_key,
                FEATURE_FLAGS_AUDIT_TTL,
                json.dumps(audit_data)
            )
            
        except Exception as e:
            feature_logger.error(f"Erro ao salvar auditoria no Redis: {e}")
    
    def set_flag(self, flag_name: str, status: FeatureFlagStatus, 
                 percentage: float = 100.0, description: str = None):
        """Define uma feature flag."""
        with self.flags_lock:
            if flag_name in self.flags:
                flag = self.flags[flag_name]
                flag.status = status
                flag.percentage = percentage
                flag.updated_at = datetime.utcnow()
                if description:
                    flag.description = description
            else:
                flag = FeatureFlagConfig(
                    name=flag_name,
                    type=FeatureFlagType.RELEASE,
                    status=status,
                    description=description or f"Feature flag: {flag_name}",
                    percentage=percentage
                )
                self.flags[flag_name] = flag
            
            # Salva no Redis se disponível
            if REDIS_AVAILABLE:
                self._save_flag_to_redis(flag)
            
            feature_logger.info(f"Feature flag atualizada | {flag_name}={status.value} | percentage={percentage}")
    
    def _save_flag_to_redis(self, flag: FeatureFlagConfig):
        """Salva feature flag no Redis."""
        try:
            flag_key = f"{FEATURE_FLAGS_PREFIX}{flag.name}"
            flag_data = asdict(flag)
            
            # Converte enums para strings
            flag_data['type'] = flag.type.value
            flag_data['status'] = flag.status.value
            flag_data['created_at'] = flag.created_at.isoformat()
            flag_data['updated_at'] = flag.updated_at.isoformat()
            
            redis_client.setex(
                flag_key,
                FEATURE_FLAGS_DEFAULT_TTL,
                json.dumps(flag_data)
            )
            
        except Exception as e:
            feature_logger.error(f"Erro ao salvar flag no Redis: {e}")
    
    def get_flag(self, flag_name: str) -> Optional[FeatureFlagConfig]:
        """Retorna configuração de uma feature flag."""
        with self.flags_lock:
            return self.flags.get(flag_name)
    
    def get_all_flags(self) -> Dict[str, FeatureFlagConfig]:
        """Retorna todas as feature flags."""
        with self.flags_lock:
            return self.flags.copy()
    
    def get_audit_log(self, flag_name: Optional[str] = None, 
                     limit: int = 100) -> List[FeatureFlagAudit]:
        """Retorna log de auditoria."""
        with self.audit_lock:
            if flag_name:
                filtered_log = [entry for entry in self.audit_log if entry.flag_name == flag_name]
            else:
                filtered_log = self.audit_log.copy()
            
            return filtered_log[-limit:]
    
    def get_usage_stats(self, flag_name: str, hours: int = 24) -> Dict[str, Any]:
        """Retorna estatísticas de uso de uma feature flag."""
        since = datetime.utcnow() - timedelta(hours=hours)
        
        with self.audit_lock:
            recent_entries = [
                entry for entry in self.audit_log 
                if entry.flag_name == flag_name and entry.timestamp >= since
            ]
        
        if not recent_entries:
            return {
                'total_checks': 0,
                'enabled_count': 0,
                'disabled_count': 0,
                'enabled_percentage': 0.0
            }
        
        total_checks = len(recent_entries)
        enabled_count = sum(1 for entry in recent_entries if entry.enabled)
        disabled_count = total_checks - enabled_count
        enabled_percentage = (enabled_count / total_checks) * 100
        
        return {
            'total_checks': total_checks,
            'enabled_count': enabled_count,
            'disabled_count': disabled_count,
            'enabled_percentage': enabled_percentage,
            'period_hours': hours
        }


# Instância global
feature_flags_manager = FeatureFlagsManager()


def feature_flag(flag_name: str, user_id: Optional[str] = None, 
                session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
    """
    Decorator para feature flags.
    
    Args:
        flag_name: Nome da feature flag
        user_id: ID do usuário (opcional)
        session_id: ID da sessão (opcional)
        context: Contexto adicional (opcional)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extrai user_id e session_id dos argumentos se disponível
            extracted_user_id = user_id
            extracted_session_id = session_id
            extracted_context = context or {}
            
            # Tenta extrair de kwargs
            if extracted_user_id is None:
                extracted_user_id = kwargs.get('user_id')
            if extracted_session_id is None:
                extracted_session_id = kwargs.get('session_id')
            
            # Verifica se feature flag está habilitada
            if feature_flags_manager.is_enabled(
                flag_name, 
                extracted_user_id, 
                extracted_session_id, 
                extracted_context
            ):
                return func(*args, **kwargs)
            else:
                # Comportamento quando flag está desabilitada
                feature_logger.info(f"Feature flag desabilitada | {flag_name} | function={func.__name__}")
                return None
        
        return wrapper
    return decorator


def require_feature_flag(flag_name: str, user_id: Optional[str] = None, 
                        session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
    """
    Decorator que requer feature flag habilitada, senão levanta exceção.
    
    Args:
        flag_name: Nome da feature flag
        user_id: ID do usuário (opcional)
        session_id: ID da sessão (opcional)
        context: Contexto adicional (opcional)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extrai user_id e session_id dos argumentos se disponível
            extracted_user_id = user_id
            extracted_session_id = session_id
            extracted_context = context or {}
            
            # Tenta extrair de kwargs
            if extracted_user_id is None:
                extracted_user_id = kwargs.get('user_id')
            if extracted_session_id is None:
                extracted_session_id = kwargs.get('session_id')
            
            # Verifica se feature flag está habilitada
            if feature_flags_manager.is_enabled(
                flag_name, 
                extracted_user_id, 
                extracted_session_id, 
                extracted_context
            ):
                return func(*args, **kwargs)
            else:
                # Levanta exceção quando flag está desabilitada
                raise FeatureFlagDisabledError(f"Feature flag '{flag_name}' is disabled")
        
        return wrapper
    return decorator


class FeatureFlagDisabledError(Exception):
    """Exceção lançada quando feature flag está desabilitada."""
    pass


# Funções de conveniência
def is_feature_enabled(flag_name: str, user_id: Optional[str] = None, 
                      session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> bool:
    """Verifica se feature flag está habilitada."""
    return feature_flags_manager.is_enabled(flag_name, user_id, session_id, context)


def set_feature_flag(flag_name: str, status: FeatureFlagStatus, 
                    percentage: float = 100.0, description: str = None):
    """Define uma feature flag."""
    feature_flags_manager.set_flag(flag_name, status, percentage, description)


def get_feature_flag(flag_name: str) -> Optional[FeatureFlagConfig]:
    """Retorna configuração de uma feature flag."""
    return feature_flags_manager.get_flag(flag_name)


def get_all_feature_flags() -> Dict[str, FeatureFlagConfig]:
    """Retorna todas as feature flags."""
    return feature_flags_manager.get_all_flags()


def get_feature_usage_stats(flag_name: str, hours: int = 24) -> Dict[str, Any]:
    """Retorna estatísticas de uso de uma feature flag."""
    return feature_flags_manager.get_usage_stats(flag_name, hours) 