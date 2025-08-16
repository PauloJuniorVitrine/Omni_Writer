"""
Hash-based Audit Trail System
=============================

Sistema para cálculo de hash SHA-256 em logs críticos com chain linking.

Tracing ID: HASH_AUDIT_20250127_001
Prompt: checklist_integracao_externa.md - Item 13
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:20:00Z

Baseado em:
- NIST Cybersecurity Framework - Audit and Accountability
- ISO/IEC 27001 - Information Security Management
- Blockchain-like Chain Linking - Immutable Audit Trails
- Cryptographic Hash Functions - SHA-256 Standard
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from threading import Lock
import os

from shared.config import Config
from shared.feature_flags import FeatureFlags


class LogSeverity(Enum):
    """Severidade do log para determinação de criticidade."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HashValidationStatus(Enum):
    """Status da validação de hash."""
    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    PENDING = "pending"


@dataclass
class AuditEntry:
    """Entrada de auditoria com hash."""
    entry_id: str
    timestamp: datetime
    service_name: str
    log_level: LogSeverity
    message: str
    context: Dict[str, Any]
    original_hash: str
    chain_hash: str
    previous_hash: Optional[str]
    tracing_id: str
    environment: str
    
    # Metadados de validação
    validation_status: HashValidationStatus
    validation_timestamp: Optional[datetime]
    validation_attempts: int
    
    # Flags de criticidade
    is_critical: bool
    requires_chain_validation: bool


@dataclass
class ChainValidationResult:
    """Resultado da validação de chain."""
    chain_id: str
    start_timestamp: datetime
    end_timestamp: datetime
    total_entries: int
    valid_entries: int
    invalid_entries: int
    broken_links: List[str]
    integrity_score: float
    validation_status: HashValidationStatus
    recommendations: List[str]


class HashAuditTrail:
    """
    Sistema de auditoria baseado em hash para logs críticos.
    
    Características:
    - Hash SHA-256 para cada log crítico
    - Chain linking para garantir sequência imutável
    - Validação automática de integridade
    - Detecção de modificações não autorizadas
    - Integração com sistema de logging existente
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Inicializa o sistema de auditoria por hash."""
        self.config = config or Config()
        self.feature_flags = FeatureFlags()
        
        # Configuração de criticidade
        self.critical_log_levels = {
            LogSeverity.ERROR,
            LogSeverity.CRITICAL
        }
        
        # Serviços críticos que sempre precisam de hash
        self.critical_services = {
            "stripe_payment_service",
            "openai_generation_service", 
            "user_authentication_service",
            "financial_impact_estimator",
            "sla_compliance_checker",
            "circuit_breaker_metrics"
        }
        
        # Palavras-chave que indicam criticidade
        self.critical_keywords = {
            "payment", "authentication", "authorization", "security",
            "compliance", "sla", "violation", "breach", "incident",
            "error", "failure", "timeout", "circuit_open", "retry"
        }
        
        # Storage de entradas de auditoria
        self.audit_entries: Dict[str, AuditEntry] = {}
        self.entry_lock = Lock()
        
        # Chain linking
        self.current_chain_hash = self._generate_initial_hash()
        self.chain_lock = Lock()
        
        # Cache de validação
        self.validation_cache: Dict[str, HashValidationStatus] = {}
        self.cache_lock = Lock()
        
        # Logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Configurações
        self.hash_algorithm = "sha256"
        self.chain_validation_interval = 300  # 5 minutos
        self.max_validation_attempts = 3
        
        # Inicializar se feature flag ativo
        if self.feature_flags.is_enabled("hash_audit_trail"):
            self._initialize_audit_system()
    
    def _generate_initial_hash(self) -> str:
        """Gera hash inicial para chain linking."""
        initial_data = f"OMNI_WRITER_AUDIT_CHAIN_{int(time.time())}"
        return hashlib.sha256(initial_data.encode()).hexdigest()
    
    def _initialize_audit_system(self):
        """Inicializa o sistema de auditoria."""
        self.logger.info("Sistema de auditoria por hash inicializado")
        
        # Criar diretório de auditoria se não existir
        audit_dir = self.config.get("hash_audit.storage_path", "logs/audit")
        os.makedirs(audit_dir, exist_ok=True)
    
    def is_critical_log(
        self, 
        service_name: str, 
        log_level: LogSeverity, 
        message: str, 
        context: Dict[str, Any]
    ) -> bool:
        """
        Determina se um log é crítico e precisa de hash.
        
        Args:
            service_name: Nome do serviço
            log_level: Nível do log
            message: Mensagem do log
            context: Contexto adicional
            
        Returns:
            True se o log é crítico
        """
        # Validar falsos positivos
        if self._is_false_positive(service_name, log_level, message):
            return False
        
        # Serviços críticos sempre precisam de hash
        if service_name in self.critical_services:
            return True
        
        # Logs de nível crítico sempre precisam de hash
        if log_level in self.critical_log_levels:
            return True
        
        # Verificar palavras-chave críticas
        message_lower = message.lower()
        if any(keyword in message_lower for keyword in self.critical_keywords):
            return True
        
        # Verificar contexto crítico
        if self._has_critical_context(context):
            return True
        
        return False
    
    def _is_false_positive(
        self, 
        service_name: str, 
        log_level: LogSeverity, 
        message: str
    ) -> bool:
        """Valida se o log é um falso positivo."""
        env = self.config.get("ENVIRONMENT", "development")
        
        # Em desenvolvimento, logs de debug não são críticos
        if env == "development" and log_level == LogSeverity.DEBUG:
            return True
        
        # Serviços de teste não são críticos
        if any(keyword in service_name.lower() for keyword in ["test", "mock", "dev", "staging"]):
            return True
        
        # Mensagens de teste não são críticas
        if any(keyword in message.lower() for keyword in ["test", "mock", "dummy", "fake"]):
            return True
        
        return False
    
    def _has_critical_context(self, context: Dict[str, Any]) -> bool:
        """Verifica se o contexto contém informações críticas."""
        critical_fields = {
            "user_id", "payment_id", "transaction_id", "api_key",
            "authentication", "authorization", "security", "compliance"
        }
        
        context_str = json.dumps(context, sort_keys=True).lower()
        return any(field in context_str for field in critical_fields)
    
    def create_audit_entry(
        self,
        service_name: str,
        log_level: LogSeverity,
        message: str,
        context: Dict[str, Any],
        tracing_id: Optional[str] = None
    ) -> Optional[AuditEntry]:
        """
        Cria entrada de auditoria com hash para log crítico.
        
        Args:
            service_name: Nome do serviço
            log_level: Nível do log
            message: Mensagem do log
            context: Contexto adicional
            tracing_id: ID de rastreamento
            
        Returns:
            AuditEntry se o log é crítico, None caso contrário
        """
        # Verificar se é log crítico
        if not self.is_critical_log(service_name, log_level, message, context):
            return None
        
        tracing_id = tracing_id or f"audit_{int(time.time())}"
        entry_id = f"entry_{int(time.time())}_{hash(service_name) % 10000}"
        timestamp = datetime.utcnow()
        
        # Gerar hash do conteúdo
        content = {
            "service_name": service_name,
            "log_level": log_level.value,
            "message": message,
            "context": context,
            "timestamp": timestamp.isoformat(),
            "tracing_id": tracing_id
        }
        
        content_json = json.dumps(content, sort_keys=True)
        original_hash = hashlib.sha256(content_json.encode()).hexdigest()
        
        # Gerar chain hash
        with self.chain_lock:
            chain_data = f"{self.current_chain_hash}:{original_hash}:{timestamp.isoformat()}"
            chain_hash = hashlib.sha256(chain_data.encode()).hexdigest()
            previous_hash = self.current_chain_hash
            self.current_chain_hash = chain_hash
        
        # Criar entrada de auditoria
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            service_name=service_name,
            log_level=log_level,
            message=message,
            context=context,
            original_hash=original_hash,
            chain_hash=chain_hash,
            previous_hash=previous_hash,
            tracing_id=tracing_id,
            environment=self.config.get("ENVIRONMENT", "unknown"),
            validation_status=HashValidationStatus.PENDING,
            validation_timestamp=None,
            validation_attempts=0,
            is_critical=True,
            requires_chain_validation=True
        )
        
        # Armazenar entrada
        with self.entry_lock:
            self.audit_entries[entry_id] = entry
        
        # Log da criação
        self.logger.info(
            f"Entrada de auditoria criada: {entry_id} - Hash: {original_hash[:8]}...",
            extra={
                "tracing_id": tracing_id,
                "entry_id": entry_id,
                "service_name": service_name,
                "log_level": log_level.value,
                "original_hash": original_hash,
                "chain_hash": chain_hash
            }
        )
        
        return entry
    
    def validate_entry_integrity(self, entry_id: str) -> bool:
        """
        Valida a integridade de uma entrada de auditoria.
        
        Args:
            entry_id: ID da entrada
            
        Returns:
            True se a integridade é válida
        """
        with self.entry_lock:
            if entry_id not in self.audit_entries:
                return False
            
            entry = self.audit_entries[entry_id]
        
        # Verificar se já foi validada recentemente
        with self.cache_lock:
            if entry_id in self.validation_cache:
                return self.validation_cache[entry_id] == HashValidationStatus.VALID
        
        # Reconstruir conteúdo
        content = {
            "service_name": entry.service_name,
            "log_level": entry.log_level.value,
            "message": entry.message,
            "context": entry.context,
            "timestamp": entry.timestamp.isoformat(),
            "tracing_id": entry.tracing_id
        }
        
        content_json = json.dumps(content, sort_keys=True)
        current_hash = hashlib.sha256(content_json.encode()).hexdigest()
        
        # Validar hash original
        is_valid = current_hash == entry.original_hash
        
        # Atualizar status
        with self.entry_lock:
            entry.validation_status = (
                HashValidationStatus.VALID if is_valid 
                else HashValidationStatus.INVALID
            )
            entry.validation_timestamp = datetime.utcnow()
            entry.validation_attempts += 1
        
        # Cache resultado
        with self.cache_lock:
            self.validation_cache[entry_id] = entry.validation_status
        
        # Log da validação
        if is_valid:
            self.logger.debug(f"Validação de integridade OK: {entry_id}")
        else:
            self.logger.warning(
                f"Violação de integridade detectada: {entry_id}",
                extra={
                    "tracing_id": entry.tracing_id,
                    "entry_id": entry_id,
                    "expected_hash": entry.original_hash,
                    "current_hash": current_hash
                }
            )
        
        return is_valid
    
    def validate_chain_integrity(
        self, 
        start_timestamp: Optional[datetime] = None,
        end_timestamp: Optional[datetime] = None
    ) -> ChainValidationResult:
        """
        Valida a integridade de uma cadeia de entradas.
        
        Args:
            start_timestamp: Timestamp inicial (opcional)
            end_timestamp: Timestamp final (opcional)
            
        Returns:
            ChainValidationResult com resultado da validação
        """
        # Filtrar entradas por período
        with self.entry_lock:
            entries = list(self.audit_entries.values())
        
        if start_timestamp:
            entries = [e for e in entries if e.timestamp >= start_timestamp]
        if end_timestamp:
            entries = [e for e in entries if e.timestamp <= end_timestamp]
        
        # Ordenar por timestamp
        entries.sort(key=lambda e: e.timestamp)
        
        if not entries:
            return ChainValidationResult(
                chain_id=f"chain_{int(time.time())}",
                start_timestamp=start_timestamp or datetime.utcnow(),
                end_timestamp=end_timestamp or datetime.utcnow(),
                total_entries=0,
                valid_entries=0,
                invalid_entries=0,
                broken_links=[],
                integrity_score=1.0,
                validation_status=HashValidationStatus.VALID,
                recommendations=["Nenhuma entrada encontrada no período"]
            )
        
        # Validar cada entrada
        valid_entries = 0
        invalid_entries = 0
        broken_links = []
        
        for i, entry in enumerate(entries):
            # Validar integridade individual
            if self.validate_entry_integrity(entry.entry_id):
                valid_entries += 1
            else:
                invalid_entries += 1
                broken_links.append(entry.entry_id)
            
            # Validar chain link (exceto primeira entrada)
            if i > 0:
                previous_entry = entries[i - 1]
                expected_chain_data = f"{previous_entry.chain_hash}:{entry.original_hash}:{entry.timestamp.isoformat()}"
                expected_chain_hash = hashlib.sha256(expected_chain_data.encode()).hexdigest()
                
                if entry.chain_hash != expected_chain_hash:
                    broken_links.append(f"chain_link_{entry.entry_id}")
        
        # Calcular score de integridade
        total_entries = len(entries)
        integrity_score = valid_entries / total_entries if total_entries > 0 else 1.0
        
        # Determinar status geral
        if invalid_entries == 0 and not broken_links:
            validation_status = HashValidationStatus.VALID
        elif integrity_score > 0.8:
            validation_status = HashValidationStatus.VALID
        else:
            validation_status = HashValidationStatus.INVALID
        
        # Gerar recomendações
        recommendations = []
        if invalid_entries > 0:
            recommendations.append(f"Investigar {invalid_entries} entradas com integridade comprometida")
        if broken_links:
            recommendations.append(f"Verificar {len(broken_links)} links de chain quebrados")
        if integrity_score < 0.9:
            recommendations.append("Implementar monitoramento mais rigoroso de integridade")
        
        if not recommendations:
            recommendations.append("Chain de auditoria íntegra")
        
        return ChainValidationResult(
            chain_id=f"chain_{entries[0].timestamp.strftime('%Y%m%d_%H%M%S')}",
            start_timestamp=entries[0].timestamp,
            end_timestamp=entries[-1].timestamp,
            total_entries=total_entries,
            valid_entries=valid_entries,
            invalid_entries=invalid_entries,
            broken_links=broken_links,
            integrity_score=integrity_score,
            validation_status=validation_status,
            recommendations=recommendations
        )
    
    def get_audit_summary(
        self, 
        service_name: Optional[str] = None,
        start_timestamp: Optional[datetime] = None,
        end_timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Obtém resumo das entradas de auditoria.
        
        Args:
            service_name: Filtrar por serviço (opcional)
            start_timestamp: Timestamp inicial (opcional)
            end_timestamp: Timestamp final (opcional)
            
        Returns:
            Dicionário com resumo das entradas
        """
        with self.entry_lock:
            entries = list(self.audit_entries.values())
        
        # Aplicar filtros
        if service_name:
            entries = [e for e in entries if e.service_name == service_name]
        if start_timestamp:
            entries = [e for e in entries if e.timestamp >= start_timestamp]
        if end_timestamp:
            entries = [e for e in entries if e.timestamp <= end_timestamp]
        
        # Estatísticas
        total_entries = len(entries)
        valid_entries = sum(1 for e in entries if e.validation_status == HashValidationStatus.VALID)
        invalid_entries = sum(1 for e in entries if e.validation_status == HashValidationStatus.INVALID)
        
        # Distribuição por serviço
        service_distribution = {}
        for entry in entries:
            service = entry.service_name
            service_distribution[service] = service_distribution.get(service, 0) + 1
        
        # Distribuição por nível de log
        level_distribution = {}
        for entry in entries:
            level = entry.log_level.value
            level_distribution[level] = level_distribution.get(level, 0) + 1
        
        # Entradas mais recentes
        recent_entries = sorted(entries, key=lambda e: e.timestamp, reverse=True)[:10]
        
        return {
            "total_entries": total_entries,
            "valid_entries": valid_entries,
            "invalid_entries": invalid_entries,
            "integrity_score": valid_entries / total_entries if total_entries > 0 else 1.0,
            "service_distribution": service_distribution,
            "level_distribution": level_distribution,
            "recent_entries": [
                {
                    "entry_id": e.entry_id,
                    "timestamp": e.timestamp.isoformat(),
                    "service_name": e.service_name,
                    "log_level": e.log_level.value,
                    "validation_status": e.validation_status.value
                }
                for e in recent_entries
            ],
            "period": {
                "start": start_timestamp.isoformat() if start_timestamp else None,
                "end": end_timestamp.isoformat() if end_timestamp else None
            }
        }
    
    def export_audit_data(
        self, 
        format: str = "json",
        include_hashes: bool = True,
        start_timestamp: Optional[datetime] = None,
        end_timestamp: Optional[datetime] = None
    ) -> str:
        """
        Exporta dados de auditoria.
        
        Args:
            format: Formato de exportação (json, csv)
            include_hashes: Incluir hashes na exportação
            start_timestamp: Timestamp inicial (opcional)
            end_timestamp: Timestamp final (opcional)
            
        Returns:
            Dados exportados em string
        """
        with self.entry_lock:
            entries = list(self.audit_entries.values())
        
        # Aplicar filtros de tempo
        if start_timestamp:
            entries = [e for e in entries if e.timestamp >= start_timestamp]
        if end_timestamp:
            entries = [e for e in entries if e.timestamp <= end_timestamp]
        
        # Ordenar por timestamp
        entries.sort(key=lambda e: e.timestamp)
        
        if format.lower() == "json":
            data = {
                "audit_entries": [
                    {
                        "entry_id": e.entry_id,
                        "timestamp": e.timestamp.isoformat(),
                        "service_name": e.service_name,
                        "log_level": e.log_level.value,
                        "message": e.message,
                        "context": e.context,
                        "tracing_id": e.tracing_id,
                        "environment": e.environment,
                        "validation_status": e.validation_status.value,
                        "validation_timestamp": e.validation_timestamp.isoformat() if e.validation_timestamp else None,
                        "validation_attempts": e.validation_attempts,
                        "is_critical": e.is_critical,
                        "requires_chain_validation": e.requires_chain_validation,
                        **({"original_hash": e.original_hash, "chain_hash": e.chain_hash} if include_hashes else {})
                    }
                    for e in entries
                ],
                "export_metadata": {
                    "export_timestamp": datetime.utcnow().isoformat(),
                    "total_entries": len(entries),
                    "include_hashes": include_hashes,
                    "format": "json"
                }
            }
            return json.dumps(data, indent=2)
        
        elif format.lower() == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            headers = [
                "entry_id", "timestamp", "service_name", "log_level", "message",
                "tracing_id", "environment", "validation_status", "validation_attempts",
                "is_critical"
            ]
            if include_hashes:
                headers.extend(["original_hash", "chain_hash"])
            
            writer.writerow(headers)
            
            # Dados
            for entry in entries:
                row = [
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.service_name,
                    entry.log_level.value,
                    entry.message,
                    entry.tracing_id,
                    entry.environment,
                    entry.validation_status.value,
                    entry.validation_attempts,
                    entry.is_critical
                ]
                if include_hashes:
                    row.extend([entry.original_hash, entry.chain_hash])
                
                writer.writerow(row)
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Formato não suportado: {format}")
    
    def cleanup_old_entries(self, days_to_keep: int = 30):
        """
        Remove entradas antigas para economizar espaço.
        
        Args:
            days_to_keep: Número de dias para manter entradas
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        with self.entry_lock:
            old_entries = [
                entry_id for entry_id, entry in self.audit_entries.items()
                if entry.timestamp < cutoff_date
            ]
            
            for entry_id in old_entries:
                del self.audit_entries[entry_id]
        
        # Limpar cache de validação
        with self.cache_lock:
            for entry_id in old_entries:
                if entry_id in self.validation_cache:
                    del self.validation_cache[entry_id]
        
        self.logger.info(f"Removidas {len(old_entries)} entradas antigas de auditoria")
    
    def get_entry_by_id(self, entry_id: str) -> Optional[AuditEntry]:
        """Obtém entrada de auditoria por ID."""
        with self.entry_lock:
            return self.audit_entries.get(entry_id)
    
    def search_entries(
        self,
        service_name: Optional[str] = None,
        log_level: Optional[LogSeverity] = None,
        message_pattern: Optional[str] = None,
        tracing_id: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditEntry]:
        """
        Busca entradas de auditoria com filtros.
        
        Args:
            service_name: Filtrar por serviço
            log_level: Filtrar por nível de log
            message_pattern: Padrão para buscar na mensagem
            tracing_id: Filtrar por tracing ID
            limit: Limite de resultados
            
        Returns:
            Lista de entradas que correspondem aos filtros
        """
        with self.entry_lock:
            entries = list(self.audit_entries.values())
        
        # Aplicar filtros
        if service_name:
            entries = [e for e in entries if e.service_name == service_name]
        if log_level:
            entries = [e for e in entries if e.log_level == log_level]
        if message_pattern:
            entries = [e for e in entries if message_pattern.lower() in e.message.lower()]
        if tracing_id:
            entries = [e for e in entries if e.tracing_id == tracing_id]
        
        # Ordenar por timestamp (mais recentes primeiro)
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        
        return entries[:limit]


# Instância global
hash_audit_trail = HashAuditTrail() 