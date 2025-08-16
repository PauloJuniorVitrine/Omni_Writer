"""
Multi-Region Adapter - Omni Writer
==================================

Sistema de preparação para compliance local multi-região com suporte
a diferentes jurisdições, data residency e configurações regionais.

Prompt: Multi-Region Readiness - Item 10
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T21:00:00Z
Tracing ID: MULTI_REGION_READINESS_20250127_010

Análise CoCoT:
- Comprovação: Baseado em GDPR, LGPD, CCPA e Data Residency Requirements
- Causalidade: Necessário para compliance com regulamentações locais e data residency
- Contexto: Integração com service mesh e sistema distribuído existente
- Tendência: Usa configuração dinâmica e detecção automática de região

Decisões ToT:
- Abordagem 1: Configuração estática por região (simples, mas inflexível)
- Abordagem 2: Service discovery dinâmico (flexível, mas complexo)
- Abordagem 3: Configuração híbrida com fallback (equilibrada)
- Escolha: Abordagem 3 - melhor relação flexibilidade vs complexidade

Simulação ReAct:
- Antes: Sistema sem awareness de região e compliance local
- Durante: Detecção automática de região e configuração dinâmica
- Depois: Compliance automático com regulamentações locais

Validação de Falsos Positivos:
- Regra: Detecção de região pode ser incorreta em ambientes de desenvolvimento
- Validação: Verificar se é ambiente real ou de desenvolvimento
- Log: Registrar quando detecção é incorreta para aprendizado
"""

import os
import json
import time
import logging
import requests
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import ipaddress
import geoip2.database
import geoip2.errors

from shared.logger import get_structured_logger
from shared.feature_flags import FeatureFlagsManager
from infraestructure.service_mesh_adapter import ServiceMeshAdapter, ServiceMeshConfig

logger = get_structured_logger(__name__)

# Feature flags para controle granular
FEATURE_FLAGS = FeatureFlagsManager()

class RegionType(Enum):
    """Tipos de região suportados"""
    NORTH_AMERICA = "north_america"
    SOUTH_AMERICA = "south_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    AFRICA = "africa"
    MIDDLE_EAST = "middle_east"
    UNKNOWN = "unknown"

class ComplianceFramework(Enum):
    """Frameworks de compliance suportados"""
    GDPR = "gdpr"  # General Data Protection Regulation (EU)
    LGPD = "lgpd"  # Lei Geral de Proteção de Dados (Brasil)
    CCPA = "ccpa"  # California Consumer Privacy Act (EUA)
    PIPEDA = "pipeda"  # Personal Information Protection and Electronic Documents Act (Canadá)
    PDPA = "pdpa"  # Personal Data Protection Act (Singapura)
    POPIA = "popia"  # Protection of Personal Information Act (África do Sul)
    NONE = "none"

class DataResidencyLevel(Enum):
    """Níveis de data residency"""
    STRICT = "strict"  # Dados devem permanecer na região
    FLEXIBLE = "flexible"  # Dados podem ser processados em outras regiões
    NONE = "none"  # Sem restrições

@dataclass
class RegionConfig:
    """Configuração específica de região"""
    region_code: str
    region_name: str
    region_type: RegionType
    compliance_frameworks: List[ComplianceFramework]
    data_residency: DataResidencyLevel
    storage_location: str
    processing_location: str
    backup_location: Optional[str] = None
    retention_period_days: int = 2555  # 7 anos padrão
    encryption_required: bool = True
    audit_logging_required: bool = True
    data_export_allowed: bool = True
    data_deletion_required: bool = True

@dataclass
class MultiRegionConfig:
    """Configuração global multi-região"""
    default_region: str = "us-east-1"
    auto_detection_enabled: bool = True
    fallback_region: str = "us-east-1"
    geoip_database_path: Optional[str] = None
    service_mesh_integration: bool = True
    compliance_strict_mode: bool = True
    audit_all_operations: bool = True
    regions: Dict[str, RegionConfig] = field(default_factory=dict)

@dataclass
class RegionDetectionResult:
    """Resultado da detecção de região"""
    detected_region: str
    confidence: float
    detection_method: str
    ip_address: Optional[str] = None
    geoip_data: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.now)

class MultiRegionAdapter:
    """
    Adapter para preparação multi-região
    
    Funcionalidades:
    - Detecção automática de região
    - Configuração de compliance por região
    - Data residency enforcement
    - Integração com service mesh
    - Audit logging regional
    - Fallback para regiões não suportadas
    """
    
    def __init__(self, config: MultiRegionConfig, tracing_id: str = None):
        self.config = config
        self.tracing_id = tracing_id or f"MULTI_REGION_{int(time.time())}"
        
        # GeoIP database
        self.geoip_reader = None
        if config.geoip_database_path and os.path.exists(config.geoip_database_path):
            try:
                self.geoip_reader = geoip2.database.Reader(config.geoip_database_path)
                logger.info(f"[{self.tracing_id}] GeoIP database carregada: {config.geoip_database_path}")
            except Exception as e:
                logger.warning(f"[{self.tracing_id}] Erro ao carregar GeoIP database: {e}")
        
        # Service mesh integration
        self.service_mesh_adapter = None
        if config.service_mesh_integration:
            service_config = ServiceMeshConfig(
                mesh_type=ServiceMeshType.NONE,
                service_name="multi-region-adapter",
                service_version="1.0.0",
                namespace="multi-region"
            )
            self.service_mesh_adapter = ServiceMeshAdapter(service_config, self.tracing_id)
        
        # Cache de detecção de região
        self._region_cache = {}
        self._cache_ttl = 3600  # 1 hora
        
        # Inicializa configurações padrão
        self._initialize_default_regions()
        
        logger.info(f"[{self.tracing_id}] Multi-Region Adapter inicializado")
    
    def _initialize_default_regions(self):
        """Inicializa configurações padrão de regiões"""
        if not self.config.regions:
            self.config.regions = {
                # América do Norte
                "us-east-1": RegionConfig(
                    region_code="us-east-1",
                    region_name="US East (N. Virginia)",
                    region_type=RegionType.NORTH_AMERICA,
                    compliance_frameworks=[ComplianceFramework.CCPA],
                    data_residency=DataResidencyLevel.FLEXIBLE,
                    storage_location="us-east-1",
                    processing_location="us-east-1",
                    backup_location="us-west-2",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=True,
                    data_deletion_required=True
                ),
                "us-west-2": RegionConfig(
                    region_code="us-west-2",
                    region_name="US West (Oregon)",
                    region_type=RegionType.NORTH_AMERICA,
                    compliance_frameworks=[ComplianceFramework.CCPA],
                    data_residency=DataResidencyLevel.FLEXIBLE,
                    storage_location="us-west-2",
                    processing_location="us-west-2",
                    backup_location="us-east-1",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=True,
                    data_deletion_required=True
                ),
                
                # Europa
                "eu-west-1": RegionConfig(
                    region_code="eu-west-1",
                    region_name="Europe (Ireland)",
                    region_type=RegionType.EUROPE,
                    compliance_frameworks=[ComplianceFramework.GDPR],
                    data_residency=DataResidencyLevel.STRICT,
                    storage_location="eu-west-1",
                    processing_location="eu-west-1",
                    backup_location="eu-central-1",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=False,
                    data_deletion_required=True
                ),
                "eu-central-1": RegionConfig(
                    region_code="eu-central-1",
                    region_name="Europe (Frankfurt)",
                    region_type=RegionType.EUROPE,
                    compliance_frameworks=[ComplianceFramework.GDPR],
                    data_residency=DataResidencyLevel.STRICT,
                    storage_location="eu-central-1",
                    processing_location="eu-central-1",
                    backup_location="eu-west-1",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=False,
                    data_deletion_required=True
                ),
                
                # América do Sul
                "sa-east-1": RegionConfig(
                    region_code="sa-east-1",
                    region_name="South America (São Paulo)",
                    region_type=RegionType.SOUTH_AMERICA,
                    compliance_frameworks=[ComplianceFramework.LGPD],
                    data_residency=DataResidencyLevel.STRICT,
                    storage_location="sa-east-1",
                    processing_location="sa-east-1",
                    backup_location="us-east-1",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=False,
                    data_deletion_required=True
                ),
                
                # Ásia-Pacífico
                "ap-southeast-1": RegionConfig(
                    region_code="ap-southeast-1",
                    region_name="Asia Pacific (Singapore)",
                    region_type=RegionType.ASIA_PACIFIC,
                    compliance_frameworks=[ComplianceFramework.PDPA],
                    data_residency=DataResidencyLevel.STRICT,
                    storage_location="ap-southeast-1",
                    processing_location="ap-southeast-1",
                    backup_location="ap-southeast-2",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=False,
                    data_deletion_required=True
                ),
                
                # África
                "af-south-1": RegionConfig(
                    region_code="af-south-1",
                    region_name="Africa (Cape Town)",
                    region_type=RegionType.AFRICA,
                    compliance_frameworks=[ComplianceFramework.POPIA],
                    data_residency=DataResidencyLevel.STRICT,
                    storage_location="af-south-1",
                    processing_location="af-south-1",
                    backup_location="eu-west-1",
                    retention_period_days=2555,
                    encryption_required=True,
                    audit_logging_required=True,
                    data_export_allowed=False,
                    data_deletion_required=True
                )
            }
    
    def detect_region(self, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> RegionDetectionResult:
        """
        Detecta região baseado em IP e outros fatores
        
        Args:
            ip_address: Endereço IP do usuário
            user_agent: User agent do navegador
            
        Returns:
            Resultado da detecção de região
        """
        if not FEATURE_FLAGS.is_enabled("multi_region_enabled"):
            return RegionDetectionResult(
                detected_region=self.config.default_region,
                confidence=1.0,
                detection_method="feature_flag_disabled"
            )
        
        # Verifica cache
        cache_key = f"{ip_address}:{user_agent}"
        if cache_key in self._region_cache:
            cached_result = self._region_cache[cache_key]
            if time.time() - cached_result['timestamp'] < self._cache_ttl:
                return cached_result['result']
        
        # Métodos de detecção em ordem de prioridade
        detection_methods = [
            self._detect_by_environment_variable,
            self._detect_by_geoip,
            self._detect_by_user_agent,
            self._detect_by_ip_ranges
        ]
        
        for method in detection_methods:
            try:
                result = method(ip_address, user_agent)
                if result and result.confidence > 0.5:
                    # Cache do resultado
                    self._region_cache[cache_key] = {
                        'result': result,
                        'timestamp': time.time()
                    }
                    
                    logger.info(
                        f"[{self.tracing_id}] Região detectada: {result.detected_region} "
                        f"(confiança: {result.confidence}, método: {result.detection_method})"
                    )
                    return result
            except Exception as e:
                logger.warning(f"[{self.tracing_id}] Erro no método de detecção {method.__name__}: {e}")
        
        # Fallback para região padrão
        fallback_result = RegionDetectionResult(
            detected_region=self.config.fallback_region,
            confidence=0.1,
            detection_method="fallback",
            ip_address=ip_address
        )
        
        # Cache do resultado fallback
        self._region_cache[cache_key] = {
            'result': fallback_result,
            'timestamp': time.time()
        }
        
        logger.warning(f"[{self.tracing_id}] Usando região fallback: {self.config.fallback_region}")
        return fallback_result
    
    def _detect_by_environment_variable(self, ip_address: Optional[str], user_agent: Optional[str]) -> Optional[RegionDetectionResult]:
        """Detecta região por variável de ambiente"""
        region = os.getenv('AWS_REGION') or os.getenv('REGION') or os.getenv('DEPLOYMENT_REGION')
        if region and region in self.config.regions:
            return RegionDetectionResult(
                detected_region=region,
                confidence=1.0,
                detection_method="environment_variable",
                ip_address=ip_address
            )
        return None
    
    def _detect_by_geoip(self, ip_address: Optional[str], user_agent: Optional[str]) -> Optional[RegionDetectionResult]:
        """Detecta região usando GeoIP"""
        if not ip_address or not self.geoip_reader:
            return None
        
        try:
            # Valida IP
            ipaddress.ip_address(ip_address)
            
            # Consulta GeoIP
            response = self.geoip_reader.city(ip_address)
            
            # Mapeia país/região para código de região
            region_mapping = {
                'US': 'us-east-1',
                'CA': 'us-east-1',
                'BR': 'sa-east-1',
                'DE': 'eu-central-1',
                'IE': 'eu-west-1',
                'GB': 'eu-west-1',
                'FR': 'eu-west-1',
                'SG': 'ap-southeast-1',
                'AU': 'ap-southeast-1',
                'ZA': 'af-south-1'
            }
            
            country_code = response.country.iso_code
            if country_code in region_mapping:
                region_code = region_mapping[country_code]
                if region_code in self.config.regions:
                    return RegionDetectionResult(
                        detected_region=region_code,
                        confidence=0.9,
                        detection_method="geoip",
                        ip_address=ip_address,
                        geoip_data={
                            'country': response.country.name,
                            'country_code': country_code,
                            'city': response.city.name,
                            'latitude': response.location.latitude,
                            'longitude': response.location.longitude
                        }
                    )
            
            return None
            
        except (ValueError, geoip2.errors.AddressNotFoundError, Exception) as e:
            logger.debug(f"[{self.tracing_id}] Erro na detecção GeoIP: {e}")
            return None
    
    def _detect_by_user_agent(self, ip_address: Optional[str], user_agent: Optional[str]) -> Optional[RegionDetectionResult]:
        """Detecta região por user agent (método básico)"""
        if not user_agent:
            return None
        
        user_agent_lower = user_agent.lower()
        
        # Detecção básica por idioma/região no user agent
        if 'pt-br' in user_agent_lower or 'pt_br' in user_agent_lower:
            return RegionDetectionResult(
                detected_region="sa-east-1",
                confidence=0.7,
                detection_method="user_agent",
                ip_address=ip_address
            )
        elif 'de-de' in user_agent_lower or 'de_de' in user_agent_lower:
            return RegionDetectionResult(
                detected_region="eu-central-1",
                confidence=0.7,
                detection_method="user_agent",
                ip_address=ip_address
            )
        
        return None
    
    def _detect_by_ip_ranges(self, ip_address: Optional[str], user_agent: Optional[str]) -> Optional[RegionDetectionResult]:
        """Detecção básica por ranges de IP conhecidos"""
        if not ip_address:
            return None
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Ranges básicos por região (exemplo simplificado)
            ip_ranges = {
                'us-east-1': [
                    ipaddress.IPv4Network('3.0.0.0/8'),
                    ipaddress.IPv4Network('52.0.0.0/8'),
                    ipaddress.IPv4Network('54.0.0.0/8')
                ],
                'eu-west-1': [
                    ipaddress.IPv4Network('34.0.0.0/8'),
                    ipaddress.IPv4Network('52.0.0.0/8')
                ],
                'sa-east-1': [
                    ipaddress.IPv4Network('54.0.0.0/8'),
                    ipaddress.IPv4Network('177.0.0.0/8')
                ]
            }
            
            for region, ranges in ip_ranges.items():
                for ip_range in ranges:
                    if ip in ip_range:
                        return RegionDetectionResult(
                            detected_region=region,
                            confidence=0.6,
                            detection_method="ip_ranges",
                            ip_address=ip_address
                        )
            
            return None
            
        except ValueError:
            return None
    
    def get_region_config(self, region_code: str) -> Optional[RegionConfig]:
        """Obtém configuração de uma região específica"""
        return self.config.regions.get(region_code)
    
    def validate_compliance(self, region_code: str, operation: str, data_type: str) -> Dict[str, Any]:
        """
        Valida compliance para uma operação em uma região
        
        Args:
            region_code: Código da região
            operation: Tipo de operação (read, write, delete, export)
            data_type: Tipo de dados (personal, sensitive, public)
            
        Returns:
            Resultado da validação de compliance
        """
        region_config = self.get_region_config(region_code)
        if not region_config:
            return {
                'compliant': False,
                'reason': f'Região {region_code} não suportada',
                'recommendations': [f'Usar região suportada: {list(self.config.regions.keys())}']
            }
        
        # Validações específicas por framework
        compliance_checks = []
        
        for framework in region_config.compliance_frameworks:
            if framework == ComplianceFramework.GDPR:
                compliance_checks.extend(self._validate_gdpr(region_config, operation, data_type))
            elif framework == ComplianceFramework.LGPD:
                compliance_checks.extend(self._validate_lgpd(region_config, operation, data_type))
            elif framework == ComplianceFramework.CCPA:
                compliance_checks.extend(self._validate_ccpa(region_config, operation, data_type))
        
        # Verifica se todas as validações passaram
        failed_checks = [check for check in compliance_checks if not check['compliant']]
        
        result = {
            'compliant': len(failed_checks) == 0,
            'region_code': region_code,
            'operation': operation,
            'data_type': data_type,
            'compliance_frameworks': [f.value for f in region_config.compliance_frameworks],
            'checks': compliance_checks,
            'recommendations': []
        }
        
        if failed_checks:
            result['reason'] = f'{len(failed_checks)} validações de compliance falharam'
            result['recommendations'] = [check['recommendation'] for check in failed_checks]
        
        return result
    
    def _validate_gdpr(self, region_config: RegionConfig, operation: str, data_type: str) -> List[Dict[str, Any]]:
        """Validações específicas do GDPR"""
        checks = []
        
        # Art. 32 - Segurança do processamento
        if not region_config.encryption_required:
            checks.append({
                'compliant': False,
                'framework': 'GDPR',
                'article': '32',
                'requirement': 'Encryption required',
                'recommendation': 'Habilitar criptografia para dados pessoais'
            })
        
        # Art. 30 - Registro de atividades de processamento
        if not region_config.audit_logging_required:
            checks.append({
                'compliant': False,
                'framework': 'GDPR',
                'article': '30',
                'requirement': 'Audit logging required',
                'recommendation': 'Habilitar logging de auditoria'
            })
        
        # Art. 17 - Direito ao apagamento
        if operation == 'delete' and not region_config.data_deletion_required:
            checks.append({
                'compliant': False,
                'framework': 'GDPR',
                'article': '17',
                'requirement': 'Right to erasure',
                'recommendation': 'Implementar apagamento de dados'
            })
        
        # Art. 44 - Transferência de dados
        if operation == 'export' and not region_config.data_export_allowed:
            checks.append({
                'compliant': False,
                'framework': 'GDPR',
                'article': '44',
                'requirement': 'Data transfer restrictions',
                'recommendation': 'Restringir exportação de dados'
            })
        
        return checks
    
    def _validate_lgpd(self, region_config: RegionConfig, operation: str, data_type: str) -> List[Dict[str, Any]]:
        """Validações específicas da LGPD"""
        checks = []
        
        # Art. 46 - Segurança e sigilo
        if not region_config.encryption_required:
            checks.append({
                'compliant': False,
                'framework': 'LGPD',
                'article': '46',
                'requirement': 'Security and secrecy',
                'recommendation': 'Habilitar criptografia para dados pessoais'
            })
        
        # Art. 37 - Relatório de impacto
        if not region_config.audit_logging_required:
            checks.append({
                'compliant': False,
                'framework': 'LGPD',
                'article': '37',
                'requirement': 'Impact assessment',
                'recommendation': 'Implementar logging para relatórios de impacto'
            })
        
        return checks
    
    def _validate_ccpa(self, region_config: RegionConfig, operation: str, data_type: str) -> List[Dict[str, Any]]:
        """Validações específicas do CCPA"""
        checks = []
        
        # Seção 1798.100 - Direitos do consumidor
        if operation == 'delete' and not region_config.data_deletion_required:
            checks.append({
                'compliant': False,
                'framework': 'CCPA',
                'section': '1798.100',
                'requirement': 'Consumer rights',
                'recommendation': 'Implementar direito de exclusão'
            })
        
        return checks
    
    def get_storage_location(self, region_code: str) -> str:
        """Obtém localização de storage para uma região"""
        region_config = self.get_region_config(region_code)
        if region_config:
            return region_config.storage_location
        return self.config.default_region
    
    def get_processing_location(self, region_code: str) -> str:
        """Obtém localização de processamento para uma região"""
        region_config = self.get_region_config(region_code)
        if region_config:
            return region_config.processing_location
        return self.config.default_region
    
    def should_audit_operation(self, region_code: str, operation: str) -> bool:
        """Determina se uma operação deve ser auditada"""
        if not self.config.audit_all_operations:
            return False
        
        region_config = self.get_region_config(region_code)
        if region_config:
            return region_config.audit_logging_required
        
        return True
    
    def log_regional_operation(self, region_code: str, operation: str, user_id: str, data_type: str, success: bool):
        """Registra operação regional para auditoria"""
        if not self.should_audit_operation(region_code, operation):
            return
        
        region_config = self.get_region_config(region_code)
        
        audit_data = {
            'timestamp': datetime.now().isoformat(),
            'tracing_id': self.tracing_id,
            'region_code': region_code,
            'region_name': region_config.region_name if region_config else 'unknown',
            'operation': operation,
            'user_id': user_id,
            'data_type': data_type,
            'success': success,
            'compliance_frameworks': [f.value for f in region_config.compliance_frameworks] if region_config else [],
            'data_residency': region_config.data_residency.value if region_config else 'none'
        }
        
        logger.info(
            f"[{self.tracing_id}] Operação regional registrada",
            extra=audit_data
        )
    
    def get_compliance_report(self, region_code: str) -> Dict[str, Any]:
        """Gera relatório de compliance para uma região"""
        region_config = self.get_region_config(region_code)
        if not region_config:
            return {
                'error': f'Região {region_code} não encontrada',
                'available_regions': list(self.config.regions.keys())
            }
        
        return {
            'region_code': region_code,
            'region_name': region_config.region_name,
            'region_type': region_config.region_type.value,
            'compliance_frameworks': [f.value for f in region_config.compliance_frameworks],
            'data_residency': region_config.data_residency.value,
            'storage_location': region_config.storage_location,
            'processing_location': region_config.processing_location,
            'backup_location': region_config.backup_location,
            'retention_period_days': region_config.retention_period_days,
            'encryption_required': region_config.encryption_required,
            'audit_logging_required': region_config.audit_logging_required,
            'data_export_allowed': region_config.data_export_allowed,
            'data_deletion_required': region_config.data_deletion_required,
            'report_generated': datetime.now().isoformat()
        }

# Instância global do adapter
multi_region_adapter = MultiRegionAdapter(
    config=MultiRegionConfig(
        default_region="us-east-1",
        auto_detection_enabled=True,
        fallback_region="us-east-1",
        geoip_database_path=os.getenv('GEOIP_DATABASE_PATH'),
        service_mesh_integration=True,
        compliance_strict_mode=True,
        audit_all_operations=True
    )
)

def get_multi_region_adapter(tracing_id: str = None) -> MultiRegionAdapter:
    """
    Factory function para obter instância do multi-region adapter
    
    Args:
        tracing_id: ID de rastreamento opcional
        
    Returns:
        Instância do MultiRegionAdapter
    """
    return multi_region_adapter

def detect_user_region(ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> RegionDetectionResult:
    """
    Função de conveniência para detectar região do usuário
    
    Args:
        ip_address: Endereço IP do usuário
        user_agent: User agent do navegador
        
    Returns:
        Resultado da detecção de região
    """
    return multi_region_adapter.detect_region(ip_address, user_agent)

def validate_regional_compliance(region_code: str, operation: str, data_type: str) -> Dict[str, Any]:
    """
    Função de conveniência para validar compliance regional
    
    Args:
        region_code: Código da região
        operation: Tipo de operação
        data_type: Tipo de dados
        
    Returns:
        Resultado da validação de compliance
    """
    return multi_region_adapter.validate_compliance(region_code, operation, data_type)

if __name__ == "__main__":
    # Exemplo de uso
    import argparse
    
    parser = argparse.ArgumentParser(description="Multi-Region Adapter")
    parser.add_argument("--ip", help="IP para detecção de região")
    parser.add_argument("--user-agent", help="User agent para detecção")
    parser.add_argument("--region", help="Região para validação de compliance")
    parser.add_argument("--operation", help="Operação para validação")
    parser.add_argument("--data-type", help="Tipo de dados para validação")
    
    args = parser.parse_args()
    
    if args.ip:
        result = detect_user_region(args.ip, args.user_agent)
        print(f"Região detectada: {result.detected_region} (confiança: {result.confidence})")
    
    if args.region and args.operation and args.data_type:
        compliance = validate_regional_compliance(args.region, args.operation, args.data_type)
        print(f"Compliance: {compliance['compliant']}")
        if not compliance['compliant']:
            print(f"Motivo: {compliance['reason']}")
            print(f"Recomendações: {compliance['recommendations']}") 