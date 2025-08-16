"""
Auditor de Rate Limits & Throttling - Omni Writer
================================================

Sistema de auditoria de limites de requisição e throttling para validar
configurações e identificar problemas de performance e segurança.

Prompt: Rate Limits & Throttling Audit - Item 7
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T19:35:00Z
Tracing ID: RATE_LIMIT_AUDIT_20250127_007

Análise CoCoT:
- Comprovação: Baseado em OWASP ASVS 1.2 e API Security Best Practices
- Causalidade: Valida configurações de rate limiting para prevenir abuso e garantir performance
- Contexto: Integração com sistema de rate limiting existente e monitoring
- Tendência: Usa análise automática e relatórios estruturados

Decisões ToT:
- Abordagem 1: Validação estática de configurações (básico, mas limitado)
- Abordagem 2: Testes de carga dinâmicos (realista, mas complexo)
- Abordagem 3: Validação estática + testes de carga + análise de logs (completo)
- Escolha: Abordagem 3 - combina validação estática com testes dinâmicos

Simulação ReAct:
- Antes: Configurações de rate limiting não validadas, possíveis gaps de segurança
- Durante: Auditoria automática de configurações e testes de carga
- Depois: Rate limiting otimizado, segurança melhorada, performance validada

Validação de Falsos Positivos:
- Regra: Limite pode ser intencionalmente baixo para ambiente específico
- Validação: Verificar contexto de ambiente e requisitos de negócio
- Log: Registrar configurações válidas mas diferentes do padrão
"""

import os
import sys
import json
import time
import threading
import requests
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import argparse
from pathlib import Path
import yaml
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Adiciona o diretório raiz ao path para importações
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.logging_config import get_structured_logger
from shared.feature_flags import is_feature_enabled
from monitoring.metrics_collector import metrics_collector


class AuditSeverity(Enum):
    """Níveis de severidade da auditoria."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    BREAKING = "breaking"


class RateLimitType(Enum):
    """Tipos de rate limiting."""
    PER_MINUTE = "per_minute"
    PER_HOUR = "per_hour"
    PER_DAY = "per_day"
    CONCURRENT = "concurrent"
    BURST = "burst"


@dataclass
class RateLimitConfig:
    """Configuração de rate limiting."""
    endpoint: str
    limit_type: RateLimitType
    limit_value: int
    window_seconds: int
    burst_limit: Optional[int] = None
    user_specific: bool = False
    ip_specific: bool = True
    description: str = ""


@dataclass
class RateLimitViolation:
    """Violação de rate limiting detectada."""
    endpoint: str
    violation_type: str
    severity: AuditSeverity
    description: str
    current_value: Any
    expected_value: Any
    recommendation: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class AuditResult:
    """Resultado da auditoria."""
    audit_id: str
    timestamp: datetime
    total_endpoints: int
    total_violations: int
    violations_by_severity: Dict[str, int]
    recommendations: List[str]
    summary: str
    details: List[RateLimitViolation]


class RateLimitAuditor:
    """
    Auditor de rate limits e throttling.
    
    Funcionalidades:
    - Validação de configurações de rate limiting
    - Testes de carga para validar limites
    - Análise de logs para detectar violações
    - Relatórios de auditoria estruturados
    - Recomendações de otimização
    """
    
    def __init__(self):
        self.logger = get_structured_logger(__name__)
        
        # Configurações
        self.enabled = is_feature_enabled("rate_limit_audit_enabled")
        self.auto_fix = is_feature_enabled("rate_limit_audit_auto_fix_enabled")
        
        # Dados
        self.rate_limit_configs: Dict[str, RateLimitConfig] = {}
        self.violations: List[RateLimitViolation] = []
        self.audit_results: List[AuditResult] = []
        
        # Configurações padrão
        self.default_limits = {
            'generate': {'per_minute': 10, 'per_hour': 100},
            'feedback': {'per_minute': 20, 'per_hour': 200},
            'download': {'per_minute': 20, 'per_hour': 200},
            'export': {'per_minute': 30, 'per_hour': 300},
            'token': {'per_minute': 5, 'per_hour': 50},
            'metrics': {'per_minute': 60, 'per_hour': 1000},
            'health': {'per_minute': 60, 'per_hour': 1000},
            'default': {'per_minute': 100, 'per_hour': 1000}
        }
        
        # Thresholds de segurança
        self.security_thresholds = {
            'min_rate_limit_per_minute': 10,
            'max_rate_limit_per_minute': 1000,
            'min_rate_limit_per_hour': 100,
            'max_rate_limit_per_hour': 10000,
            'max_concurrent_requests': 50,
            'max_burst_limit': 100
        }
        
        # Inicialização
        self._load_rate_limit_configs()
        
        self.logger.info("Auditor de Rate Limits inicializado", extra={
            'tracing_id': 'RATE_LIMIT_AUDIT_20250127_007',
            'enabled': self.enabled,
            'auto_fix': self.auto_fix,
            'configs_count': len(self.rate_limit_configs)
        })
    
    def _load_rate_limit_configs(self):
        """Carrega configurações de rate limiting do sistema."""
        # Configurações do Flask-Limiter
        self.rate_limit_configs['/generate'] = RateLimitConfig(
            endpoint='/generate',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=10,
            window_seconds=60,
            user_specific=True,
            ip_specific=True,
            description="Geração de artigos - limite por minuto"
        )
        
        self.rate_limit_configs['/feedback'] = RateLimitConfig(
            endpoint='/feedback',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=20,
            window_seconds=60,
            user_specific=True,
            ip_specific=True,
            description="Envio de feedback - limite por minuto"
        )
        
        self.rate_limit_configs['/download'] = RateLimitConfig(
            endpoint='/download',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=20,
            window_seconds=60,
            user_specific=True,
            ip_specific=True,
            description="Download de arquivos - limite por minuto"
        )
        
        self.rate_limit_configs['/export'] = RateLimitConfig(
            endpoint='/export',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=30,
            window_seconds=60,
            user_specific=True,
            ip_specific=True,
            description="Exportação de dados - limite por minuto"
        )
        
        self.rate_limit_configs['/token/rotate'] = RateLimitConfig(
            endpoint='/token/rotate',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=5,
            window_seconds=60,
            user_specific=True,
            ip_specific=True,
            description="Rotação de tokens - limite por minuto"
        )
        
        self.rate_limit_configs['/metrics'] = RateLimitConfig(
            endpoint='/metrics',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=60,
            window_seconds=60,
            user_specific=False,
            ip_specific=True,
            description="Métricas do sistema - limite por minuto"
        )
        
        self.rate_limit_configs['/health'] = RateLimitConfig(
            endpoint='/health',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=60,
            window_seconds=60,
            user_specific=False,
            ip_specific=True,
            description="Health check - limite por minuto"
        )
        
        # Configurações globais
        self.rate_limit_configs['global'] = RateLimitConfig(
            endpoint='global',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=100,
            window_seconds=60,
            user_specific=False,
            ip_specific=True,
            description="Limite global por IP"
        )
    
    def audit_rate_limit_configs(self) -> AuditResult:
        """Audita configurações de rate limiting."""
        self.logger.info("Iniciando auditoria de configurações de rate limiting")
        
        violations = []
        
        # Valida cada configuração
        for endpoint, config in self.rate_limit_configs.items():
            # Valida limites mínimos de segurança
            if config.limit_type == RateLimitType.PER_MINUTE:
                if config.limit_value < self.security_thresholds['min_rate_limit_per_minute']:
                    violations.append(RateLimitViolation(
                        endpoint=endpoint,
                        violation_type="security_threshold",
                        severity=AuditSeverity.CRITICAL,
                        description=f"Rate limit muito baixo para {endpoint}",
                        current_value=config.limit_value,
                        expected_value=f">= {self.security_thresholds['min_rate_limit_per_minute']}",
                        recommendation="Aumentar limite para prevenir DoS",
                        timestamp=datetime.now(),
                        metadata={'threshold_type': 'min_rate_limit_per_minute'}
                    ))
                
                if config.limit_value > self.security_thresholds['max_rate_limit_per_minute']:
                    violations.append(RateLimitViolation(
                        endpoint=endpoint,
                        violation_type="security_threshold",
                        severity=AuditSeverity.WARNING,
                        description=f"Rate limit muito alto para {endpoint}",
                        current_value=config.limit_value,
                        expected_value=f"<= {self.security_thresholds['max_rate_limit_per_minute']}",
                        recommendation="Considerar reduzir limite para segurança",
                        timestamp=datetime.now(),
                        metadata={'threshold_type': 'max_rate_limit_per_minute'}
                    ))
            
            # Valida se endpoints sensíveis têm rate limiting
            if endpoint in ['/generate', '/feedback', '/download'] and not config.user_specific:
                violations.append(RateLimitViolation(
                    endpoint=endpoint,
                    violation_type="missing_user_specific",
                    severity=AuditSeverity.CRITICAL,
                    description=f"Endpoint {endpoint} deve ter rate limiting por usuário",
                    current_value=config.user_specific,
                    expected_value=True,
                    recommendation="Habilitar rate limiting por usuário",
                    timestamp=datetime.now(),
                    metadata={'endpoint_type': 'sensitive'}
                ))
            
            # Valida se endpoints públicos têm rate limiting por IP
            if endpoint in ['/metrics', '/health'] and not config.ip_specific:
                violations.append(RateLimitViolation(
                    endpoint=endpoint,
                    violation_type="missing_ip_specific",
                    severity=AuditSeverity.WARNING,
                    description=f"Endpoint {endpoint} deve ter rate limiting por IP",
                    current_value=config.ip_specific,
                    expected_value=True,
                    recommendation="Habilitar rate limiting por IP",
                    timestamp=datetime.now(),
                    metadata={'endpoint_type': 'public'}
                ))
        
        # Valida consistência entre endpoints similares
        self._validate_consistency(violations)
        
        # Gera resultado da auditoria
        result = self._generate_audit_result(violations, "config_audit")
        
        self.logger.info(f"Auditoria de configurações concluída: {len(violations)} violações encontradas")
        
        return result
    
    def _validate_consistency(self, violations: List[RateLimitViolation]):
        """Valida consistência entre endpoints similares."""
        # Agrupa endpoints por tipo
        endpoint_groups = {
            'generation': ['/generate'],
            'feedback': ['/feedback'],
            'download': ['/download', '/export'],
            'admin': ['/metrics', '/health'],
            'auth': ['/token/rotate']
        }
        
        for group_name, endpoints in endpoint_groups.items():
            if len(endpoints) < 2:
                continue
            
            # Verifica se limites são consistentes
            limits = []
            for endpoint in endpoints:
                if endpoint in self.rate_limit_configs:
                    config = self.rate_limit_configs[endpoint]
                    limits.append((endpoint, config.limit_value))
            
            if len(limits) >= 2:
                # Verifica se há inconsistência significativa (>50% diferença)
                values = [limit[1] for limit in limits]
                min_val = min(values)
                max_val = max(values)
                
                if max_val > min_val * 1.5:  # 50% de diferença
                    violations.append(RateLimitViolation(
                        endpoint=f"group_{group_name}",
                        violation_type="inconsistency",
                        severity=AuditSeverity.WARNING,
                        description=f"Inconsistência nos limites do grupo {group_name}",
                        current_value=f"min={min_val}, max={max_val}",
                        expected_value="Limites similares para endpoints do mesmo grupo",
                        recommendation="Padronizar limites para endpoints similares",
                        timestamp=datetime.now(),
                        metadata={'group': group_name, 'limits': limits}
                    ))
    
    def test_rate_limit_enforcement(self, base_url: str = "http://localhost:5000") -> AuditResult:
        """Testa se os rate limits estão sendo aplicados corretamente."""
        self.logger.info("Iniciando testes de enforcement de rate limiting")
        
        violations = []
        
        # Testa cada endpoint
        for endpoint, config in self.rate_limit_configs.items():
            if endpoint == 'global':
                continue  # Skip global config
            
            try:
                result = self._test_endpoint_rate_limit(base_url, endpoint, config)
                if result:
                    violations.append(result)
            except Exception as e:
                violations.append(RateLimitViolation(
                    endpoint=endpoint,
                    violation_type="test_error",
                    severity=AuditSeverity.CRITICAL,
                    description=f"Erro ao testar rate limit de {endpoint}",
                    current_value=str(e),
                    expected_value="Teste executado com sucesso",
                    recommendation="Verificar se endpoint está acessível",
                    timestamp=datetime.now(),
                    metadata={'error': str(e)}
                ))
        
        # Gera resultado da auditoria
        result = self._generate_audit_result(violations, "enforcement_test")
        
        self.logger.info(f"Testes de enforcement concluídos: {len(violations)} violações encontradas")
        
        return result
    
    def _test_endpoint_rate_limit(self, base_url: str, endpoint: str, config: RateLimitConfig) -> Optional[RateLimitViolation]:
        """Testa rate limit de um endpoint específico."""
        url = f"{base_url}{endpoint}"
        
        # Faz requisições até atingir o limite
        responses = []
        start_time = time.time()
        
        for i in range(config.limit_value + 5):  # +5 para garantir que atinge o limite
            try:
                response = requests.get(url, timeout=5)
                responses.append({
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'timestamp': time.time()
                })
                
                # Se recebeu 429, para o teste
                if response.status_code == 429:
                    break
                    
            except requests.exceptions.RequestException as e:
                responses.append({
                    'status_code': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                })
                break
        
        # Analisa resultados
        successful_requests = [r for r in responses if r['status_code'] == 200]
        rate_limited_requests = [r for r in responses if r['status_code'] == 429]
        
        # Verifica se rate limiting está funcionando
        if len(successful_requests) > config.limit_value:
            return RateLimitViolation(
                endpoint=endpoint,
                violation_type="rate_limit_not_enforced",
                severity=AuditSeverity.CRITICAL,
                description=f"Rate limit não está sendo aplicado em {endpoint}",
                current_value=f"{len(successful_requests)} requests bem-sucedidas",
                expected_value=f"<= {config.limit_value} requests bem-sucedidas",
                recommendation="Verificar configuração do Flask-Limiter",
                timestamp=datetime.now(),
                metadata={
                    'successful_requests': len(successful_requests),
                    'rate_limited_requests': len(rate_limited_requests),
                    'expected_limit': config.limit_value
                }
            )
        
        # Verifica se rate limiting está muito restritivo
        if len(rate_limited_requests) == 0 and len(successful_requests) < config.limit_value:
            return RateLimitViolation(
                endpoint=endpoint,
                violation_type="rate_limit_too_restrictive",
                severity=AuditSeverity.WARNING,
                description=f"Rate limit pode estar muito restritivo em {endpoint}",
                current_value=f"{len(successful_requests)} requests bem-sucedidas",
                expected_value=f"~{config.limit_value} requests bem-sucedidas",
                recommendation="Verificar se endpoint está funcionando corretamente",
                timestamp=datetime.now(),
                metadata={
                    'successful_requests': len(successful_requests),
                    'expected_limit': config.limit_value
                }
            )
        
        return None
    
    def analyze_rate_limit_logs(self, log_file: str = "logs/exec_trace/requests.log") -> AuditResult:
        """Analisa logs para detectar violações de rate limiting."""
        self.logger.info(f"Analisando logs de rate limiting: {log_file}")
        
        violations = []
        
        if not os.path.exists(log_file):
            violations.append(RateLimitViolation(
                endpoint="logs",
                violation_type="log_file_missing",
                severity=AuditSeverity.WARNING,
                description="Arquivo de log de requests não encontrado",
                current_value="File not found",
                expected_value="Log file exists",
                recommendation="Verificar se logging está configurado corretamente",
                timestamp=datetime.now(),
                metadata={'log_file': log_file}
            ))
            return self._generate_audit_result(violations, "log_analysis")
        
        try:
            # Analisa logs
            rate_limit_events = self._parse_rate_limit_logs(log_file)
            
            # Detecta padrões suspeitos
            violations.extend(self._detect_suspicious_patterns(rate_limit_events))
            
            # Analisa distribuição de requests
            violations.extend(self._analyze_request_distribution(rate_limit_events))
            
        except Exception as e:
            violations.append(RateLimitViolation(
                endpoint="logs",
                violation_type="log_analysis_error",
                severity=AuditSeverity.CRITICAL,
                description=f"Erro ao analisar logs: {str(e)}",
                current_value=str(e),
                expected_value="Log analysis completed successfully",
                recommendation="Verificar formato dos logs",
                timestamp=datetime.now(),
                metadata={'error': str(e)}
            ))
        
        # Gera resultado da auditoria
        result = self._generate_audit_result(violations, "log_analysis")
        
        self.logger.info(f"Análise de logs concluída: {len(violations)} violações encontradas")
        
        return result
    
    def _parse_rate_limit_logs(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse logs de rate limiting."""
        events = []
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    # Tenta parsear como JSON
                    event = json.loads(line.strip())
                    events.append(event)
                except json.JSONDecodeError:
                    # Se não for JSON, tenta parsear como log estruturado
                    if 'rate_limit' in line.lower() or '429' in line:
                        events.append({
                            'raw_line': line.strip(),
                            'timestamp': datetime.now().isoformat()
                        })
        
        return events
    
    def _detect_suspicious_patterns(self, events: List[Dict[str, Any]]) -> List[RateLimitViolation]:
        """Detecta padrões suspeitos nos logs."""
        violations = []
        
        # Agrupa eventos por IP
        ip_events = defaultdict(list)
        for event in events:
            ip = event.get('ip', event.get('remote_addr', 'unknown'))
            ip_events[ip].append(event)
        
        # Detecta IPs com muitas violações
        for ip, ip_event_list in ip_events.items():
            rate_limit_violations = [e for e in ip_event_list if e.get('status_code') == 429]
            
            if len(rate_limit_violations) > 10:  # Mais de 10 violações
                violations.append(RateLimitViolation(
                    endpoint=f"ip_{ip}",
                    violation_type="suspicious_ip",
                    severity=AuditSeverity.WARNING,
                    description=f"IP {ip} com muitas violações de rate limit",
                    current_value=f"{len(rate_limit_violations)} violações",
                    expected_value="< 10 violações por IP",
                    recommendation="Investigar se é ataque ou usuário legítimo",
                    timestamp=datetime.now(),
                    metadata={'ip': ip, 'violations_count': len(rate_limit_violations)}
                ))
        
        return violations
    
    def _analyze_request_distribution(self, events: List[Dict[str, Any]]) -> List[RateLimitViolation]:
        """Analisa distribuição de requests."""
        violations = []
        
        # Agrupa por endpoint
        endpoint_events = defaultdict(list)
        for event in events:
            endpoint = event.get('endpoint', event.get('path', 'unknown'))
            endpoint_events[endpoint].append(event)
        
        # Analisa cada endpoint
        for endpoint, endpoint_event_list in endpoint_events.items():
            if len(endpoint_event_list) < 10:  # Mínimo de eventos para análise
                continue
            
            # Calcula taxa de violações
            total_requests = len(endpoint_event_list)
            rate_limit_violations = [e for e in endpoint_event_list if e.get('status_code') == 429]
            violation_rate = len(rate_limit_violations) / total_requests
            
            # Se taxa de violação é muito alta (>20%)
            if violation_rate > 0.2:
                violations.append(RateLimitViolation(
                    endpoint=endpoint,
                    violation_type="high_violation_rate",
                    severity=AuditSeverity.WARNING,
                    description=f"Taxa alta de violações de rate limit em {endpoint}",
                    current_value=f"{violation_rate:.1%}",
                    expected_value="< 20%",
                    recommendation="Considerar ajustar limites ou investigar padrão de uso",
                    timestamp=datetime.now(),
                    metadata={
                        'total_requests': total_requests,
                        'violations': len(rate_limit_violations),
                        'violation_rate': violation_rate
                    }
                ))
        
        return violations
    
    def _generate_audit_result(self, violations: List[RateLimitViolation], audit_type: str) -> AuditResult:
        """Gera resultado da auditoria."""
        # Conta violações por severidade
        violations_by_severity = defaultdict(int)
        for violation in violations:
            violations_by_severity[violation.severity.value] += 1
        
        # Gera recomendações
        recommendations = []
        if violations_by_severity.get('critical', 0) > 0:
            recommendations.append("Corrigir violações críticas imediatamente")
        if violations_by_severity.get('warning', 0) > 0:
            recommendations.append("Revisar configurações de rate limiting")
        if violations_by_severity.get('info', 0) > 0:
            recommendations.append("Monitorar padrões de uso")
        
        # Gera resumo
        total_violations = len(violations)
        if total_violations == 0:
            summary = "✅ Auditoria passou sem violações"
        elif violations_by_severity.get('critical', 0) > 0:
            summary = f"❌ {total_violations} violações encontradas (incluindo críticas)"
        else:
            summary = f"⚠️ {total_violations} violações encontradas (apenas warnings/info)"
        
        result = AuditResult(
            audit_id=f"rate_limit_audit_{audit_type}_{int(time.time())}",
            timestamp=datetime.now(),
            total_endpoints=len(self.rate_limit_configs),
            total_violations=total_violations,
            violations_by_severity=dict(violations_by_severity),
            recommendations=recommendations,
            summary=summary,
            details=violations
        )
        
        # Adiciona à lista de resultados
        self.audit_results.append(result)
        
        return result
    
    def generate_audit_report(self, output_file: str = "rate_limit_audit_report.json") -> str:
        """Gera relatório completo da auditoria."""
        self.logger.info(f"Gerando relatório de auditoria: {output_file}")
        
        # Combina todos os resultados
        all_violations = []
        for result in self.audit_results:
            all_violations.extend(result.details)
        
        # Remove duplicatas baseado em endpoint e tipo
        unique_violations = []
        seen = set()
        for violation in all_violations:
            key = (violation.endpoint, violation.violation_type)
            if key not in seen:
                seen.add(key)
                unique_violations.append(violation)
        
        # Gera relatório
        report = {
            'audit_info': {
                'timestamp': datetime.now().isoformat(),
                'auditor_version': '1.0.0',
                'tracing_id': 'RATE_LIMIT_AUDIT_20250127_007'
            },
            'summary': {
                'total_audits': len(self.audit_results),
                'total_violations': len(unique_violations),
                'violations_by_severity': defaultdict(int),
                'endpoints_audited': len(self.rate_limit_configs)
            },
            'violations': [asdict(v) for v in unique_violations],
            'recommendations': self._generate_global_recommendations(unique_violations),
            'configurations': {
                endpoint: asdict(config) for endpoint, config in self.rate_limit_configs.items()
            }
        }
        
        # Conta violações por severidade
        for violation in unique_violations:
            report['summary']['violations_by_severity'][violation.severity.value] += 1
        
        # Salva relatório
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Relatório salvo em: {output_file}")
        
        return output_file
    
    def _generate_global_recommendations(self, violations: List[RateLimitViolation]) -> List[str]:
        """Gera recomendações globais baseadas nas violações."""
        recommendations = []
        
        # Análise por tipo de violação
        violation_types = defaultdict(int)
        for violation in violations:
            violation_types[violation.violation_type] += 1
        
        # Recomendações baseadas em padrões
        if violation_types.get('security_threshold', 0) > 0:
            recommendations.append("Revisar thresholds de segurança para rate limiting")
        
        if violation_types.get('rate_limit_not_enforced', 0) > 0:
            recommendations.append("Verificar configuração do Flask-Limiter")
        
        if violation_types.get('suspicious_ip', 0) > 0:
            recommendations.append("Implementar blacklist de IPs maliciosos")
        
        if violation_types.get('high_violation_rate', 0) > 0:
            recommendations.append("Ajustar limites baseado no padrão de uso real")
        
        # Recomendações gerais
        recommendations.extend([
            "Monitorar logs de rate limiting regularmente",
            "Implementar alertas para violações críticas",
            "Documentar políticas de rate limiting",
            "Testar rate limiting em ambiente de staging"
        ])
        
        return recommendations
    
    def run_full_audit(self, base_url: str = "http://localhost:5000") -> AuditResult:
        """Executa auditoria completa."""
        self.logger.info("Iniciando auditoria completa de rate limiting")
        
        # Executa todas as auditorias
        config_result = self.audit_rate_limit_configs()
        enforcement_result = self.test_rate_limit_enforcement(base_url)
        log_result = self.analyze_rate_limit_logs()
        
        # Combina resultados
        all_violations = []
        all_violations.extend(config_result.details)
        all_violations.extend(enforcement_result.details)
        all_violations.extend(log_result.details)
        
        # Gera resultado final
        final_result = self._generate_audit_result(all_violations, "full_audit")
        
        # Gera relatório
        self.generate_audit_report()
        
        self.logger.info("Auditoria completa concluída")
        
        return final_result


# Funções utilitárias
def get_rate_limit_auditor() -> RateLimitAuditor:
    """Obtém instância do auditor de rate limits."""
    return RateLimitAuditor()


def run_rate_limit_audit(base_url: str = "http://localhost:5000") -> AuditResult:
    """Executa auditoria de rate limiting."""
    auditor = get_rate_limit_auditor()
    return auditor.run_full_audit(base_url)


def main():
    """Função principal para execução via linha de comando."""
    parser = argparse.ArgumentParser(description='Auditor de Rate Limits & Throttling')
    parser.add_argument('--base-url', default='http://localhost:5000', help='URL base da aplicação')
    parser.add_argument('--output', default='rate_limit_audit_report.json', help='Arquivo de saída')
    parser.add_argument('--config-only', action='store_true', help='Auditar apenas configurações')
    parser.add_argument('--test-only', action='store_true', help='Testar apenas enforcement')
    parser.add_argument('--logs-only', action='store_true', help='Analisar apenas logs')
    
    args = parser.parse_args()
    
    auditor = get_rate_limit_auditor()
    
    if args.config_only:
        result = auditor.audit_rate_limit_configs()
    elif args.test_only:
        result = auditor.test_rate_limit_enforcement(args.base_url)
    elif args.logs_only:
        result = auditor.analyze_rate_limit_logs()
    else:
        result = auditor.run_full_audit(args.base_url)
    
    # Salva resultado
    with open(args.output, 'w') as f:
        json.dump(asdict(result), f, indent=2, default=str)
    
    print(f"Auditoria concluída. Resultado salvo em: {args.output}")
    print(f"Resumo: {result.summary}")


if __name__ == "__main__":
    main() 