"""
Header Sensitivity Auditor - Omni Writer
=======================================

Sistema de auditoria de headers para detectar vazamento de dados internos
e informações sensíveis em respostas HTTP.

Prompt: Header Sensitivity Audit - Item 9
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T20:30:00Z
Tracing ID: HEADER_SENSITIVITY_AUDIT_20250127_009

Análise CoCoT:
- Comprovação: Baseado em OWASP ASVS 1.2 e OWASP API Security Top 10
- Causalidade: Detecta headers que vazam informações internas e dados sensíveis
- Contexto: Integração com sistema de headers de segurança existente
- Tendência: Usa análise semântica e validação de contexto para reduzir falsos positivos

Decisões ToT:
- Abordagem 1: Lista estática de headers sensíveis (simples, mas limitada)
- Abordagem 2: Análise de conteúdo dos headers (precisa, mas complexa)
- Abordagem 3: Lista estática + análise semântica + contexto (equilibrada)
- Escolha: Abordagem 3 - melhor relação precisão vs complexidade

Simulação ReAct:
- Antes: Headers podem vazar informações internas sem detecção
- Durante: Auditoria automática de headers em todas as respostas
- Depois: Headers limpos, sem vazamento de dados sensíveis

Validação de Falsos Positivos:
- Regra: Header pode ser intencionalmente exposto para funcionalidade
- Validação: Verificar contexto e necessidade de negócio
- Log: Registrar headers válidos mas potencialmente sensíveis
"""

import os
import re
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
import requests
from urllib.parse import urlparse

from shared.logger import get_structured_logger

logger = get_structured_logger(__name__)

class HeaderSensitivityLevel(Enum):
    """Níveis de sensibilidade de headers."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class HeaderViolationType(Enum):
    """Tipos de violação de headers."""
    INTERNAL_INFO_LEAK = "internal_info_leak"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    DEBUG_INFO_LEAK = "debug_info_leak"
    SERVER_INFO_LEAK = "server_info_leak"
    VERSION_INFO_LEAK = "version_info_leak"
    PATH_INFO_LEAK = "path_info_leak"
    ERROR_DETAILS_LEAK = "error_details_leak"

@dataclass
class HeaderViolation:
    """Representa uma violação de header detectada."""
    header_name: str
    header_value: str
    violation_type: HeaderViolationType
    sensitivity_level: HeaderSensitivityLevel
    description: str
    risk_score: float
    recommendation: str
    context: Dict[str, Any]
    timestamp: datetime
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None

@dataclass
class HeaderAuditResult:
    """Resultado da auditoria de headers."""
    total_headers: int
    violations: List[HeaderViolation]
    risk_score: float
    recommendations: List[str]
    audit_timestamp: datetime
    endpoint: str
    method: str
    status_code: int

class HeaderSensitivityAuditor:
    """
    Auditor de sensibilidade de headers HTTP.
    
    Detecta headers que podem vazar informações internas, dados sensíveis
    ou informações de debug que não devem ser expostas publicamente.
    """
    
    def __init__(self):
        self.tracing_id = f"HEADER_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Headers sensíveis conhecidos
        self.sensitive_headers = {
            # Headers que vazam informações do servidor
            'server': HeaderSensitivityLevel.HIGH,
            'x-powered-by': HeaderSensitivityLevel.HIGH,
            'x-aspnet-version': HeaderSensitivityLevel.HIGH,
            'x-aspnetmvc-version': HeaderSensitivityLevel.HIGH,
            'x-runtime': HeaderSensitivityLevel.MEDIUM,
            'x-version': HeaderSensitivityLevel.HIGH,
            'x-generator': HeaderSensitivityLevel.MEDIUM,
            
            # Headers de debug e desenvolvimento
            'x-debug': HeaderSensitivityLevel.CRITICAL,
            'x-debug-info': HeaderSensitivityLevel.CRITICAL,
            'x-debug-token': HeaderSensitivityLevel.CRITICAL,
            'x-debug-token-link': HeaderSensitivityLevel.CRITICAL,
            'x-symfony-cache': HeaderSensitivityLevel.HIGH,
            'x-symfony-profiler': HeaderSensitivityLevel.HIGH,
            
            # Headers que vazam caminhos internos
            'x-sendfile': HeaderSensitivityLevel.HIGH,
            'x-accel-redirect': HeaderSensitivityLevel.HIGH,
            'x-file-path': HeaderSensitivityLevel.CRITICAL,
            'x-real-path': HeaderSensitivityLevel.CRITICAL,
            
            # Headers de erro detalhados
            'x-error-details': HeaderSensitivityLevel.CRITICAL,
            'x-error-code': HeaderSensitivityLevel.HIGH,
            'x-error-message': HeaderSensitivityLevel.CRITICAL,
            'x-stack-trace': HeaderSensitivityLevel.CRITICAL,
            
            # Headers de configuração interna
            'x-config': HeaderSensitivityLevel.CRITICAL,
            'x-environment': HeaderSensitivityLevel.HIGH,
            'x-database': HeaderSensitivityLevel.CRITICAL,
            'x-redis': HeaderSensitivityLevel.CRITICAL,
            
            # Headers de autenticação expostos
            'x-auth-token': HeaderSensitivityLevel.CRITICAL,
            'x-api-key': HeaderSensitivityLevel.CRITICAL,
            'x-session-id': HeaderSensitivityLevel.HIGH,
            'x-user-id': HeaderSensitivityLevel.HIGH,
            
            # Headers de performance que podem vazar informações
            'x-response-time': HeaderSensitivityLevel.MEDIUM,
            'x-request-id': HeaderSensitivityLevel.LOW,
            'x-correlation-id': HeaderSensitivityLevel.LOW,
        }
        
        # Padrões de conteúdo sensível
        self.sensitive_patterns = {
            # Padrões de caminhos internos
            r'/var/www/': HeaderSensitivityLevel.CRITICAL,
            r'/home/\w+/': HeaderSensitivityLevel.CRITICAL,
            r'/usr/local/': HeaderSensitivityLevel.HIGH,
            r'/etc/': HeaderSensitivityLevel.CRITICAL,
            r'/tmp/': HeaderSensitivityLevel.MEDIUM,
            r'/proc/': HeaderSensitivityLevel.CRITICAL,
            
            # Padrões de IPs internos
            r'192\.168\.': HeaderSensitivityLevel.HIGH,
            r'10\.': HeaderSensitivityLevel.HIGH,
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.': HeaderSensitivityLevel.HIGH,
            r'127\.0\.0\.1': HeaderSensitivityLevel.MEDIUM,
            r'localhost': HeaderSensitivityLevel.MEDIUM,
            
            # Padrões de informações de debug
            r'debug': HeaderSensitivityLevel.HIGH,
            r'development': HeaderSensitivityLevel.HIGH,
            r'test': HeaderSensitivityLevel.MEDIUM,
            r'staging': HeaderSensitivityLevel.MEDIUM,
            
            # Padrões de erros detalhados
            r'stack trace': HeaderSensitivityLevel.CRITICAL,
            r'error details': HeaderSensitivityLevel.CRITICAL,
            r'exception': HeaderSensitivityLevel.HIGH,
            r'fatal error': HeaderSensitivityLevel.CRITICAL,
            
            # Padrões de configuração
            r'password': HeaderSensitivityLevel.CRITICAL,
            r'secret': HeaderSensitivityLevel.CRITICAL,
            r'token': HeaderSensitivityLevel.CRITICAL,
            r'key': HeaderSensitivityLevel.CRITICAL,
            r'credential': HeaderSensitivityLevel.CRITICAL,
        }
        
        # Headers permitidos em contexto específico
        self.allowed_in_context = {
            'x-request-id': ['monitoring', 'tracing'],
            'x-correlation-id': ['monitoring', 'tracing'],
            'x-response-time': ['performance', 'monitoring'],
            'x-cache': ['caching'],
            'x-rate-limit': ['rate_limiting'],
            'x-trace-id': ['tracing'],
            'x-span-id': ['tracing'],
        }
        
        logger.info(f"Header Sensitivity Auditor inicializado - Tracing ID: {self.tracing_id}")
    
    def audit_headers(self, headers: Dict[str, str], context: Dict[str, Any] = None) -> HeaderAuditResult:
        """
        Audita headers para detectar vazamentos de informações sensíveis.
        
        Args:
            headers: Dicionário de headers HTTP
            context: Contexto da requisição (endpoint, método, etc.)
            
        Returns:
            Resultado da auditoria com violações encontradas
        """
        context = context or {}
        violations = []
        
        logger.info(f"Auditando {len(headers)} headers - Context: {context.get('endpoint', 'unknown')}")
        
        for header_name, header_value in headers.items():
            # Verifica se é um header sensível conhecido
            if header_name.lower() in self.sensitive_headers:
                sensitivity_level = self.sensitive_headers[header_name.lower()]
                violation = self._create_header_violation(
                    header_name, header_value, HeaderViolationType.INTERNAL_INFO_LEAK,
                    sensitivity_level, context
                )
                violations.append(violation)
                continue
            
            # Verifica padrões de conteúdo sensível
            content_violation = self._check_content_patterns(header_name, header_value, context)
            if content_violation:
                violations.append(content_violation)
            
            # Verifica se header vaza informações de debug
            debug_violation = self._check_debug_info(header_name, header_value, context)
            if debug_violation:
                violations.append(debug_violation)
            
            # Verifica se header vaza informações de servidor
            server_violation = self._check_server_info(header_name, header_value, context)
            if server_violation:
                violations.append(server_violation)
        
        # Calcula score de risco
        risk_score = self._calculate_risk_score(violations)
        
        # Gera recomendações
        recommendations = self._generate_recommendations(violations, context)
        
        result = HeaderAuditResult(
            total_headers=len(headers),
            violations=violations,
            risk_score=risk_score,
            recommendations=recommendations,
            audit_timestamp=datetime.now(),
            endpoint=context.get('endpoint', 'unknown'),
            method=context.get('method', 'unknown'),
            status_code=context.get('status_code', 0)
        )
        
        logger.info(f"Auditoria concluída - {len(violations)} violações, score: {risk_score:.2f}")
        return result
    
    def _create_header_violation(
        self, 
        header_name: str, 
        header_value: str, 
        violation_type: HeaderViolationType,
        sensitivity_level: HeaderSensitivityLevel,
        context: Dict[str, Any]
    ) -> HeaderViolation:
        """Cria uma violação de header."""
        
        descriptions = {
            HeaderViolationType.INTERNAL_INFO_LEAK: f"Header '{header_name}' vaza informações internas",
            HeaderViolationType.SENSITIVE_DATA_EXPOSURE: f"Header '{header_name}' expõe dados sensíveis",
            HeaderViolationType.DEBUG_INFO_LEAK: f"Header '{header_name}' vaza informações de debug",
            HeaderViolationType.SERVER_INFO_LEAK: f"Header '{header_name}' vaza informações do servidor",
            HeaderViolationType.VERSION_INFO_LEAK: f"Header '{header_name}' vaza informações de versão",
            HeaderViolationType.PATH_INFO_LEAK: f"Header '{header_name}' vaza caminhos internos",
            HeaderViolationType.ERROR_DETAILS_LEAK: f"Header '{header_name}' vaza detalhes de erro",
        }
        
        recommendations = {
            HeaderViolationType.INTERNAL_INFO_LEAK: "Remover header ou usar valor genérico",
            HeaderViolationType.SENSITIVE_DATA_EXPOSURE: "Remover header completamente",
            HeaderViolationType.DEBUG_INFO_LEAK: "Desabilitar em produção",
            HeaderViolationType.SERVER_INFO_LEAK: "Usar valor genérico ou remover",
            HeaderViolationType.VERSION_INFO_LEAK: "Remover ou usar versão genérica",
            HeaderViolationType.PATH_INFO_LEAK: "Remover header completamente",
            HeaderViolationType.ERROR_DETAILS_LEAK: "Usar apenas códigos de erro genéricos",
        }
        
        # Valida se é falso positivo
        is_false_positive, reason = self._validate_false_positive(header_name, header_value, context)
        
        return HeaderViolation(
            header_name=header_name,
            header_value=header_value,
            violation_type=violation_type,
            sensitivity_level=sensitivity_level,
            description=descriptions[violation_type],
            risk_score=self._calculate_violation_risk(sensitivity_level, violation_type),
            recommendation=recommendations[violation_type],
            context=context,
            timestamp=datetime.now(),
            is_false_positive=is_false_positive,
            false_positive_reason=reason
        )
    
    def _check_content_patterns(self, header_name: str, header_value: str, context: Dict[str, Any]) -> Optional[HeaderViolation]:
        """Verifica padrões de conteúdo sensível no valor do header."""
        
        header_lower = header_value.lower()
        
        for pattern, sensitivity_level in self.sensitive_patterns.items():
            if re.search(pattern, header_lower, re.IGNORECASE):
                # Verifica se é falso positivo
                is_false_positive, reason = self._validate_false_positive(header_name, header_value, context)
                
                if not is_false_positive:
                    return HeaderViolation(
                        header_name=header_name,
                        header_value=header_value,
                        violation_type=HeaderViolationType.SENSITIVE_DATA_EXPOSURE,
                        sensitivity_level=sensitivity_level,
                        description=f"Header '{header_name}' contém padrão sensível: {pattern}",
                        risk_score=self._calculate_violation_risk(sensitivity_level, HeaderViolationType.SENSITIVE_DATA_EXPOSURE),
                        recommendation="Remover ou sanitizar conteúdo sensível",
                        context=context,
                        timestamp=datetime.now(),
                        is_false_positive=False
                    )
                else:
                    logger.info(f"Falso positivo detectado para {header_name}: {reason}")
        
        return None
    
    def _check_debug_info(self, header_name: str, header_value: str, context: Dict[str, Any]) -> Optional[HeaderViolation]:
        """Verifica se header vaza informações de debug."""
        
        debug_indicators = [
            'debug', 'development', 'test', 'staging', 'dev',
            'trace', 'stack', 'error', 'exception', 'fatal'
        ]
        
        header_lower = header_name.lower()
        value_lower = header_value.lower()
        
        for indicator in debug_indicators:
            if indicator in header_lower or indicator in value_lower:
                # Verifica se é falso positivo
                is_false_positive, reason = self._validate_false_positive(header_name, header_value, context)
                
                if not is_false_positive:
                    return HeaderViolation(
                        header_name=header_name,
                        header_value=header_value,
                        violation_type=HeaderViolationType.DEBUG_INFO_LEAK,
                        sensitivity_level=HeaderSensitivityLevel.CRITICAL,
                        description=f"Header '{header_name}' vaza informações de debug",
                        risk_score=self._calculate_violation_risk(HeaderSensitivityLevel.CRITICAL, HeaderViolationType.DEBUG_INFO_LEAK),
                        recommendation="Remover header de debug em produção",
                        context=context,
                        timestamp=datetime.now(),
                        is_false_positive=False
                    )
        
        return None
    
    def _check_server_info(self, header_name: str, header_value: str, context: Dict[str, Any]) -> Optional[HeaderViolation]:
        """Verifica se header vaza informações do servidor."""
        
        server_indicators = [
            'server', 'powered-by', 'version', 'runtime',
            'aspnet', 'php', 'python', 'node', 'java'
        ]
        
        header_lower = header_name.lower()
        value_lower = header_value.lower()
        
        for indicator in server_indicators:
            if indicator in header_lower or indicator in value_lower:
                # Verifica se é falso positivo
                is_false_positive, reason = self._validate_false_positive(header_name, header_value, context)
                
                if not is_false_positive:
                    return HeaderViolation(
                        header_name=header_name,
                        header_value=header_value,
                        violation_type=HeaderViolationType.SERVER_INFO_LEAK,
                        sensitivity_level=HeaderSensitivityLevel.HIGH,
                        description=f"Header '{header_name}' vaza informações do servidor",
                        risk_score=self._calculate_violation_risk(HeaderSensitivityLevel.HIGH, HeaderViolationType.SERVER_INFO_LEAK),
                        recommendation="Usar valor genérico ou remover header",
                        context=context,
                        timestamp=datetime.now(),
                        is_false_positive=False
                    )
        
        return None
    
    def _validate_false_positive(self, header_name: str, header_value: str, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Valida se a violação é um falso positivo."""
        
        header_lower = header_name.lower()
        
        # Verifica se header é permitido no contexto
        if header_lower in self.allowed_in_context:
            allowed_contexts = self.allowed_in_context[header_lower]
            current_context = context.get('context_type', 'general')
            
            if current_context in allowed_contexts:
                return True, f"Header permitido no contexto: {current_context}"
        
        # Verifica se é ambiente de desenvolvimento
        if context.get('environment') == 'development':
            if header_lower in ['x-debug', 'x-debug-info', 'x-debug-token']:
                return True, "Header de debug permitido em desenvolvimento"
        
        # Verifica se é endpoint de monitoramento
        if context.get('endpoint', '').startswith('/metrics') or context.get('endpoint', '').startswith('/health'):
            if header_lower in ['x-response-time', 'x-request-id', 'x-correlation-id']:
                return True, "Header de monitoramento permitido em endpoints de métricas"
        
        # Verifica se é endpoint de tracing
        if context.get('endpoint', '').startswith('/trace') or 'trace' in context.get('endpoint', ''):
            if header_lower in ['x-trace-id', 'x-span-id', 'x-request-id']:
                return True, "Header de tracing permitido em endpoints de tracing"
        
        return False, None
    
    def _calculate_violation_risk(self, sensitivity_level: HeaderSensitivityLevel, violation_type: HeaderViolationType) -> float:
        """Calcula score de risco para uma violação."""
        
        base_scores = {
            HeaderSensitivityLevel.LOW: 0.2,
            HeaderSensitivityLevel.MEDIUM: 0.5,
            HeaderSensitivityLevel.HIGH: 0.8,
            HeaderSensitivityLevel.CRITICAL: 1.0,
        }
        
        type_multipliers = {
            HeaderViolationType.INTERNAL_INFO_LEAK: 1.0,
            HeaderViolationType.SENSITIVE_DATA_EXPOSURE: 1.2,
            HeaderViolationType.DEBUG_INFO_LEAK: 1.3,
            HeaderViolationType.SERVER_INFO_LEAK: 1.1,
            HeaderViolationType.VERSION_INFO_LEAK: 1.0,
            HeaderViolationType.PATH_INFO_LEAK: 1.4,
            HeaderViolationType.ERROR_DETAILS_LEAK: 1.5,
        }
        
        base_score = base_scores[sensitivity_level]
        multiplier = type_multipliers[violation_type]
        
        return min(1.0, base_score * multiplier)
    
    def _calculate_risk_score(self, violations: List[HeaderViolation]) -> float:
        """Calcula score de risco geral baseado nas violações."""
        
        if not violations:
            return 0.0
        
        # Filtra violações que não são falsos positivos
        real_violations = [v for v in violations if not v.is_false_positive]
        
        if not real_violations:
            return 0.0
        
        # Calcula score médio ponderado
        total_score = sum(v.risk_score for v in real_violations)
        return min(1.0, total_score / len(real_violations))
    
    def _generate_recommendations(self, violations: List[HeaderViolation], context: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas nas violações encontradas."""
        
        recommendations = []
        
        # Filtra violações reais (não falsos positivos)
        real_violations = [v for v in violations if not v.is_false_positive]
        
        if not real_violations:
            recommendations.append("Nenhuma violação crítica encontrada")
            return recommendations
        
        # Agrupa por tipo de violação
        violation_types = {}
        for violation in real_violations:
            if violation.violation_type not in violation_types:
                violation_types[violation.violation_type] = []
            violation_types[violation.violation_type].append(violation)
        
        # Gera recomendações específicas
        if HeaderViolationType.DEBUG_INFO_LEAK in violation_types:
            recommendations.append("Remover headers de debug em produção")
        
        if HeaderViolationType.SERVER_INFO_LEAK in violation_types:
            recommendations.append("Configurar headers de servidor para valores genéricos")
        
        if HeaderViolationType.SENSITIVE_DATA_EXPOSURE in violation_types:
            recommendations.append("Implementar sanitização de conteúdo em headers")
        
        if HeaderViolationType.PATH_INFO_LEAK in violation_types:
            recommendations.append("Remover headers que expõem caminhos internos")
        
        # Recomendação geral
        if len(real_violations) > 5:
            recommendations.append("Implementar auditoria automática de headers em CI/CD")
        
        return recommendations
    
    def audit_endpoint(self, url: str, method: str = "GET", headers: Dict[str, str] = None) -> HeaderAuditResult:
        """
        Audita headers de um endpoint específico.
        
        Args:
            url: URL do endpoint
            method: Método HTTP
            headers: Headers adicionais para a requisição
            
        Returns:
            Resultado da auditoria
        """
        try:
            logger.info(f"Auditando endpoint: {method} {url}")
            
            # Faz requisição
            response = requests.request(
                method=method,
                url=url,
                headers=headers or {},
                timeout=10,
                allow_redirects=False
            )
            
            # Extrai contexto
            parsed_url = urlparse(url)
            context = {
                'endpoint': parsed_url.path,
                'method': method,
                'status_code': response.status_code,
                'host': parsed_url.hostname,
                'environment': self._detect_environment(url)
            }
            
            # Audita headers da resposta
            return self.audit_headers(dict(response.headers), context)
            
        except Exception as e:
            logger.error(f"Erro ao auditar endpoint {url}: {e}")
            
            return HeaderAuditResult(
                total_headers=0,
                violations=[],
                risk_score=0.0,
                recommendations=["Erro ao acessar endpoint"],
                audit_timestamp=datetime.now(),
                endpoint=url,
                method=method,
                status_code=0
            )
    
    def _detect_environment(self, url: str) -> str:
        """Detecta ambiente baseado na URL."""
        url_lower = url.lower()
        
        if any(env in url_lower for env in ['localhost', '127.0.0.1', 'dev.', 'development']):
            return 'development'
        elif any(env in url_lower for env in ['staging', 'test.', 'qa.']):
            return 'staging'
        elif any(env in url_lower for env in ['prod.', 'production', 'live']):
            return 'production'
        else:
            return 'unknown'
    
    def generate_report(self, results: List[HeaderAuditResult]) -> Dict[str, Any]:
        """Gera relatório consolidado de auditoria."""
        
        total_endpoints = len(results)
        total_violations = sum(len(r.violations) for r in results)
        real_violations = sum(len([v for v in r.violations if not v.is_false_positive]) for r in results)
        avg_risk_score = sum(r.risk_score for r in results) / total_endpoints if total_endpoints > 0 else 0
        
        # Agrupa violações por tipo
        violation_types = {}
        for result in results:
            for violation in result.violations:
                if not violation.is_false_positive:
                    if violation.violation_type not in violation_types:
                        violation_types[violation.violation_type] = 0
                    violation_types[violation.violation_type] += 1
        
        # Headers mais problemáticos
        problematic_headers = {}
        for result in results:
            for violation in result.violations:
                if not violation.is_false_positive:
                    if violation.header_name not in problematic_headers:
                        problematic_headers[violation.header_name] = 0
                    problematic_headers[violation.header_name] += 1
        
        return {
            'audit_summary': {
                'total_endpoints': total_endpoints,
                'total_violations': total_violations,
                'real_violations': real_violations,
                'false_positives': total_violations - real_violations,
                'average_risk_score': avg_risk_score,
                'audit_timestamp': datetime.now().isoformat(),
                'tracing_id': self.tracing_id
            },
            'violation_types': violation_types,
            'problematic_headers': dict(sorted(problematic_headers.items(), key=lambda x: x[1], reverse=True)[:10]),
            'recommendations': self._generate_global_recommendations(results),
            'detailed_results': [asdict(result) for result in results]
        }
    
    def _generate_global_recommendations(self, results: List[HeaderAuditResult]) -> List[str]:
        """Gera recomendações globais baseadas em todos os resultados."""
        
        recommendations = []
        
        # Conta tipos de violação
        violation_counts = {}
        for result in results:
            for violation in result.violations:
                if not violation.is_false_positive:
                    if violation.violation_type not in violation_counts:
                        violation_counts[violation.violation_type] = 0
                    violation_counts[violation.violation_type] += 1
        
        # Recomendações baseadas em padrões
        if violation_counts.get(HeaderViolationType.DEBUG_INFO_LEAK, 0) > 5:
            recommendations.append("Implementar controle de ambiente para headers de debug")
        
        if violation_counts.get(HeaderViolationType.SERVER_INFO_LEAK, 0) > 3:
            recommendations.append("Configurar headers de servidor globalmente")
        
        if violation_counts.get(HeaderViolationType.SENSITIVE_DATA_EXPOSURE, 0) > 2:
            recommendations.append("Implementar sanitização automática de headers")
        
        # Recomendação geral
        total_violations = sum(violation_counts.values())
        if total_violations > 10:
            recommendations.append("Implementar auditoria automática de headers no pipeline CI/CD")
        
        return recommendations

# Instância global do auditor
header_auditor = HeaderSensitivityAuditor()

def audit_headers(headers: Dict[str, str], context: Dict[str, Any] = None) -> HeaderAuditResult:
    """
    Função de conveniência para auditar headers.
    
    Args:
        headers: Dicionário de headers HTTP
        context: Contexto da requisição
        
    Returns:
        Resultado da auditoria
    """
    return header_auditor.audit_headers(headers, context)

def audit_endpoint(url: str, method: str = "GET", headers: Dict[str, str] = None) -> HeaderAuditResult:
    """
    Função de conveniência para auditar endpoint.
    
    Args:
        url: URL do endpoint
        method: Método HTTP
        headers: Headers adicionais
        
    Returns:
        Resultado da auditoria
    """
    return header_auditor.audit_endpoint(url, method, headers)

if __name__ == "__main__":
    # Exemplo de uso
    import argparse
    
    parser = argparse.ArgumentParser(description="Header Sensitivity Auditor")
    parser.add_argument("url", help="URL do endpoint para auditar")
    parser.add_argument("--method", default="GET", help="Método HTTP")
    parser.add_argument("--output", help="Arquivo de saída JSON")
    
    args = parser.parse_args()
    
    # Audita endpoint
    result = audit_endpoint(args.url, args.method)
    
    # Exibe resultados
    print(f"Auditoria de Headers - {args.url}")
    print(f"Total de headers: {result.total_headers}")
    print(f"Violações encontradas: {len(result.violations)}")
    print(f"Score de risco: {result.risk_score:.2f}")
    print(f"Recomendações: {result.recommendations}")
    
    # Salva resultado se solicitado
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
        print(f"Resultado salvo em: {args.output}") 