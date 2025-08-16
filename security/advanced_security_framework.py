"""
Advanced Security Framework - IMP-400
Prompt: Security Hardening - Fase 4
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:00:00Z
Tracing ID: ENTERPRISE_20250127_400

Framework avançado de segurança com detecção de ameaças,
proteção proativa e compliance com padrões de segurança.
"""

import time
import hashlib
import hmac
import secrets
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import re
import ipaddress
from functools import wraps
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("security.framework")

class ThreatLevel(Enum):
    """Níveis de ameaça"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityEvent(Enum):
    """Tipos de eventos de segurança"""
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_VIOLATION = "authorization_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTEMPT = "csrf_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    DDoS_ATTEMPT = "ddos_attempt"

@dataclass
class SecurityThreat:
    """Ameaça de segurança detectada"""
    event_type: SecurityEvent
    threat_level: ThreatLevel
    source_ip: str
    user_agent: str
    timestamp: datetime
    description: str
    payload: Optional[str] = None
    mitigation_applied: bool = False
    blocked: bool = False

@dataclass
class SecurityRule:
    """Regra de segurança"""
    name: str
    description: str
    pattern: str
    threat_level: ThreatLevel
    action: str  # block, log, alert
    enabled: bool = True
    cooldown_seconds: int = 300

@dataclass
class SecurityMetrics:
    """Métricas de segurança"""
    total_requests: int = 0
    blocked_requests: int = 0
    suspicious_requests: int = 0
    authentication_failures: int = 0
    authorization_violations: int = 0
    threats_detected: int = 0
    last_threat_detected: Optional[datetime] = None

class AdvancedSecurityFramework:
    """
    Framework avançado de segurança.
    
    Funcionalidades:
    - Detecção de ameaças em tempo real
    - Proteção contra ataques comuns
    - Rate limiting inteligente
    - Análise comportamental
    - Compliance com padrões de segurança
    """
    
    def __init__(self):
        self.security_rules: List[SecurityRule] = []
        self.detected_threats: List[SecurityThreat] = []
        self.blocked_ips: Dict[str, datetime] = {}
        self.rate_limiters: Dict[str, Dict[str, List[datetime]]] = {}
        self.security_metrics = SecurityMetrics()
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self._lock = threading.RLock()
        
        self._initialize_security_rules()
        logger.info("Advanced Security Framework inicializado")
    
    def _initialize_security_rules(self):
        """Inicializa regras de segurança padrão"""
        # SQL Injection patterns
        sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(from|into|where|table|database)\b)",
            r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*['\"])",
            r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(union|select|insert|update|delete|drop|create|alter)\b)",
            r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(union|select|insert|update|delete|drop|create|alter)\b)"
        ]
        
        for i, pattern in enumerate(sql_patterns):
            self.security_rules.append(SecurityRule(
                name=f"SQL Injection Pattern {i+1}",
                description=f"Detecta tentativas de SQL injection - padrão {i+1}",
                pattern=pattern,
                threat_level=ThreatLevel.CRITICAL,
                action="block"
            ))
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>"
        ]
        
        for i, pattern in enumerate(xss_patterns):
            self.security_rules.append(SecurityRule(
                name=f"XSS Pattern {i+1}",
                description=f"Detecta tentativas de XSS - padrão {i+1}",
                pattern=pattern,
                threat_level=ThreatLevel.HIGH,
                action="block"
            ))
        
        # Path traversal
        self.security_rules.append(SecurityRule(
            name="Path Traversal",
            description="Detecta tentativas de path traversal",
            pattern=r"\.\./|\.\.\\",
            threat_level=ThreatLevel.HIGH,
            action="block"
        ))
        
        # Command injection
        self.security_rules.append(SecurityRule(
            name="Command Injection",
            description="Detecta tentativas de command injection",
            pattern=r"[;&|`$()]",
            threat_level=ThreatLevel.CRITICAL,
            action="block"
        ))
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[SecurityThreat]]:
        """
        Analisa requisição em busca de ameaças.
        
        Returns:
            Tuple[bool, Optional[SecurityThreat]]: (is_safe, threat_detected)
        """
        source_ip = request_data.get('source_ip', '')
        user_agent = request_data.get('user_agent', '')
        payload = request_data.get('payload', '')
        headers = request_data.get('headers', {})
        
        # Verificar se IP está bloqueado
        if self._is_ip_blocked(source_ip):
            threat = SecurityThreat(
                event_type=SecurityEvent.AUTHORIZATION_VIOLATION,
                threat_level=ThreatLevel.HIGH,
                source_ip=source_ip,
                user_agent=user_agent,
                timestamp=datetime.utcnow(),
                description=f"IP bloqueado tentou acessar: {source_ip}",
                blocked=True
            )
            return False, threat
        
        # Verificar rate limiting
        if not self._check_rate_limit(source_ip):
            threat = SecurityThreat(
                event_type=SecurityEvent.RATE_LIMIT_EXCEEDED,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=source_ip,
                user_agent=user_agent,
                timestamp=datetime.utcnow(),
                description=f"Rate limit excedido para IP: {source_ip}",
                blocked=True
            )
            return False, threat
        
        # Analisar payload contra regras de segurança
        for rule in self.security_rules:
            if not rule.enabled:
                continue
            
            if self._match_security_rule(rule, payload, headers):
                threat = SecurityThreat(
                    event_type=self._get_event_type_from_rule(rule),
                    threat_level=rule.threat_level,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    timestamp=datetime.utcnow(),
                    description=f"Regra de segurança violada: {rule.name}",
                    payload=payload,
                    blocked=(rule.action == "block")
                )
                
                # Aplicar ação da regra
                if rule.action == "block":
                    self._block_ip(source_ip, rule.cooldown_seconds)
                
                return False, threat
        
        # Análise comportamental
        behavioral_threat = self._analyze_behavioral_patterns(request_data)
        if behavioral_threat:
            return False, behavioral_threat
        
        return True, None
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Verifica se IP está bloqueado"""
        with self._lock:
            if ip in self.blocked_ips:
                block_until = self.blocked_ips[ip]
                if datetime.utcnow() < block_until:
                    return True
                else:
                    del self.blocked_ips[ip]
            return False
    
    def _block_ip(self, ip: str, duration_seconds: int):
        """Bloqueia IP por determinado tempo"""
        with self._lock:
            self.blocked_ips[ip] = datetime.utcnow() + timedelta(seconds=duration_seconds)
        logger.warning(f"IP bloqueado: {ip} por {duration_seconds}s")
    
    def _check_rate_limit(self, ip: str, limit: int = 100, window_seconds: int = 60) -> bool:
        """Verifica rate limiting para IP"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        with self._lock:
            if ip not in self.rate_limiters:
                self.rate_limiters[ip] = {}
            
            if 'requests' not in self.rate_limiters[ip]:
                self.rate_limiters[ip]['requests'] = []
            
            # Remover requisições antigas
            self.rate_limiters[ip]['requests'] = [
                req_time for req_time in self.rate_limiters[ip]['requests']
                if req_time > window_start
            ]
            
            # Verificar limite
            if len(self.rate_limiters[ip]['requests']) >= limit:
                return False
            
            # Adicionar requisição atual
            self.rate_limiters[ip]['requests'].append(now)
            return True
    
    def _match_security_rule(self, rule: SecurityRule, payload: str, headers: Dict) -> bool:
        """Verifica se payload corresponde à regra de segurança"""
        try:
            # Verificar payload
            if payload and re.search(rule.pattern, payload, re.IGNORECASE):
                return True
            
            # Verificar headers
            for header_value in headers.values():
                if isinstance(header_value, str) and re.search(rule.pattern, header_value, re.IGNORECASE):
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Erro ao verificar regra {rule.name}: {e}")
            return False
    
    def _get_event_type_from_rule(self, rule: SecurityRule) -> SecurityEvent:
        """Mapeia regra para tipo de evento"""
        if "sql" in rule.name.lower():
            return SecurityEvent.SQL_INJECTION_ATTEMPT
        elif "xss" in rule.name.lower():
            return SecurityEvent.XSS_ATTEMPT
        elif "csrf" in rule.name.lower():
            return SecurityEvent.CSRF_ATTEMPT
        else:
            return SecurityEvent.SUSPICIOUS_ACTIVITY
    
    def _analyze_behavioral_patterns(self, request_data: Dict[str, Any]) -> Optional[SecurityThreat]:
        """Analisa padrões comportamentais suspeitos"""
        source_ip = request_data.get('source_ip', '')
        user_agent = request_data.get('user_agent', '')
        
        # Verificar user agent suspeito
        suspicious_user_agents = [
            'sqlmap', 'nikto', 'nmap', 'wget', 'curl', 'python-requests',
            'bot', 'crawler', 'spider', 'scraper'
        ]
        
        user_agent_lower = user_agent.lower()
        for suspicious in suspicious_user_agents:
            if suspicious in user_agent_lower:
                return SecurityThreat(
                    event_type=SecurityEvent.SUSPICIOUS_ACTIVITY,
                    threat_level=ThreatLevel.MEDIUM,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    timestamp=datetime.utcnow(),
                    description=f"User agent suspeito detectado: {suspicious}",
                    blocked=False
                )
        
        return None
    
    def record_threat(self, threat: SecurityThreat):
        """Registra ameaça detectada"""
        with self._lock:
            self.detected_threats.append(threat)
            self.security_metrics.threats_detected += 1
            self.security_metrics.last_threat_detected = threat.timestamp
            
            if threat.blocked:
                self.security_metrics.blocked_requests += 1
            
            # Manter apenas últimas 1000 ameaças
            if len(self.detected_threats) > 1000:
                self.detected_threats = self.detected_threats[-1000:]
        
        logger.warning(f"Ameaça detectada: {threat.description} (IP: {threat.source_ip})")
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Criptografa dados sensíveis"""
        try:
            encrypted_data = self.cipher_suite.encrypt(data.encode())
            return encrypted_data.decode()
        except Exception as e:
            logger.error(f"Erro ao criptografar dados: {e}")
            return data
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Descriptografa dados sensíveis"""
        try:
            decrypted_data = self.cipher_suite.decrypt(encrypted_data.encode())
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Erro ao descriptografar dados: {e}")
            return encrypted_data
    
    def generate_secure_token(self, payload: Dict[str, Any], expiration_hours: int = 24) -> str:
        """Gera token JWT seguro"""
        try:
            payload['exp'] = datetime.utcnow() + timedelta(hours=expiration_hours)
            payload['iat'] = datetime.utcnow()
            payload['jti'] = secrets.token_urlsafe(32)
            
            token = jwt.encode(payload, self.encryption_key, algorithm='HS256')
            return token
        except Exception as e:
            logger.error(f"Erro ao gerar token: {e}")
            return None
    
    def verify_secure_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verifica token JWT"""
        try:
            payload = jwt.decode(token, self.encryption_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expirado")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token inválido: {e}")
            return None
    
    def hash_password(self, password: str) -> str:
        """Gera hash seguro de senha"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${hash_obj.hex()}"
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verifica senha contra hash"""
        try:
            salt, hash_hex = hashed_password.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == hash_hex
        except Exception as e:
            logger.error(f"Erro ao verificar senha: {e}")
            return False
    
    def get_security_metrics(self) -> SecurityMetrics:
        """Retorna métricas de segurança"""
        return self.security_metrics
    
    def get_recent_threats(self, hours: int = 24) -> List[SecurityThreat]:
        """Retorna ameaças recentes"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            threat for threat in self.detected_threats
            if threat.timestamp > cutoff_time
        ]
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Gera relatório de segurança"""
        recent_threats = self.get_recent_threats(24)
        
        threat_counts = {}
        for threat in recent_threats:
            event_type = threat.event_type.value
            threat_counts[event_type] = threat_counts.get(event_type, 0) + 1
        
        return {
            "summary": {
                "total_threats_24h": len(recent_threats),
                "blocked_requests": self.security_metrics.blocked_requests,
                "blocked_ips_count": len(self.blocked_ips),
                "last_threat_detected": self.security_metrics.last_threat_detected.isoformat() if self.security_metrics.last_threat_detected else None
            },
            "threat_breakdown": threat_counts,
            "recent_threats": [
                {
                    "event_type": threat.event_type.value,
                    "threat_level": threat.threat_level.value,
                    "source_ip": threat.source_ip,
                    "timestamp": threat.timestamp.isoformat(),
                    "description": threat.description,
                    "blocked": threat.blocked
                }
                for threat in recent_threats[-10:]  # Últimas 10 ameaças
            ]
        }

def security_check(request_data: Dict[str, Any]):
    """Decorator para verificação de segurança"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            security_framework = get_security_framework()
            
            # Analisar requisição
            is_safe, threat = security_framework.analyze_request(request_data)
            
            if not is_safe and threat:
                security_framework.record_threat(threat)
                
                if threat.blocked:
                    return {
                        "error": "Acesso negado por questões de segurança",
                        "threat_detected": threat.description
                    }, 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Instância global do framework
security_framework: Optional[AdvancedSecurityFramework] = None

def initialize_security_framework() -> AdvancedSecurityFramework:
    """Inicializa o framework de segurança"""
    global security_framework
    security_framework = AdvancedSecurityFramework()
    return security_framework

def get_security_framework() -> AdvancedSecurityFramework:
    """Retorna instância do framework de segurança"""
    if security_framework is None:
        raise RuntimeError("Security Framework não foi inicializado.")
    return security_framework 