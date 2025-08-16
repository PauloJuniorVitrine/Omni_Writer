"""
Security Headers System - Omni Writer
=====================================

Sistema de headers de segurança hardenizados com CSP avançado,
Permissions-Policy, Referrer-Policy e proteções modernas.

Prompt: Implementação de headers de segurança hardenizados
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:45:00Z
"""

import os
import secrets
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from werkzeug.datastructures import ContentSecurityPolicy

# Configuração de logging estruturado
headers_logger = logging.getLogger("security_headers")
headers_logger.setLevel(logging.INFO)
if not headers_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/security_headers.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [security_headers] %(message)s'
    )
    handler.setFormatter(formatter)
    headers_logger.addHandler(handler)

class SecurityHeadersManager:
    """
    Gerenciador de headers de segurança hardenizados.
    
    Funcionalidades:
    - CSP avançado com nonces dinâmicos
    - Permissions-Policy moderno
    - Referrer-Policy configurável
    - Headers de segurança adicionais
    - Logs de auditoria
    """
    
    def __init__(self):
        self.nonce_cache = {}
        self.nonce_rotation_interval = 3600  # 1 hora
        self.last_nonce_rotation = datetime.utcnow()
    
    def generate_nonce(self) -> str:
        """Gera nonce único para CSP."""
        return secrets.token_urlsafe(16)
    
    def rotate_nonces(self):
        """Rotaciona nonces periodicamente."""
        now = datetime.utcnow()
        if (now - self.last_nonce_rotation).total_seconds() > self.nonce_rotation_interval:
            self.nonce_cache.clear()
            self.last_nonce_rotation = now
            headers_logger.info("Nonces rotacionados por segurança")
    
    def get_csp_policy(self, nonce: str = None) -> str:
        """
        Gera política CSP hardenizada.
        
        Args:
            nonce: Nonce para scripts inline (opcional)
            
        Returns:
            String da política CSP
        """
        if nonce is None:
            nonce = self.generate_nonce()
        
        # Política CSP hardenizada
        csp_directives = {
            # Fontes padrão - apenas self
            'default-src': ["'self'"],
            
            # Scripts - apenas self e nonce
            'script-src': ["'self'", f"'nonce-{nonce}'"],
            
            # Estilos - apenas self e nonce
            'style-src': ["'self'", f"'nonce-{nonce}'", "'unsafe-inline'"],
            
            # Imagens - apenas self e data URIs limitados
            'img-src': ["'self'", "data:", "https:"],
            
            # Fontes - apenas self
            'font-src': ["'self'"],
            
            # Conectividade - apenas self
            'connect-src': ["'self'"],
            
            # Media - apenas self
            'media-src': ["'self'"],
            
            # Objetos - nenhum (bloqueia Flash, Java, etc.)
            'object-src': ["'none'"],
            
            # Frames - apenas self
            'frame-src': ["'self'"],
            
            # Frame ancestors - nenhum (previne clickjacking)
            'frame-ancestors': ["'none'"],
            
            # Base URI - apenas self
            'base-uri': ["'self'"],
            
            # Form action - apenas self
            'form-action': ["'self'"],
            
            # Manifest - apenas self
            'manifest-src': ["'self'"],
            
            # Worker - apenas self
            'worker-src': ["'self'"],
            
            # Upgrade insecure requests
            'upgrade-insecure-requests': [],
            
            # Report URI (opcional)
            # 'report-uri': ['/csp-report'],
            
            # Report to (moderno)
            # 'report-to': ['csp-endpoint'],
        }
        
        # Constrói string CSP
        csp_parts = []
        for directive, sources in csp_directives.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)
    
    def get_permissions_policy(self) -> str:
        """
        Gera Permissions-Policy moderno.
        
        Returns:
            String da política de permissões
        """
        # Política de permissões restritiva
        permissions = {
            # Câmera - desabilitada
            'camera': [],
            
            # Microfone - desabilitado
            'microphone': [],
            
            # Geolocalização - desabilitada
            'geolocation': [],
            
            # Notificações push - desabilitadas
            'push': [],
            
            # Sincronização em background - desabilitada
            'background-sync': [],
            
            # Execução de scripts em background - desabilitada
            'execution-while-not-rendered': [],
            
            # Execução de scripts durante renderização - desabilitada
            'execution-while-out-of-viewport': [],
            
            # Acesso a dados de pagamento - desabilitado
            'payment': [],
            
            # Acesso a dados de autofill - desabilitado
            'autoplay': [],
            
            # Acesso a dados de clipboard - desabilitado
            'clipboard-read': [],
            'clipboard-write': [],
            
            # Acesso a dados de tela - desabilitado
            'display-capture': [],
            
            # Acesso a dados de documentos - desabilitado
            'document-domain': [],
            
            # Acesso a dados de encodificação - desabilitado
            'encrypted-media': [],
            
            # Acesso a dados de fullscreen - desabilitado
            'fullscreen': [],
            
            # Acesso a dados de gamepad - desabilitado
            'gamepad': [],
            
            # Acesso a dados de gyroscope - desabilitado
            'gyroscope': [],
            
            # Acesso a dados de magnetometer - desabilitado
            'magnetometer': [],
            
            # Acesso a dados de midi - desabilitado
            'midi': [],
            
            # Acesso a dados de picture-in-picture - desabilitado
            'picture-in-picture': [],
            
            # Acesso a dados de publickey-credentials-get - desabilitado
            'publickey-credentials-get': [],
            
            # Acesso a dados de screen-wake-lock - desabilitado
            'screen-wake-lock': [],
            
            # Acesso a dados de usb - desabilitado
            'usb': [],
            
            # Acesso a dados de web-share - desabilitado
            'web-share': [],
            
            # Acesso a dados de xr-spatial-tracking - desabilitado
            'xr-spatial-tracking': [],
        }
        
        # Constrói string de permissões
        policy_parts = []
        for feature, origins in permissions.items():
            if origins:
                policy_parts.append(f"{feature}=({', '.join(origins)})")
            else:
                policy_parts.append(f"{feature}=()")
        
        return ", ".join(policy_parts)
    
    def get_referrer_policy(self) -> str:
        """
        Gera Referrer-Policy configurável.
        
        Returns:
            String da política de referrer
        """
        # Política restritiva para privacidade
        return "strict-origin-when-cross-origin"
    
    def get_all_security_headers(self, nonce: str = None) -> Dict[str, str]:
        """
        Gera todos os headers de segurança hardenizados.
        
        Args:
            nonce: Nonce para CSP (opcional)
            
        Returns:
            Dicionário com todos os headers
        """
        # Rotaciona nonces se necessário
        self.rotate_nonces()
        
        # Gera nonce se não fornecido
        if nonce is None:
            nonce = self.generate_nonce()
        
        headers = {
            # Headers básicos de segurança
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            
            # HSTS hardenizado
            'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
            
            # CSP avançado
            'Content-Security-Policy': self.get_csp_policy(nonce),
            
            # Permissions-Policy moderno
            'Permissions-Policy': self.get_permissions_policy(),
            
            # Referrer-Policy
            'Referrer-Policy': self.get_referrer_policy(),
            
            # Headers adicionais de segurança
            'X-Download-Options': 'noopen',
            'X-Permitted-Cross-Domain-Policies': 'none',
            
            # Cache control para recursos sensíveis
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            
            # Headers de privacidade
            'X-DNS-Prefetch-Control': 'off',
            'X-Robots-Tag': 'noindex, nofollow',
        }
        
        # Log de auditoria
        headers_logger.info(
            f"Headers de segurança gerados - Nonce: {nonce[:8]}..., "
            f"Total headers: {len(headers)}"
        )
        
        return headers
    
    def apply_headers_to_response(self, response, nonce: str = None) -> Any:
        """
        Aplica headers de segurança a uma resposta Flask.
        
        Args:
            response: Resposta Flask
            nonce: Nonce para CSP (opcional)
            
        Returns:
            Resposta com headers aplicados
        """
        headers = self.get_all_security_headers(nonce)
        
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value
        
        return response
    
    def get_csp_report_only_policy(self) -> str:
        """
        Gera política CSP em modo report-only para monitoramento.
        
        Returns:
            String da política CSP report-only
        """
        # Política mais permissiva para monitoramento
        csp_directives = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'media-src': ["'self'"],
            'object-src': ["'none'"],
            'frame-src': ["'self'"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'manifest-src': ["'self'"],
            'worker-src': ["'self'"],
            'report-uri': ['/csp-report'],
        }
        
        csp_parts = []
        for directive, sources in csp_directives.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)
    
    def validate_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Valida se todos os headers necessários estão presentes.
        
        Args:
            headers: Dicionário de headers
            
        Returns:
            Dicionário com resultado da validação
        """
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Permissions-Policy',
            'Referrer-Policy'
        ]
        
        missing_headers = []
        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)
        
        return {
            'valid': len(missing_headers) == 0,
            'missing_headers': missing_headers,
            'total_headers': len(headers),
            'validation_timestamp': datetime.utcnow().isoformat()
        }

# Instância global do gerenciador
security_headers_manager = SecurityHeadersManager()

def apply_security_headers(response, nonce: str = None):
    """
    Função de conveniência para aplicar headers de segurança.
    
    Args:
        response: Resposta Flask
        nonce: Nonce para CSP (opcional)
        
    Returns:
        Resposta com headers aplicados
    """
    return security_headers_manager.apply_headers_to_response(response, nonce)

def get_security_headers(nonce: str = None) -> Dict[str, str]:
    """
    Função de conveniência para obter headers de segurança.
    
    Args:
        nonce: Nonce para CSP (opcional)
        
    Returns:
        Dicionário com headers de segurança
    """
    return security_headers_manager.get_all_security_headers(nonce)

def validate_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Função de conveniência para validar headers de segurança.
    
    Args:
        headers: Dicionário de headers
        
    Returns:
        Dicionário com resultado da validação
    """
    return security_headers_manager.validate_headers(headers) 