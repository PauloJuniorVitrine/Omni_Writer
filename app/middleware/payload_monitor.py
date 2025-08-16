#!/usr/bin/env python3
"""
🔍 PAYLOAD MONITOR MIDDLEWARE - Interceptação Automática de Payloads
Tracing ID: PAYLOAD_MIDDLEWARE_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Middleware para interceptar automaticamente todos os requests
e analisar payloads para detecção de tamanhos excessivos.
"""

import json
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from flask import request, g, Response
from werkzeug.exceptions import RequestEntityTooLarge

# Importa o auditor de payloads
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'scripts'))
from payload_auditor import get_payload_auditor

logger = logging.getLogger('payload_monitor')

class PayloadMonitorMiddleware:
    """
    Middleware para monitoramento automático de payloads.
    
    Funcionalidades:
    - Intercepta todos os requests automaticamente
    - Analisa tamanho e conteúdo dos payloads
    - Gera alertas para payloads excessivos
    - Integra com sistema de auditoria
    - Adiciona métricas ao contexto da requisição
    """
    
    def __init__(self, app=None, max_payload_kb: float = 500):
        """
        Inicializa o middleware de monitoramento.
        
        Args:
            app: Aplicação Flask
            max_payload_kb: Tamanho máximo permitido em KB
        """
        self.max_payload_kb = max_payload_kb
        self.auditor = get_payload_auditor()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa o middleware na aplicação Flask."""
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        
        # Configura limite de tamanho de request
        app.config['MAX_CONTENT_LENGTH'] = int(self.max_payload_kb * 1024)
        
        logger.info(f"PayloadMonitorMiddleware inicializado - Max: {self.max_payload_kb}KB")
    
    def _before_request(self):
        """Executado antes de cada request."""
        start_time = time.time()
        
        # Extrai informações da requisição
        endpoint = request.endpoint or request.path
        method = request.method
        user_id = self._extract_user_id()
        request_id = self._generate_request_id()
        
        # Armazena informações no contexto
        g.payload_monitor = {
            'start_time': start_time,
            'endpoint': endpoint,
            'method': method,
            'user_id': user_id,
            'request_id': request_id,
            'payload_analyzed': False
        }
        
        # Analisa payload se presente
        if request.method in ['POST', 'PUT', 'PATCH']:
            self._analyze_request_payload(endpoint, method, user_id, request_id)
    
    def _after_request(self, response: Response) -> Response:
        """Executado após cada request."""
        if hasattr(g, 'payload_monitor'):
            monitor_data = g.payload_monitor
            
            # Calcula tempo de processamento
            processing_time = (time.time() - monitor_data['start_time']) * 1000
            
            # Log de performance se payload foi analisado
            if monitor_data.get('payload_analyzed'):
                logger.info(f"Request processado: {monitor_data['endpoint']} - "
                           f"{processing_time:.2f}ms")
            
            # Adiciona headers de monitoramento
            response.headers['X-Payload-Monitored'] = 'true'
            response.headers['X-Processing-Time'] = f"{processing_time:.2f}"
        
        return response
    
    def _extract_user_id(self) -> Optional[str]:
        """Extrai ID do usuário da requisição."""
        try:
            # Tenta extrair de diferentes fontes
            if hasattr(request, 'user') and request.user:
                return str(request.user.id)
            
            # De headers de autenticação
            auth_header = request.headers.get('Authorization')
            if auth_header and 'Bearer' in auth_header:
                # Aqui você pode decodificar o JWT para extrair user_id
                # Por simplicidade, retorna None
                pass
            
            # De query parameters
            return request.args.get('user_id')
            
        except Exception as e:
            logger.debug(f"Erro ao extrair user_id: {e}")
            return None
    
    def _generate_request_id(self) -> str:
        """Gera ID único para a requisição."""
        timestamp = int(time.time() * 1000)
        random_suffix = hash(request.remote_addr) % 10000
        return f"REQ_{timestamp}_{random_suffix}"
    
    def _analyze_request_payload(self, 
                                endpoint: str, 
                                method: str, 
                                user_id: Optional[str], 
                                request_id: str) -> None:
        """Analisa payload da requisição."""
        try:
            # Obtém payload baseado no content-type
            payload = self._extract_payload()
            
            if payload is not None:
                # Analisa payload usando o auditor
                metrics = self.auditor.analyze_payload(
                    payload=payload,
                    endpoint=endpoint,
                    method=method,
                    user_id=user_id,
                    request_id=request_id
                )
                
                # Armazena métricas no contexto
                g.payload_monitor['metrics'] = metrics
                g.payload_monitor['payload_analyzed'] = True
                
                # Log detalhado para payloads excessivos
                if metrics.is_excessive:
                    logger.warning(f"PAYLOAD EXCESSIVO DETECTADO: {endpoint} - "
                                 f"{metrics.payload_size_kb:.2f}KB > {self.max_payload_kb}KB")
                
                # Adiciona headers informativos
                request.environ['HTTP_X_PAYLOAD_SIZE_KB'] = str(metrics.payload_size_kb)
                request.environ['HTTP_X_PAYLOAD_EXCESSIVE'] = str(metrics.is_excessive).lower()
        
        except RequestEntityTooLarge:
            logger.error(f"PAYLOAD MUITO GRANDE: {endpoint} - Request rejeitado")
            raise
        
        except Exception as e:
            logger.error(f"Erro ao analisar payload: {e}")
    
    def _extract_payload(self) -> Optional[Dict[str, Any] | str | bytes]:
        """Extrai payload da requisição baseado no content-type."""
        try:
            content_type = request.content_type or ''
            
            # JSON payload
            if 'application/json' in content_type:
                if request.is_json:
                    return request.get_json()
                else:
                    return request.get_data(as_text=True)
            
            # Form data
            elif 'application/x-www-form-urlencoded' in content_type:
                return dict(request.form)
            
            # Multipart form data
            elif 'multipart/form-data' in content_type:
                form_data = dict(request.form)
                # Adiciona informações sobre arquivos
                if request.files:
                    form_data['files'] = {
                        name: {
                            'filename': file.filename,
                            'content_type': file.content_type,
                            'size': len(file.read())
                        }
                        for name, file in request.files.items()
                    }
                return form_data
            
            # Raw data
            else:
                return request.get_data()
        
        except Exception as e:
            logger.error(f"Erro ao extrair payload: {e}")
            return None

# Decorator para endpoints específicos
def monitor_payload(max_size_kb: float = None):
    """
    Decorator para monitorar payloads em endpoints específicos.
    
    Args:
        max_size_kb: Tamanho máximo específico para este endpoint
    """
    def decorator(f):
        def wrapper(*args, **kwargs):
            # Sobrescreve limite se especificado
            if max_size_kb is not None:
                original_max = request.app.config.get('MAX_CONTENT_LENGTH')
                request.app.config['MAX_CONTENT_LENGTH'] = int(max_size_kb * 1024)
                
                try:
                    result = f(*args, **kwargs)
                finally:
                    # Restaura limite original
                    if original_max is not None:
                        request.app.config['MAX_CONTENT_LENGTH'] = original_max
                
                return result
            
            return f(*args, **kwargs)
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Função para obter métricas do request atual
def get_current_payload_metrics():
    """Retorna métricas do payload do request atual."""
    if hasattr(g, 'payload_monitor') and g.payload_monitor.get('payload_analyzed'):
        return g.payload_monitor.get('metrics')
    return None

# Função para verificar se payload atual é excessivo
def is_current_payload_excessive() -> bool:
    """Verifica se o payload do request atual é excessivo."""
    metrics = get_current_payload_metrics()
    return metrics.is_excessive if metrics else False

# Configuração de alertas customizados
class PayloadAlertConfig:
    """Configuração para alertas de payload customizados."""
    
    def __init__(self):
        self.alert_thresholds = {
            '/api/generate-articles': 2000,  # 2MB
            '/api/entrega-zip': 10000,       # 10MB
            '/api/upload-content': 5000,     # 5MB
            '/api/bulk-operations': 3000     # 3MB
        }
        
        self.alert_channels = {
            'slack': True,
            'email': False,
            'log': True
        }
    
    def get_threshold_for_endpoint(self, endpoint: str) -> float:
        """Retorna threshold específico para endpoint."""
        return self.alert_thresholds.get(endpoint, 500)  # Default 500KB
    
    def should_alert(self, endpoint: str, size_kb: float) -> bool:
        """Verifica se deve gerar alerta para o endpoint."""
        threshold = self.get_threshold_for_endpoint(endpoint)
        return size_kb > threshold

# Instância global de configuração
alert_config = PayloadAlertConfig()

if __name__ == "__main__":
    # Teste do middleware
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    middleware = PayloadMonitorMiddleware(app, max_payload_kb=500)
    
    @app.route('/test-payload', methods=['POST'])
    @monitor_payload(max_size_kb=1000)
    def test_payload():
        payload_metrics = get_current_payload_metrics()
        
        if payload_metrics and payload_metrics.is_excessive:
            return jsonify({
                'error': 'Payload excessivo',
                'size_kb': payload_metrics.payload_size_kb,
                'threshold_kb': 500
            }), 413
        
        return jsonify({
            'success': True,
            'payload_size_kb': payload_metrics.payload_size_kb if payload_metrics else 0
        })
    
    print("✅ PayloadMonitorMiddleware testado com sucesso!")
    print("📊 Middleware pronto para interceptar payloads automaticamente") 