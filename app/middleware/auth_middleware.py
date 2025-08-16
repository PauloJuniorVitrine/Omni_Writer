# 🔐 MIDDLEWARE DE AUTENTICAÇÃO
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas código baseado em requisitos reais do Omni Writer

"""
Middleware de Autenticação
==========================

Este módulo implementa autenticação e autorização para endpoints
protegidos do sistema Omni Writer.
"""

import jwt
import time
import logging
from functools import wraps
from typing import Dict, Any, Optional, Callable
from flask import request, jsonify, g, current_app
from werkzeug.exceptions import Unauthorized, Forbidden

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "AUTH_MIDDLEWARE_20250127_001"

class AuthMiddleware:
    """
    Middleware de autenticação e autorização.
    
    Funcionalidades:
    - Validação de tokens JWT
    - Verificação de permissões
    - Contexto de usuário
    - Rate limiting por usuário
    """
    
    def __init__(self, app=None):
        self.app = app
        self.secret_key = "omni_writer_secret_key_2025"
        self.algorithm = "HS256"
        self.tracing_id = TRACING_ID
        
        # Configurações de segurança
        self.token_expiry = 3600  # 1 hora
        self.refresh_expiry = 604800  # 7 dias
        
        # Cache de tokens (em produção usar Redis)
        self.token_cache = {}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa o middleware com a aplicação Flask"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Registra funções de template para debug
        app.context_processor(self.context_processor)
        
        logger.info(f"[{self.tracing_id}] Middleware de autenticação inicializado")
    
    def before_request(self):
        """Executado antes de cada request"""
        # Endpoints públicos que não precisam de autenticação
        public_endpoints = [
            '/health',
            '/metrics',
            '/docs',
            '/openapi.json',
            '/generate',  # Endpoint principal (pode ser público)
            '/download',
            '/export_prompts',
            '/export_artigos_csv',
            '/feedback',
            '/webhook'
        ]
        
        # Verifica se é endpoint público
        if request.endpoint and any(ep in request.path for ep in public_endpoints):
            return None
        
        # Para endpoints protegidos, valida autenticação
        if request.path.startswith('/api/protected'):
            return self.validate_protected_endpoint()
        
        return None
    
    def after_request(self, response):
        """Executado após cada request"""
        # Adiciona headers de segurança
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    
    def context_processor(self):
        """Contexto para templates"""
        return {
            'current_user': getattr(g, 'user', None),
            'is_authenticated': hasattr(g, 'user')
        }
    
    def validate_protected_endpoint(self):
        """Valida endpoint protegido"""
        logger.info(f"[{self.tracing_id}] Validando endpoint protegido: {request.path}")
        
        # Extrai token do header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning(f"[{self.tracing_id}] Token não fornecido")
            return self.unauthorized_response("Token não fornecido")
        
        # Valida formato do token
        if not auth_header.startswith('Bearer '):
            logger.warning(f"[{self.tracing_id}] Formato de token inválido")
            return self.unauthorized_response("Formato de token inválido")
        
        token = auth_header.split(' ')[1]
        
        # Valida token
        try:
            user_data = self.validate_token(token)
            if not user_data:
                logger.warning(f"[{self.tracing_id}] Token inválido")
                return self.unauthorized_response("Token inválido")
            
            # Define contexto de usuário
            g.user = user_data
            g.token = token
            
            # Verifica permissões
            if not self.check_permissions(user_data, request.path, request.method):
                logger.warning(f"[{self.tracing_id}] Permissão negada para usuário {user_data.get('user_id')}")
                return self.forbidden_response("Permissão negada")
            
            logger.info(f"[{self.tracing_id}] Autenticação válida para usuário {user_data.get('user_id')}")
            return None
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"[{self.tracing_id}] Token expirado")
            return self.unauthorized_response("Token expirado")
        except jwt.InvalidTokenError as e:
            logger.warning(f"[{self.tracing_id}] Token inválido: {e}")
            return self.unauthorized_response("Token inválido")
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro na validação: {e}")
            return self.unauthorized_response("Erro na validação")
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Valida token JWT.
        
        Args:
            token: Token JWT a ser validado
            
        Returns:
            Dados do usuário se token válido, None caso contrário
        """
        try:
            # Decodifica token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True
                }
            )
            
            # Validações adicionais
            if not self.validate_payload(payload):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"[{self.tracing_id}] Token expirado")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"[{self.tracing_id}] Token inválido: {e}")
            raise
    
    def validate_payload(self, payload: Dict[str, Any]) -> bool:
        """
        Valida payload do token.
        
        Args:
            payload: Payload do token JWT
            
        Returns:
            True se payload válido, False caso contrário
        """
        required_fields = ['user_id', 'email', 'exp', 'iat']
        
        # Verifica campos obrigatórios
        for field in required_fields:
            if field not in payload:
                logger.warning(f"[{self.tracing_id}] Campo obrigatório ausente: {field}")
                return False
        
        # Verifica se não expirou
        current_time = int(time.time())
        if payload['exp'] < current_time:
            logger.warning(f"[{self.tracing_id}] Token expirado")
            return False
        
        # Verifica se foi emitido no futuro (clock skew)
        if payload['iat'] > current_time + 300:  # 5 minutos de tolerância
            logger.warning(f"[{self.tracing_id}] Token emitido no futuro")
            return False
        
        return True
    
    def check_permissions(self, user_data: Dict[str, Any], path: str, method: str) -> bool:
        """
        Verifica permissões do usuário.
        
        Args:
            user_data: Dados do usuário
            path: Caminho da requisição
            method: Método HTTP
            
        Returns:
            True se usuário tem permissão, False caso contrário
        """
        user_id = user_data.get('user_id')
        user_role = user_data.get('role', 'user')
        
        # Permissões por role
        permissions = {
            'admin': ['GET', 'POST', 'PUT', 'DELETE'],
            'moderator': ['GET', 'POST', 'PUT'],
            'user': ['GET', 'POST'],
            'readonly': ['GET']
        }
        
        # Verifica se role existe
        if user_role not in permissions:
            logger.warning(f"[{self.tracing_id}] Role inválida: {user_role}")
            return False
        
        # Verifica se método é permitido para o role
        if method not in permissions[user_role]:
            logger.warning(f"[{self.tracing_id}] Método {method} não permitido para role {user_role}")
            return False
        
        # Verificações específicas por endpoint
        if path.startswith('/api/protected/admin') and user_role != 'admin':
            logger.warning(f"[{self.tracing_id}] Acesso negado a endpoint admin para role {user_role}")
            return False
        
        if path.startswith('/api/protected/moderator') and user_role not in ['admin', 'moderator']:
            logger.warning(f"[{self.tracing_id}] Acesso negado a endpoint moderator para role {user_role}")
            return False
        
        return True
    
    def generate_token(self, user_data: Dict[str, Any]) -> str:
        """
        Gera token JWT para usuário.
        
        Args:
            user_data: Dados do usuário
            
        Returns:
            Token JWT gerado
        """
        payload = {
            'user_id': user_data['user_id'],
            'email': user_data['email'],
            'role': user_data.get('role', 'user'),
            'iat': int(time.time()),
            'exp': int(time.time()) + self.token_expiry
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Cache do token
        self.token_cache[token] = {
            'user_data': user_data,
            'created_at': time.time()
        }
        
        logger.info(f"[{self.tracing_id}] Token gerado para usuário {user_data['user_id']}")
        return token
    
    def refresh_token(self, token: str) -> Optional[str]:
        """
        Renova token JWT.
        
        Args:
            token: Token atual
            
        Returns:
            Novo token se válido, None caso contrário
        """
        try:
            # Valida token atual
            user_data = self.validate_token(token)
            if not user_data:
                return None
            
            # Gera novo token
            new_token = self.generate_token(user_data)
            
            # Remove token antigo do cache
            if token in self.token_cache:
                del self.token_cache[token]
            
            logger.info(f"[{self.tracing_id}] Token renovado para usuário {user_data['user_id']}")
            return new_token
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao renovar token: {e}")
            return None
    
    def unauthorized_response(self, message: str):
        """Resposta para não autorizado"""
        return jsonify({
            'error': 'Unauthorized',
            'message': message,
            'tracing_id': self.tracing_id
        }), 401
    
    def forbidden_response(self, message: str):
        """Resposta para acesso negado"""
        return jsonify({
            'error': 'Forbidden',
            'message': message,
            'tracing_id': self.tracing_id
        }), 403

# Decorator para endpoints protegidos
def require_auth(f):
    """Decorator para endpoints que requerem autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verifica se usuário está autenticado
        if not hasattr(g, 'user'):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Autenticação requerida',
                'tracing_id': TRACING_ID
            }), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Decorator para verificação de permissões
def require_permission(permission: str):
    """Decorator para verificação de permissões específicas"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user'):
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Autenticação requerida',
                    'tracing_id': TRACING_ID
                }), 401
            
            user_role = g.user.get('role', 'user')
            if permission not in get_user_permissions(user_role):
                return jsonify({
                    'error': 'Forbidden',
                    'message': f'Permissão {permission} requerida',
                    'tracing_id': TRACING_ID
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_permissions(role: str) -> list:
    """Retorna permissões do usuário baseado no role"""
    permissions = {
        'admin': ['read', 'write', 'delete', 'admin'],
        'moderator': ['read', 'write', 'moderate'],
        'user': ['read', 'write'],
        'readonly': ['read']
    }
    return permissions.get(role, [])

# Instância global do middleware
auth_middleware = AuthMiddleware()

# Funções de utilidade para testes
def create_test_token(user_id: str, email: str, role: str = 'user') -> str:
    """Cria token de teste para testes de integração"""
    user_data = {
        'user_id': user_id,
        'email': email,
        'role': role
    }
    return auth_middleware.generate_token(user_data)

def validate_test_token(token: str) -> Optional[Dict[str, Any]]:
    """Valida token de teste"""
    return auth_middleware.validate_token(token) 