"""
Aplicação Flask para User Service

Baseado no código real de app/routes.py e shared/token_repository.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from datetime import datetime
import json

from .controllers import UserController
from .models import User, Token, Permission
from .services import UserAuthService, TokenService

def create_app():
    """
    Factory da aplicação User Service.
    
    Baseado no código real de app/app_factory.py
    """
    app = Flask(__name__)
    
    # Configurações básicas
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'user-service-secret')
    app.config['JSON_AS_ASCII'] = False
    
    # CORS para comunicação entre serviços
    CORS(app, origins=['http://localhost:3000', 'http://localhost:5000'])
    
    # Rate limiting
    REDIS_URL = os.getenv('REDIS_URL', None)
    if REDIS_URL:
        from redis import Redis
        limiter = Limiter(get_remote_address, storage_uri=REDIS_URL)
    else:
        limiter = Limiter(get_remote_address)
    
    # Configuração de logging estruturado
    logger = logging.getLogger("user_service")
    logger.setLevel(logging.INFO)
    log_handler = logging.FileHandler("logs/exec_trace/user_service.log")
    log_handler.setFormatter(logging.Formatter('%(message)s'))
    if not logger.hasHandlers():
        logger.addHandler(log_handler)
    
    # Inicializar serviços
    auth_service = UserAuthService()
    token_service = TokenService()
    controller = UserController(auth_service, token_service)
    
    # Decorador para logging estruturado
    def log_request(response=None, trace_id=None, operation_type=None):
        log_data = {
            "timestamp_utc": datetime.utcnow().isoformat(),
            "service": "user-service",
            "ip": request.remote_addr,
            "rota": request.path,
            "metodo": request.method,
            "status": response.status_code if response else None,
            "user_agent": request.headers.get('User-Agent'),
            "trace_id": trace_id,
            "operation_type": operation_type,
        }
        logger.info(json.dumps(log_data, ensure_ascii=False))
        return response
    
    # Decorador para logging de rotas
    def log_route(operation_type=None):
        def decorator(f):
            def wrapper(*args, **kwargs):
                trace_id = request.headers.get('X-Trace-ID')
                try:
                    resp = f(*args, **kwargs)
                    if hasattr(resp, 'status_code'):
                        log_request(resp, trace_id, operation_type)
                    return resp
                except Exception as e:
                    log_request(None, trace_id, f"{operation_type}_error")
                    raise
            return wrapper
        return decorator
    
    # Decorador de autenticação
    def require_service_token(f):
        def decorated(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            token = auth.split(' ', 1)[1].strip() if auth.startswith('Bearer ') else None
            if not token or token != os.getenv('SERVICE_TOKEN', 'service-token'):
                return jsonify({'error': 'Acesso negado: token de serviço inválido'}), 401
            return f(*args, **kwargs)
        return decorated
    
    # Rotas do User Service
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check do serviço"""
        return jsonify({
            'service': 'user-service',
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        })
    
    @app.route('/api/auth/validate', methods=['POST'])
    @limiter.limit('100/minute')
    @log_route(operation_type='validate_token')
    @require_service_token
    def validate_token():
        """
        Valida um token de autenticação.
        
        Baseado no código real de shared/token_repository.py
        """
        try:
            data = request.get_json()
            if not data or 'token' not in data:
                return jsonify({'error': 'Token é obrigatório'}), 400
            
            result = controller.validate_token(
                token=data['token'],
                trace_id=request.headers.get('X-Trace-ID')
            )
            
            return jsonify({
                'valid': result.valid,
                'user_id': result.user_id,
                'permissions': result.permissions,
                'expires_at': result.expires_at.isoformat() if result.expires_at else None
            })
            
        except Exception as e:
            return jsonify({
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/auth/rotate', methods=['POST'])
    @limiter.limit('10/minute')
    @log_route(operation_type='rotate_token')
    @require_service_token
    def rotate_token():
        """
        Rotaciona um token de autenticação.
        
        Baseado no código real de shared/token_repository.py
        """
        try:
            data = request.get_json()
            if not data or 'token' not in data:
                return jsonify({'error': 'Token é obrigatório'}), 400
            
            result = controller.rotate_token(
                token=data['token'],
                trace_id=request.headers.get('X-Trace-ID')
            )
            
            if result.success:
                return jsonify({
                    'success': True,
                    'new_token': result.new_token,
                    'expires_at': result.expires_at.isoformat() if result.expires_at else None
                })
            else:
                return jsonify({
                    'success': False,
                    'error': result.error_message
                }), 400
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/users/<user_id>', methods=['GET'])
    @log_route(operation_type='get_user')
    @require_service_token
    def get_user(user_id):
        """Recupera informações de um usuário"""
        try:
            user = controller.get_user(user_id)
            if user:
                return jsonify({
                    'success': True,
                    'user': user.to_dict()
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Usuário não encontrado'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/users/<user_id>/permissions', methods=['GET'])
    @log_route(operation_type='get_user_permissions')
    @require_service_token
    def get_user_permissions(user_id):
        """Recupera permissões de um usuário"""
        try:
            permissions = controller.get_user_permissions(user_id)
            return jsonify({
                'success': True,
                'permissions': permissions
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint não encontrado'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Erro interno do servidor'}), 500
    
    return app 