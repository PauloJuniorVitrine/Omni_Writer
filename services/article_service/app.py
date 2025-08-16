"""
Aplicação Flask para Article Service

Baseado no código real de app/routes.py e app/app_factory.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from datetime import datetime
import json

from .controllers import ArticleController
from .models import Article, Prompt, GenerationConfig
from .services import ArticleGenerationService, ArticleStorageService

def create_app():
    """
    Factory da aplicação Article Service.
    
    Baseado no código real de app/app_factory.py
    """
    app = Flask(__name__)
    
    # Configurações básicas
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'article-service-secret')
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
    logger = logging.getLogger("article_service")
    logger.setLevel(logging.INFO)
    log_handler = logging.FileHandler("logs/exec_trace/article_service.log")
    log_handler.setFormatter(logging.Formatter('%(message)s'))
    if not logger.hasHandlers():
        logger.addHandler(log_handler)
    
    # Inicializar serviços
    generation_service = ArticleGenerationService()
    storage_service = ArticleStorageService()
    controller = ArticleController(generation_service, storage_service)
    
    # Decorador para logging estruturado
    def log_request(response=None, trace_id=None, operation_type=None):
        log_data = {
            "timestamp_utc": datetime.utcnow().isoformat(),
            "service": "article-service",
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
    
    # Rotas do Article Service
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check do serviço"""
        return jsonify({
            'service': 'article-service',
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        })
    
    @app.route('/api/articles/generate', methods=['POST'])
    @limiter.limit('10/minute')
    @log_route(operation_type='generate_article')
    @require_service_token
    def generate_article():
        """
        Gera um artigo baseado no prompt fornecido.
        
        Baseado no código real de app/routes.py:generate()
        """
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Dados inválidos'}), 400
            
            # Validação básica
            if 'prompt' not in data or 'model_type' not in data:
                return jsonify({'error': 'Prompt e model_type são obrigatórios'}), 400
            
            # Geração do artigo
            result = controller.generate_article(
                prompt=data['prompt'],
                model_type=data['model_type'],
                api_key=data.get('api_key'),
                trace_id=request.headers.get('X-Trace-ID')
            )
            
            if result.success:
                return jsonify({
                    'success': True,
                    'article_id': result.article_id,
                    'content': result.content,
                    'title': result.title,
                    'trace_id': result.trace_id
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
    
    @app.route('/api/articles/<article_id>', methods=['GET'])
    @log_route(operation_type='get_article')
    @require_service_token
    def get_article(article_id):
        """Recupera um artigo pelo ID"""
        try:
            article = controller.get_article(article_id)
            if article:
                return jsonify({
                    'success': True,
                    'article': article.to_dict()
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Artigo não encontrado'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/articles/batch', methods=['POST'])
    @limiter.limit('5/minute')
    @log_route(operation_type='generate_batch')
    @require_service_token
    def generate_batch():
        """
        Gera múltiplos artigos em lote.
        
        Baseado no código real de app/pipeline.py
        """
        try:
            data = request.get_json()
            if not data or 'prompts' not in data:
                return jsonify({'error': 'Lista de prompts é obrigatória'}), 400
            
            result = controller.generate_batch(
                prompts=data['prompts'],
                model_type=data.get('model_type', 'openai'),
                api_key=data.get('api_key'),
                trace_id=request.headers.get('X-Trace-ID')
            )
            
            return jsonify({
                'success': True,
                'batch_id': result.batch_id,
                'total_prompts': len(data['prompts']),
                'trace_id': result.trace_id
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/articles/export/<batch_id>', methods=['GET'])
    @log_route(operation_type='export_articles')
    @require_service_token
    def export_articles(batch_id):
        """Exporta artigos de um lote em ZIP"""
        try:
            zip_path = controller.export_batch(batch_id)
            if zip_path:
                return jsonify({
                    'success': True,
                    'download_url': f'/api/articles/download/{batch_id}'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Lote não encontrado ou ainda em processamento'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/articles/download/<batch_id>', methods=['GET'])
    @log_route(operation_type='download_articles')
    def download_articles(batch_id):
        """Download do arquivo ZIP com artigos"""
        try:
            from flask import send_file
            zip_path = controller.get_batch_zip_path(batch_id)
            if zip_path and os.path.exists(zip_path):
                return send_file(
                    zip_path,
                    as_attachment=True,
                    download_name=f'articles_batch_{batch_id}.zip'
                )
            else:
                return jsonify({
                    'success': False,
                    'error': 'Arquivo não encontrado'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Erro interno: {str(e)}'
            }), 500
    
    @app.route('/api/articles/status/<batch_id>', methods=['GET'])
    @log_route(operation_type='batch_status')
    def batch_status(batch_id):
        """Status de processamento de um lote"""
        try:
            status = controller.get_batch_status(batch_id)
            if status:
                return jsonify({
                    'success': True,
                    'status': status
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Lote não encontrado'
                }), 404
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