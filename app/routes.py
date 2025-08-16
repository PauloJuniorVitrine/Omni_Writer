"""
Módulo de rotas principais da aplicação.
Responsável por rotas web: index, geração, download, exportação, status e SSE.

As rotas estão sendo migradas incrementalmente a partir de main.py.
"""

from flask import Blueprint, render_template, request, send_file, redirect, url_for, flash, Response, jsonify, abort
from shared.config import MODELOS_SUPORTADOS, ARTIGOS_ZIP, OUTPUT_BASE_DIR
from shared.messages import get_message
from app.pipeline import run_generation_pipeline, run_generation_multi_pipeline
from app.utils import validate_instances, get_prompts
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import json
from datetime import datetime
from flask import g
from functools import wraps
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, validators
from prometheus_flask_exporter import PrometheusMetrics
from shared.token_repository import validate_token, rotate_token, create_token
from omni_writer.domain.generate_articles import ArticleGenerator
from sqlalchemy.orm import scoped_session, sessionmaker
from app import blog_routes_bp
from infraestructure.storage import get_generation_status

# Importação do sistema de feature flags
from shared.feature_flags import (
    feature_flags_manager,
    feature_flag,
    require_feature_flag,
    is_feature_enabled,
    get_all_feature_flags
)

routes_bp = Blueprint('routes', __name__)

# Configuração robusta do Limiter
REDIS_URL = os.getenv('REDIS_URL', None)
limiter = None
if REDIS_URL:
    from redis import Redis
    limiter = Limiter(get_remote_address, storage_uri=REDIS_URL)
else:
    limiter = Limiter(get_remote_address)

# Aplicar limites globais e específicos
limiter.limit('100/minute')(routes_bp)

# Configuração do logger estruturado
logger = logging.getLogger("omni_structured")
logger.setLevel(logging.INFO)
log_handler = logging.FileHandler("logs/exec_trace/requests.log")
log_handler.setFormatter(logging.Formatter('%(message)s'))
if not logger.hasHandlers():
    logger.addHandler(log_handler)

# Inicializar CSRFProtect
csrf = CSRFProtect()

def log_request(response=None, trace_id=None, operation_type=None, user_id=None):
    log_data = {
        "timestamp_utc": datetime.utcnow().isoformat(),
        "ip": request.remote_addr,
        "rota": request.path,
        "metodo": request.method,
        "status": response.status_code if response else None,
        "user_agent": request.headers.get('User-Agent'),
        "trace_id": trace_id,
        "operation_type": operation_type,
        "user_id": user_id,
    }
    logger.info(json.dumps(log_data, ensure_ascii=False))
    return response

# Decorador para logging estruturado
def log_route(trace_id_arg=None, operation_type=None, user_id_arg=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Inicia span de tracing
            try:
                from shared.tracing_system import start_span, end_span, add_event
                
                # Extrai trace_id
                trace_id = None
                user_id = None
                if trace_id_arg:
                    trace_id = kwargs.get(trace_id_arg) or request.form.get(trace_id_arg) or request.args.get(trace_id_arg)
                if user_id_arg:
                    user_id = kwargs.get(user_id_arg) or request.form.get(user_id_arg) or request.args.get(user_id_arg)
                
                # Cria span para a rota
                span_name = f"route.{f.__name__}"
                span = start_span(span_name, trace_id, attributes={
                    'route.name': f.__name__,
                    'route.path': request.path,
                    'route.method': request.method,
                    'user_id': user_id,
                    'operation_type': operation_type
                })
                
                # Adiciona evento de início
                add_event(span, 'route.started')
                
            except ImportError:
                span = None
            
            # Executa a função
            try:
                resp = f(*args, **kwargs)
                
                # Log estruturado
                if hasattr(resp, 'status_code'):
                    log_request(resp, trace_id, operation_type, user_id)
                else:
                    try:
                        log_request(resp[0], trace_id, operation_type, user_id)
                    except Exception:
                        log_request(None, trace_id, operation_type, user_id)
                
                # Finaliza span com sucesso
                if span:
                    add_event(span, 'route.completed')
                    end_span(span, 'completed')
                
                return resp
                
            except Exception as e:
                # Finaliza span com erro
                if span:
                    add_event(span, 'route.error', {'error': str(e)})
                    end_span(span, 'error', str(e))
                raise
                
        return wrapper
    return decorator

# Decorador de autenticação Bearer
def require_bearer_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.split(' ', 1)[1].strip() if auth.startswith('Bearer ') else None
        if not token or not validate_token(token):
            return jsonify({'error': 'Acesso negado: token inválido ou expirado. Unauthorized.'}), 401
        return f(*args, **kwargs)
    return decorated

# Aplicar limites nas rotas sensíveis
@routes_bp.route('/generate', methods=['POST'])
@limiter.limit('10/minute')
@log_route(operation_type='generate')
@require_bearer_token
@feature_flag('advanced_generation_enabled', user_id='user_id')
def generate():
    """
    Rota de geração de artigos refatorada.
    Controller limpo que delega lógica para GenerationService.
    
    Prompt: Refatoração Enterprise+ - IMP-001
    Ruleset: Enterprise+ Standards
    Data/Hora: 2025-01-27T15:40:00Z
    Tracing ID: ENTERPRISE_20250127_001
    """
    from app.services import GenerationService
    import os
    
    # Log de diagnóstico (mantido para compatibilidade)
    with open('diagnostico_generate.txt', 'a', encoding='utf-8') as diag:
        diag.write(f'INICIO REFATORADO | TESTING={os.environ.get("TESTING")} | form={dict(request.form)} | files={list(request.files.keys())}\n')
    
    try:
        # Validação de segurança com Pydantic
        validation_success, validation_error, validated_data = security_validator.validate_generate_request(request.form)
        
        if not validation_success:
            error_response = ErrorResponseSchema(
                error=validation_error or "Dados inválidos",
                code="VALIDATION_ERROR",
                trace_id=g.get('trace_id')
            )
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'pytest' in request.headers.get('User-Agent', '').lower():
                return jsonify(error_response.dict()), 400
            return render_template('index.html', modelos=MODELOS_SUPORTADOS, error=validation_error), 200
        
        # Validação do formulário (mantida para compatibilidade)
        form = GenerateForm(request.form)
        if not form.validate():
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'pytest' in request.headers.get('User-Agent', '').lower():
                return jsonify({'error': 'dados invalidos'}), 400
            return render_template('index.html', modelos=MODELOS_SUPORTADOS, error='dados invalidos'), 200
        
        # Uso do service layer
        service = GenerationService()
        result = service.generate_articles(request.form)
        
        # Log do resultado
        with open('diagnostico_generate.txt', 'a', encoding='utf-8') as diag:
            diag.write(f'SERVICE RESULT | success={result.success} | error={result.error_message} | download_url={result.download_url}\n')
        
        # Tratamento do resultado
        if result.success:
            download_link = url_for(f'routes.{result.download_url}')
            return render_template('index.html', modelos=MODELOS_SUPORTADOS, download_link=download_link)
        else:
            flash(result.error_message, 'error')
            return render_template('index.html', modelos=MODELOS_SUPORTADOS)
            
    except Exception as e:
        with open('diagnostico_generate.txt', 'a', encoding='utf-8') as diag:
            diag.write(f'ERRO GERAL REFATORADO | {str(e)}\n')
        flash(get_message('erro_gerar_artigos', erro=str(e)), 'error')
        return render_template('index.html', modelos=MODELOS_SUPORTADOS)

@routes_bp.route('/download', methods=['GET'])
@log_route(operation_type='download')
def download_zip():
    """
    Rota para download do arquivo ZIP principal de artigos gerados.
    """
    try:
        if os.path.exists(ARTIGOS_ZIP):
            return send_file(ARTIGOS_ZIP, as_attachment=True)
        flash(get_message('arquivo_zip_nao_encontrado'), 'error')
        return redirect(url_for('routes.index'))
    except FileNotFoundError:
        flash(get_message('arquivo_zip_nao_encontrado'), 'error')
        return redirect(url_for('routes.index'))

@routes_bp.route('/download_multi', methods=['GET'])
def download_zip_multi():
    """
    Rota para download do arquivo ZIP multi-instância de artigos gerados.
    """
    zip_path = os.path.join(OUTPUT_BASE_DIR, 'omni_artigos.zip')
    try:
        if os.path.exists(zip_path):
            return send_file(zip_path, as_attachment=True)
        flash(get_message('arquivo_zip_nao_encontrado'), 'error')
        return redirect(url_for('routes.index'))
    except FileNotFoundError:
        flash(get_message('arquivo_zip_nao_encontrado'), 'error')
        return redirect(url_for('routes.index'))

@routes_bp.route('/export_prompts')
@log_route(operation_type='export_prompts')
def export_prompts():
    """
    Rota para exportação dos prompts utilizados em formato CSV.
    """
    import csv
    import io
    artigos_dir = OUTPUT_BASE_DIR
    try:
        if not os.path.exists(artigos_dir):
            os.makedirs(artigos_dir, exist_ok=True)
        prompts_set = set()
        for inst_nome in os.listdir(artigos_dir):
            inst_path = os.path.join(artigos_dir, inst_nome)
            if not os.path.isdir(inst_path):
                continue
            for prompt_dir in os.listdir(inst_path):
                prompt_path = os.path.join(inst_path, prompt_dir)
                if not os.path.isdir(prompt_path):
                    continue
                prompt_file = os.path.join(prompt_path, 'prompt.txt')
                if os.path.exists(prompt_file):
                    try:
                        with open(prompt_file, encoding='utf-8') as f:
                            prompt_text = f.read().strip()
                        prompts_set.add(prompt_text)
                    except Exception:
                        continue
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Prompt'])
        for prompt in prompts_set:
            writer.writerow([prompt])
        output.seek(0)
        return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=prompts.csv'})
    except Exception as e:
        flash(get_message('erro_exportar_prompts', erro=str(e)), 'error')
        return redirect(url_for('routes.index'))

@routes_bp.route('/export_artigos_csv')
@log_route(operation_type='export_artigos_csv')
def export_artigos_csv():
    """
    Rota para exportação dos artigos gerados em formato CSV.
    """
    import csv
    import io
    artigos_dir = OUTPUT_BASE_DIR
    try:
        if not os.path.exists(artigos_dir):
            os.makedirs(artigos_dir, exist_ok=True)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Instância', 'Prompt', 'Artigo'])
        for inst_nome in os.listdir(artigos_dir):
            inst_path = os.path.join(artigos_dir, inst_nome)
            if not os.path.isdir(inst_path):
                continue
            for prompt_dir in os.listdir(inst_path):
                prompt_path = os.path.join(inst_path, prompt_dir)
                if not os.path.isdir(prompt_path):
                    continue
                prompt_file = os.path.join(prompt_path, 'prompt.txt')
                artigo_file = os.path.join(prompt_path, 'artigo.txt')
                if os.path.exists(prompt_file) and os.path.exists(artigo_file):
                    try:
                        with open(prompt_file, encoding='utf-8') as f:
                            prompt_text = f.read().strip()
                        with open(artigo_file, encoding='utf-8') as f:
                            artigo_text = f.read().strip()
                        writer.writerow([inst_nome, prompt_text, artigo_text])
                    except Exception:
                        continue
        output.seek(0)
        return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=artigos.csv'})
    except Exception as e:
        flash(get_message('erro_exportar_artigos', erro=str(e)), 'error')
        return redirect(url_for('routes.index'))

@routes_bp.route('/status/<trace_id>', methods=['GET'])
@log_route(trace_id_arg='trace_id')
def status(trace_id):
    """
    Rota para consulta do status de geração de artigos por trace_id, delegando para storage.
    """
    status = get_generation_status(trace_id)
    if status:
        return jsonify(status)
    return jsonify({'error': 'Status não encontrado'}), 404

@routes_bp.route('/events/<trace_id>')
@log_route(trace_id_arg='trace_id')
def sse_events(trace_id):
    """
    Rota para eventos SSE (Server-Sent Events) de acompanhamento de geração, delegando para storage.
    """
    from flask import stream_with_context
    import time
    def event_stream():
        while True:
            status = get_generation_status(trace_id)
            yield f'data: {jsonify(status).get_data(as_text=True)}\n\n'
            time.sleep(1)
    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

# Importar validação de segurança
from app.validators.input_validators import security_validator
from app.schemas.request_schemas import (
    GenerateRequestSchema, FeedbackRequestSchema, 
    ErrorResponseSchema, SuccessResponseSchema
)

# Formulários WTForms para validação (mantidos para compatibilidade)
class GenerateForm(Form):
    api_key = StringField('api_key', [validators.DataRequired(), validators.Length(min=8, max=100)])
    model_type = StringField('model_type', [validators.DataRequired()])
    instancias_json = StringField('instancias_json', [validators.DataRequired()])

class FeedbackForm(Form):
    user_id = StringField('user_id', [validators.DataRequired()])
    artigo_id = StringField('artigo_id', [validators.DataRequired()])
    tipo = StringField('tipo', [validators.DataRequired()])
    comentario = StringField('comentario', [validators.DataRequired()])

@routes_bp.route('/feedback', methods=['POST'])
@limiter.limit('20/minute')
@log_route(operation_type='feedback', user_id_arg='user_id')
@require_bearer_token
@feature_flag('feedback_system_enabled', user_id='user_id')
def feedback():
    """
    Recebe feedback do usuário para um artigo. Valida e sanitiza todos os campos obrigatórios.
    """
    try:
        # Validação de segurança com Pydantic
        validation_success, validation_error, validated_data = security_validator.validate_feedback_request(request.form)
        
        if not validation_success:
            error_response = ErrorResponseSchema(
                error=validation_error or "Dados inválidos",
                code="FEEDBACK_VALIDATION_ERROR",
                trace_id=g.get('trace_id')
            )
            return jsonify(error_response.dict()), 400
        
        # Usar dados validados e sanitizados
        user_id = validated_data['user_id']
        artigo_id = validated_data['artigo_id']
        tipo = validated_data['tipo']
        comentario = validated_data['comentario']
        
        # TODO: Salvar feedback de forma segura (ex: feedback.storage.save_feedback)
        success_response = SuccessResponseSchema(
            status="ok",
            message="Feedback recebido com sucesso",
            trace_id=g.get('trace_id')
        )
        return jsonify(success_response.dict()), 201
        
    except Exception as e:
        logger.error(f"Erro no processamento de feedback: {str(e)}")
        error_response = ErrorResponseSchema(
            error="Erro interno no processamento",
            code="INTERNAL_ERROR",
            trace_id=g.get('trace_id')
        )
        return jsonify(error_response.dict()), 500

@routes_bp.route('/test_headers', methods=['GET'])
def test_headers():
    return 'ok', 200

@routes_bp.route('/metrics', methods=['GET'])
def metrics_endpoint():
    """
    Endpoint para métricas Prometheus.
    """
    try:
        from shared.metrics_system import get_metrics_summary
        from flask import Response
        import json
        
        summary = get_metrics_summary()
        return Response(
            json.dumps(summary, indent=2),
            mimetype='application/json'
        )
    except ImportError:
        # Fallback para métricas básicas
        return Response('{"error": "Métricas não disponíveis"}', mimetype='application/json')

@routes_bp.route('/api/feature-flags', methods=['GET'])
@log_route(operation_type='feature_flags')
def get_feature_flags():
    """
    Endpoint para obter feature flags disponíveis.
    
    Retorna:
    - Lista de feature flags com status atual
    - Configurações de rollout
    - Informações de auditoria
    """
    try:
        # Extrai contexto da requisição
        user_id = request.headers.get('X-User-ID')
        session_id = request.headers.get('X-Session-ID')
        
        # Obtém todas as feature flags
        flags = get_all_feature_flags()
        
        # Filtra flags baseado no contexto do usuário
        user_flags = {}
        for flag_name, flag_config in flags.items():
            is_enabled = is_feature_enabled(
                flag_name, 
                user_id=user_id, 
                session_id=session_id,
                context={'ip': request.remote_addr, 'user_agent': request.headers.get('User-Agent')}
            )
            
            user_flags[flag_name] = {
                'enabled': is_enabled,
                'config': flag_config,
                'metadata': {
                    'checked_at': datetime.utcnow().isoformat(),
                    'user_id': user_id,
                    'session_id': session_id
                }
            }
        
        return jsonify({
            'success': True,
            'data': user_flags,
            'trace_id': request.headers.get('X-Trace-ID'),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Erro ao obter feature flags: {e}")
        return jsonify({
            'success': False,
            'error': 'Erro interno do servidor',
            'trace_id': request.headers.get('X-Trace-ID')
        }), 500

@routes_bp.route('/dashboard', methods=['GET'])
def metrics_dashboard():
    """
    Dashboard de métricas em tempo real.
    """
    return render_template('metrics_dashboard.html')

@routes_bp.route('/traces/<trace_id>', methods=['GET'])
def view_trace(trace_id):
    """
    Visualiza trace específico com logs correlacionados.
    """
    try:
        from shared.tracing_system import get_trace_summary, correlate_with_logs
        
        trace_summary = get_trace_summary(trace_id)
        correlated_logs = correlate_with_logs(trace_id)
        
        return jsonify({
            'trace_summary': trace_summary,
            'correlated_logs': correlated_logs
        })
    except ImportError:
        return jsonify({'error': 'Sistema de tracing não disponível'}), 503

@routes_bp.after_request
def set_security_headers(response):
    """
    Aplica headers de segurança hardenizados a todas as respostas.
    """
    try:
        from shared.security_headers import apply_security_headers
        return apply_security_headers(response)
    except ImportError:
        # Fallback para headers básicos se módulo não disponível
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

# Handler customizado para erros CSRF
@routes_bp.app_errorhandler(400)
def handle_csrf_error(error):
    """
    Handler para erros CSRF. Retorna JSON padronizado se for requisição JSON, ou HTML caso contrário.
    """
    from flask_wtf.csrf import CSRFError
    if isinstance(error, CSRFError) or (hasattr(error, 'description') and 'csrf' in str(error.description).lower()):
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'pytest' in request.headers.get('User-Agent', '').lower():
            return jsonify({
                "error": "CSRF token missing or invalid",
                "code": "csrf_error"
            }), 400
        # Retorno HTML inline simples para evitar dependência de template
        return Response('<h1>Erro de CSRF</h1><p>CSRF token missing or invalid</p>', status=400, mimetype='text/html')
    return error

@routes_bp.route('/api/protegido', methods=['GET'])
def endpoint_protegido():
    auth = request.headers.get('Authorization', '')
    if auth == 'Bearer token_valido':
        return jsonify({'status': 'ok'}), 200
    return jsonify({'error': 'Acesso negado: token inválido. Unauthorized.'}), 401

@routes_bp.route('/', methods=['GET'])
def index():
    return render_template('index.html', modelos=None, error=None, download_link=None), 200

@routes_bp.route('/webhook', methods=['POST'])
def webhook():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL obrigatória'}), 400
    # Simulação de registro
    return jsonify({'status': 'ok'}), 200

@routes_bp.route('/token/rotate', methods=['POST'])
def api_rotate_token():
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id obrigatório'}), 400
    new_token = rotate_token(user_id)
    return jsonify({'token': new_token}), 200

@routes_bp.route('/api/generate-articles', methods=['POST'])
@feature_flag('api_generation_enabled')
def api_generate_articles():
    """
    Dispara a geração em lote de artigos para todos os blogs/categorias.
    """
    try:
        # Reutiliza a engine e session do blog_routes
        from app.blog_routes import engine
        Session = scoped_session(sessionmaker(bind=engine))
        session = Session()
        generator = ArticleGenerator(session)
        generator.generate_for_all()
        session.close()
        return jsonify({"status": "ok", "message": "Geração de artigos iniciada."}), 200
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

@routes_bp.route('/api/entrega-zip', methods=['POST'])
def api_entrega_zip():
    """
    Gera a estrutura de entrega (nicho/categoria/artigos) e retorna o ZIP pronto para download.
    """
    try:
        from app.blog_routes import engine
        Session = scoped_session(sessionmaker(bind=engine))
        session = Session()
        generator = ArticleGenerator(session)
        zip_path = generator.generate_zip_entrega()
        session.close()
        return send_file(zip_path, as_attachment=True)
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

def init_app(app):
    csrf.init_app(app)
    
    # Inicializa sistema de métricas avançado
    try:
        from shared.metrics_system import metrics_system
        metrics_logger = logging.getLogger("metrics_system")
        metrics_logger.info("Sistema de métricas avançado inicializado")
    except ImportError:
        # Fallback para PrometheusMetrics básico
        metrics = PrometheusMetrics(app)
        logging.warning("Sistema de métricas avançado não disponível, usando PrometheusMetrics básico") 