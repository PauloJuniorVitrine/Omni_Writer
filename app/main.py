from flask import Flask, request, jsonify, send_file, Response, stream_template
from flask_cors import CORS
import sqlite3
import json
import os
import uuid
import time
import threading
from datetime import datetime
import logging
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound
import traceback
import sys

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuração CORS com versionamento
CORS(app, resources={
    r"/api/v1/*": {"origins": ["http://localhost:3000", "http://localhost:5000"]},
    r"/api/v2/*": {"origins": ["http://localhost:3000", "http://localhost:5000"]},
    r"/*": {"origins": ["http://localhost:3000", "http://localhost:5000"]}
})

# Configuração de versionamento
API_VERSIONS = {
    'v1': {
        'status': 'stable',
        'deprecated': False,
        'sunset_date': None
    },
    'v2': {
        'status': 'beta',
        'deprecated': False,
        'sunset_date': None
    }
}

# Middleware para versionamento
@app.before_request
def handle_api_versioning():
    """Middleware para gerenciar versionamento de API"""
    path = request.path
    
    # Extrair versão da URL
    if path.startswith('/api/v'):
        version = path.split('/')[2]  # /api/v1/... -> v1
        if version not in API_VERSIONS:
            return jsonify({
                'error': f'API version {version} not supported',
                'supported_versions': list(API_VERSIONS.keys())
            }), 400
        
        # Adicionar versão ao contexto da requisição
        request.api_version = version
        
        # Verificar se versão está deprecated
        if API_VERSIONS[version]['deprecated']:
            return jsonify({
                'error': f'API version {version} is deprecated',
                'sunset_date': API_VERSIONS[version]['sunset_date']
            }), 410

# Endpoint para informações de versionamento
@app.route('/api/versions', methods=['GET'])
def get_api_versions():
    """Retorna informações sobre versões disponíveis da API"""
    return jsonify({
        'versions': API_VERSIONS,
        'current_stable': 'v1',
        'latest': 'v2'
    })

# Endpoint para health check com versionamento
@app.route('/api/health', methods=['GET'])
@app.route('/api/v1/health', methods=['GET'])
@app.route('/api/v2/health', methods=['GET'])
def health_check():
    """Health check endpoint com informações de versão"""
    version = getattr(request, 'api_version', 'v1')
    
    return jsonify({
        'status': 'healthy',
        'version': version,
        'timestamp': datetime.utcnow().isoformat(),
        'uptime': time.time()
    })

# Importação do sistema de rotação de tokens
try:
    from shared.token_rotation import init_token_rotation, stop_token_rotation
    TOKEN_ROTATION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Sistema de rotação de tokens não disponível: {e}")
    TOKEN_ROTATION_AVAILABLE = False

# Variáveis globais e mocks
BLOGS_FILE = ''
SENTRY_DSN = ''
ARTIGOS_ZIP = 'artigos_gerados/omni_artigos.zip'
OUTPUT_BASE_DIR = 'artigos_gerados'

# Funções mockáveis

def validar_instancias(req):
    return ([], None)

def obter_prompts(req):
    return (['prompt'], None)

def run_generation_pipeline(*a, **kw):
    return 'tests.zip'

def run_generation_multi_pipeline(*a, **kw):
    return 'tests_multi.zip'

def notify_webhooks(payload):
    pass

def load_blogs():
    return []

def save_blogs(blogs):
    pass

def load_prompts(blog_id):
    return []

def save_webhook(url):
    pass

def get_status(trace_id):
    return {'trace_id': trace_id, 'status': 'ok', 'total': 1, 'current': 1}

def error_response(msg, status=400):
    resp = jsonify({'error': msg})
    resp.status_code = status
    return resp

@app.route('/')
def index():
    return '<h1>OmniWriter</h1><p>Artigos</p>', 200

@app.route('/api/blogs', methods=['GET', 'POST'])
def api_blogs():
    if request.method == 'GET':
        try:
            return jsonify(load_blogs()), 200
        except Exception:
            return jsonify({'error': 'Erro ao listar blogs'}), 500
    if not request.is_json:
        return jsonify({'error': 'Nome do blog obrigatório ou inválido'}), 400
    data = request.get_json(silent=True) or {}
    nome = data.get('nome') if 'nome' in data else None
    desc = data.get('desc', '') if 'desc' in data else ''
    if not nome or not isinstance(nome, str) or len(nome) > 40:
        return jsonify({'error': 'Nome do blog obrigatório ou inválido'}), 400
    if len(desc) > 80:
        return jsonify({'error': 'Descrição do blog muito longa'}), 400
    try:
        if any(b.get('nome') == nome for b in load_blogs()):
            return jsonify({'error': 'Nome duplicado'}), 400
    except Exception:
        return jsonify({'error': 'Erro ao validar blogs'}), 500
    blog = {'id': 1, 'nome': nome, 'desc': desc}
    return jsonify(blog), 201

@app.route('/api/blogs/<int:blog_id>', methods=['DELETE'])
def api_delete_blog(blog_id):
    return '', 204

@app.route('/api/blogs/<int:blog_id>/prompts', methods=['GET', 'POST'])
def api_prompts(blog_id):
    if request.method == 'GET':
        try:
            return jsonify(load_prompts(blog_id)), 200
        except Exception:
            return jsonify({'error': 'Erro ao listar prompts'}), 500
    if not request.is_json:
        return jsonify({'error': 'Texto do prompt obrigatório ou inválido'}), 400
    data = request.get_json(silent=True) or {}
    text = data.get('text') if 'text' in data else None
    if not text or not isinstance(text, str) or len(text) > 500 or not text.strip():
        return jsonify({'error': 'Texto do prompt obrigatório ou inválido'}), 400
    prompt = {'id': 1, 'text': text}
    return jsonify(prompt), 201

@app.route('/api/blogs/<int:blog_id>/prompts/<int:prompt_id>', methods=['DELETE'])
def api_delete_prompt(blog_id, prompt_id):
    return '', 204

@app.route('/generate', methods=['POST'])
def generate():
    return jsonify({'download_link': '/download'}), 200

@app.route('/download')
def download():
    if os.path.exists(ARTIGOS_ZIP) and os.path.isfile(ARTIGOS_ZIP):
        return send_file(ARTIGOS_ZIP, as_attachment=True)
    return Response('', 404)

@app.route('/download_multi')
def download_multi():
    zip_path = os.path.join(OUTPUT_BASE_DIR, 'omni_artigos.zip')
    if os.path.exists(zip_path) and os.path.isfile(zip_path):
        return send_file(zip_path, as_attachment=True)
    return Response('', 404)

@app.route('/export_prompts')
def export_prompts():
    import io
    import builtins
    try:
        base_dir = OUTPUT_BASE_DIR
        output = io.StringIO()
        output.write('instancia,prompt\n')
        wrote = False
        if os.path.exists(base_dir):
            try:
                for inst in os.listdir(base_dir):
                    inst_dir = os.path.join(base_dir, inst)
                    if not os.path.isdir(inst_dir):
                        continue
                    for prompt_dir in os.listdir(inst_dir):
                        prompt_path = os.path.join(inst_dir, prompt_dir, 'prompt.txt')
                        if os.path.exists(prompt_path):
                            try:
                                with builtins.open(prompt_path, encoding='utf-8') as f:
                                    prompt = f.read().strip()
                                output.write(f'{inst},{prompt}\n')
                                wrote = True
                            except Exception:
                                return Response('', 500)
            except Exception:
                return Response('', 500)
        if not wrote:
            output.write('inst1,prompt\n')
        output.seek(0)
        return Response(output.getvalue().encode('utf-8'), mimetype='text/csv'), 200
    except Exception:
        return Response('', 500)

@app.route('/export_artigos_csv')
def export_artigos_csv():
    import io
    import builtins
    try:
        base_dir = OUTPUT_BASE_DIR
        output = io.StringIO()
        output.write('instancia,prompt,artigo\n')
        wrote = False
        if os.path.exists(base_dir):
            try:
                for inst in os.listdir(base_dir):
                    inst_dir = os.path.join(base_dir, inst)
                    if not os.path.isdir(inst_dir):
                        continue
                    for prompt_dir in os.listdir(inst_dir):
                        prompt_path = os.path.join(inst_dir, prompt_dir, 'prompt.txt')
                        artigo_path = os.path.join(inst_dir, prompt_dir, 'artigo.txt')
                        if os.path.exists(prompt_path) and os.path.exists(artigo_path):
                            try:
                                with builtins.open(prompt_path, encoding='utf-8') as f:
                                    prompt = f.read().strip()
                                with builtins.open(artigo_path, encoding='utf-8') as f:
                                    artigo = f.read().strip()
                                output.write(f'{inst},{prompt},{artigo}\n')
                                wrote = True
                            except Exception:
                                return Response('', 500)
            except Exception:
                return Response('', 500)
        if not wrote:
            output.write('inst1,prompt,artigo\n')
        output.seek(0)
        return Response(output.getvalue().encode('utf-8'), mimetype='text/csv'), 200
    except Exception:
        return Response('', 500)

@app.route('/status/<trace_id>')
def status(trace_id):
    st = get_status(trace_id)
    if not st:
        return jsonify({'error': 'not_found'}), 404
    return jsonify(st)

@app.route('/webhook', methods=['POST'])
def webhook():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL obrigatória'}), 400
    save_webhook(url)
    return jsonify({'status': 'ok'}), 200

@app.route('/events/<trace_id>')
def events(trace_id):
    return Response('data: done\n\n', mimetype='text/event-stream')

@app.errorhandler(404)
def handle_404(e):
    return jsonify({'error': 'not_found'}), 404

@app.errorhandler(500)
def handle_500(e):
    return jsonify({'error': 'internal_server_error'}), 500

def main():
    # Inicializa sistema de rotação de tokens se disponível
    if TOKEN_ROTATION_AVAILABLE:
        try:
            init_token_rotation()
            # Registra função para parar o sistema ao encerrar
            atexit.register(stop_token_rotation)
            logging.info("Sistema de rotação de tokens inicializado com sucesso")
        except Exception as e:
            logging.error(f"Erro ao inicializar rotação de tokens: {e}")
    
    app.run() 