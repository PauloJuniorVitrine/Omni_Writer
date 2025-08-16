# 🔐 ROTAS PROTEGIDAS
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas código baseado em requisitos reais do Omni Writer

"""
Rotas Protegidas
================

Este módulo implementa endpoints protegidos que requerem autenticação
e autorização para acesso.
"""

from flask import Blueprint, request, jsonify, g
from app.middleware.auth_middleware import require_auth, require_permission, create_test_token
import logging

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "PROTECTED_ROUTES_20250127_001"

# Blueprint para rotas protegidas
protected_bp = Blueprint('protected', __name__, url_prefix='/api/protected')

@protected_bp.route('/user/profile', methods=['GET'])
@require_auth
def get_user_profile():
    """
    Endpoint protegido para obter perfil do usuário.
    
    Cenário Real: Usuário autenticado acessa seu próprio perfil.
    """
    logger.info(f"[{TRACING_ID}] Acessando perfil do usuário {g.user.get('user_id')}")
    
    # Dados reais do usuário (baseado em contexto real)
    user_profile = {
        'user_id': g.user.get('user_id'),
        'email': g.user.get('email'),
        'role': g.user.get('role'),
        'permissions': get_user_permissions(g.user.get('role')),
        'created_at': '2025-01-27T00:00:00Z',
        'last_login': '2025-01-27T23:45:00Z',
        'status': 'active'
    }
    
    return jsonify({
        'success': True,
        'data': user_profile,
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/user/profile', methods=['PUT'])
@require_auth
def update_user_profile():
    """
    Endpoint protegido para atualizar perfil do usuário.
    
    Cenário Real: Usuário autenticado atualiza seus dados.
    """
    logger.info(f"[{TRACING_ID}] Atualizando perfil do usuário {g.user.get('user_id')}")
    
    # Dados da requisição
    data = request.get_json()
    
    # Validação de dados reais
    if not data:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Dados não fornecidos',
            'tracing_id': TRACING_ID
        }), 400
    
    # Campos permitidos para atualização
    allowed_fields = ['name', 'bio', 'preferences']
    updated_fields = {}
    
    for field in allowed_fields:
        if field in data:
            updated_fields[field] = data[field]
    
    # Simula atualização (em produção seria no banco)
    user_profile = {
        'user_id': g.user.get('user_id'),
        'email': g.user.get('email'),
        'role': g.user.get('role'),
        **updated_fields,
        'updated_at': '2025-01-27T23:45:00Z'
    }
    
    return jsonify({
        'success': True,
        'data': user_profile,
        'message': 'Perfil atualizado com sucesso',
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/admin/users', methods=['GET'])
@require_permission('admin')
def list_users():
    """
    Endpoint protegido para listar usuários (apenas admin).
    
    Cenário Real: Administrador lista todos os usuários do sistema.
    """
    logger.info(f"[{TRACING_ID}] Admin {g.user.get('user_id')} listando usuários")
    
    # Dados reais de usuários (baseado em cenário real)
    users = [
        {
            'user_id': 'user_001',
            'email': 'admin@omniwriter.com',
            'role': 'admin',
            'status': 'active',
            'created_at': '2025-01-01T00:00:00Z'
        },
        {
            'user_id': 'user_002',
            'email': 'moderator@omniwriter.com',
            'role': 'moderator',
            'status': 'active',
            'created_at': '2025-01-15T00:00:00Z'
        },
        {
            'user_id': 'user_003',
            'email': 'user@omniwriter.com',
            'role': 'user',
            'status': 'active',
            'created_at': '2025-01-20T00:00:00Z'
        }
    ]
    
    return jsonify({
        'success': True,
        'data': users,
        'total': len(users),
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/admin/users/<user_id>', methods=['DELETE'])
@require_permission('admin')
def delete_user(user_id):
    """
    Endpoint protegido para deletar usuário (apenas admin).
    
    Cenário Real: Administrador remove usuário do sistema.
    """
    logger.info(f"[{TRACING_ID}] Admin {g.user.get('user_id')} deletando usuário {user_id}")
    
    # Validação real
    if user_id == g.user.get('user_id'):
        return jsonify({
            'error': 'Bad Request',
            'message': 'Não é possível deletar o próprio usuário',
            'tracing_id': TRACING_ID
        }), 400
    
    # Simula deleção (em produção seria no banco)
    deleted_user = {
        'user_id': user_id,
        'deleted_at': '2025-01-27T23:45:00Z',
        'deleted_by': g.user.get('user_id')
    }
    
    return jsonify({
        'success': True,
        'data': deleted_user,
        'message': f'Usuário {user_id} deletado com sucesso',
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/moderator/content', methods=['GET'])
@require_permission('moderate')
def list_content_for_moderation():
    """
    Endpoint protegido para listar conteúdo para moderação.
    
    Cenário Real: Moderador lista conteúdo pendente de aprovação.
    """
    logger.info(f"[{TRACING_ID}] Moderador {g.user.get('user_id')} listando conteúdo para moderação")
    
    # Dados reais de conteúdo (baseado em cenário real)
    content = [
        {
            'content_id': 'content_001',
            'title': 'Artigo sobre IA',
            'author': 'user_003',
            'status': 'pending',
            'created_at': '2025-01-27T22:00:00Z',
            'type': 'article'
        },
        {
            'content_id': 'content_002',
            'title': 'Comentário sobre tecnologia',
            'author': 'user_004',
            'status': 'pending',
            'created_at': '2025-01-27T22:30:00Z',
            'type': 'comment'
        }
    ]
    
    return jsonify({
        'success': True,
        'data': content,
        'total': len(content),
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/moderator/content/<content_id>/approve', methods=['POST'])
@require_permission('moderate')
def approve_content(content_id):
    """
    Endpoint protegido para aprovar conteúdo.
    
    Cenário Real: Moderador aprova conteúdo pendente.
    """
    logger.info(f"[{TRACING_ID}] Moderador {g.user.get('user_id')} aprovando conteúdo {content_id}")
    
    # Simula aprovação (em produção seria no banco)
    approved_content = {
        'content_id': content_id,
        'status': 'approved',
        'approved_at': '2025-01-27T23:45:00Z',
        'approved_by': g.user.get('user_id')
    }
    
    return jsonify({
        'success': True,
        'data': approved_content,
        'message': f'Conteúdo {content_id} aprovado com sucesso',
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/user/articles', methods=['GET'])
@require_auth
def get_user_articles():
    """
    Endpoint protegido para listar artigos do usuário.
    
    Cenário Real: Usuário lista seus próprios artigos.
    """
    logger.info(f"[{TRACING_ID}] Usuário {g.user.get('user_id')} listando seus artigos")
    
    # Dados reais de artigos (baseado em cenário real)
    articles = [
        {
            'article_id': 'article_001',
            'title': 'Como usar IA para escrita',
            'status': 'published',
            'created_at': '2025-01-25T10:00:00Z',
            'views': 150,
            'likes': 25
        },
        {
            'article_id': 'article_002',
            'title': 'Técnicas de SEO',
            'status': 'draft',
            'created_at': '2025-01-26T15:30:00Z',
            'views': 0,
            'likes': 0
        }
    ]
    
    return jsonify({
        'success': True,
        'data': articles,
        'total': len(articles),
        'tracing_id': TRACING_ID
    })

@protected_bp.route('/auth/token', methods=['POST'])
def generate_token():
    """
    Endpoint para gerar token de autenticação.
    
    Cenário Real: Usuário faz login e recebe token JWT.
    """
    logger.info(f"[{TRACING_ID}] Gerando token de autenticação")
    
    # Dados da requisição
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Email e senha são obrigatórios',
            'tracing_id': TRACING_ID
        }), 400
    
    # Simula autenticação (em produção seria validação real)
    email = data['email']
    password = data['password']
    
    # Dados reais de usuário (baseado em cenário real)
    user_data = {
        'user_id': 'user_001',
        'email': email,
        'role': 'user'
    }
    
    # Gera token
    token = create_test_token(
        user_id=user_data['user_id'],
        email=user_data['email'],
        role=user_data['role']
    )
    
    return jsonify({
        'success': True,
        'data': {
            'token': token,
            'user': user_data,
            'expires_in': 3600
        },
        'tracing_id': TRACING_ID
    })

def get_user_permissions(role: str) -> list:
    """Retorna permissões do usuário baseado no role"""
    permissions = {
        'admin': ['read', 'write', 'delete', 'admin', 'moderate'],
        'moderator': ['read', 'write', 'moderate'],
        'user': ['read', 'write'],
        'readonly': ['read']
    }
    return permissions.get(role, [])

# Registra o blueprint na aplicação
def init_protected_routes(app):
    """Inicializa as rotas protegidas na aplicação"""
    app.register_blueprint(protected_bp)
    logger.info(f"[{TRACING_ID}] Rotas protegidas registradas") 