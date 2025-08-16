"""
User Service - Microserviço de Gestão de Usuários

Responsabilidades:
- Autenticação e autorização de usuários
- Gestão de tokens e sessões
- Validação de permissões
- Gestão de perfis de usuário
- Integração com sistema de feedback

Prompt: IMP-015: Microserviços
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: ENTERPRISE_20250127_015
"""

__version__ = "1.0.0"
__service_name__ = "user-service"
__description__ = "Microserviço para gestão de usuários e autenticação"

from .app import create_app
from .models import User, Token, Permission
from .services import UserAuthService, TokenService
from .controllers import UserController

__all__ = [
    'create_app',
    'User',
    'Token',
    'Permission',
    'UserAuthService',
    'TokenService',
    'UserController'
] 