"""
Notification Service - Microserviço de Notificações

Responsabilidades:
- Envio de notificações e webhooks
- Gestão de templates de notificação
- Integração com sistemas externos
- Feedback e análise de notificações
- Sistema de filas para notificações

Prompt: IMP-015: Microserviços
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: ENTERPRISE_20250127_015
"""

__version__ = "1.0.0"
__service_name__ = "notification-service"
__description__ = "Microserviço para notificações e webhooks"

from .app import create_app
from .models import Notification, Webhook, NotificationTemplate
from .services import NotificationService, WebhookService
from .controllers import NotificationController

__all__ = [
    'create_app',
    'Notification',
    'Webhook',
    'NotificationTemplate',
    'NotificationService',
    'WebhookService',
    'NotificationController'
] 