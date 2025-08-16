"""
Módulo de Microserviços - Omni Writer

Este módulo contém a implementação dos microserviços separados por domínio de negócio:
- Article Service: Geração, armazenamento e consulta de artigos
- User Service: Gestão de usuários, autenticação e autorização
- Notification Service: Notificações e webhooks

Prompt: IMP-015: Microserviços
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: ENTERPRISE_20250127_015
"""

__version__ = "1.0.0"
__author__ = "Omni Writer Team"
__description__ = "Microserviços para Omni Writer"

# Configurações dos microserviços
SERVICE_CONFIG = {
    "article_service": {
        "port": 5001,
        "host": "0.0.0.0",
        "name": "article-service",
        "version": "1.0.0"
    },
    "user_service": {
        "port": 5002,
        "host": "0.0.0.0", 
        "name": "user-service",
        "version": "1.0.0"
    },
    "notification_service": {
        "port": 5003,
        "host": "0.0.0.0",
        "name": "notification-service", 
        "version": "1.0.0"
    }
}

# Configurações de comunicação entre serviços
INTER_SERVICE_CONFIG = {
    "timeout": 30,
    "retries": 3,
    "circuit_breaker": {
        "failure_threshold": 5,
        "recovery_timeout": 60,
        "expected_exception": Exception
    }
}

# Endpoints de comunicação
SERVICE_ENDPOINTS = {
    "article_service": "http://article-service:5001",
    "user_service": "http://user-service:5002", 
    "notification_service": "http://notification-service:5003"
} 