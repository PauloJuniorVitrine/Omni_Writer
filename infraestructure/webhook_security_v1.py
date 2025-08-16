import hmac
import hashlib
import time
from typing import Any, Dict
from flask import request
import logging

# Configurações (devem ser lidas de variáveis de ambiente em produção)
WEBHOOK_SECRET = 'CHANGEME_SECRET'  # Substituir por variável de ambiente
ALLOWED_IPS = ['127.0.0.1']  # Exemplo, substituir por lista de IPs permitidos
MAX_TIMESTAMP_DIFF = 300  # 5 minutos

logger = logging.getLogger('webhook_security')


def generate_hmac_signature(payload: str, secret: str) -> str:
    """Gera assinatura HMAC-SHA256 para o payload."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def validate_webhook_request(req: Any, secret: str = WEBHOOK_SECRET) -> Dict[str, Any]:
    """Valida assinatura HMAC, timestamp e IP de origem do request."""
    # 1. Validação de IP
    remote_ip = req.remote_addr
    if remote_ip not in ALLOWED_IPS:
        logger.warning(f'IP não permitido: {remote_ip}')
        return {"valid": False, "reason": "IP não permitido"}

    # 2. Validação de timestamp
    timestamp = req.headers.get('X-Timestamp')
    if not timestamp:
        logger.warning('Timestamp ausente')
        return {"valid": False, "reason": "Timestamp ausente"}
    try:
        ts = int(timestamp)
    except ValueError:
        logger.warning('Timestamp inválido')
        return {"valid": False, "reason": "Timestamp inválido"}
    if abs(time.time() - ts) > MAX_TIMESTAMP_DIFF:
        logger.warning('Timestamp fora do intervalo permitido')
        return {"valid": False, "reason": "Timestamp fora do intervalo permitido"}

    # 3. Validação de assinatura HMAC
    signature = req.headers.get('X-Signature')
    if not signature:
        logger.warning('Assinatura ausente')
        return {"valid": False, "reason": "Assinatura ausente"}
    expected_signature = generate_hmac_signature(req.data.decode(), secret)
    if not hmac.compare_digest(signature, expected_signature):
        logger.warning('Assinatura HMAC inválida')
        return {"valid": False, "reason": "Assinatura HMAC inválida"}

    logger.info(f'Webhook validado com sucesso de {remote_ip}')
    return {"valid": True} 