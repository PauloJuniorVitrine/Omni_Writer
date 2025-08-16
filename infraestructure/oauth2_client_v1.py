import os
import requests
import logging
from urllib.parse import urlencode

OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID', 'CHANGEME_CLIENT_ID')
OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET', 'CHANGEME_CLIENT_SECRET')
OAUTH2_PROVIDER_URL = os.getenv('OAUTH2_PROVIDER_URL', 'https://accounts.google.com')
OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://localhost:8000/auth/callback')

logger = logging.getLogger('oauth2_client')

def get_authorization_url(state: str) -> str:
    """Gera URL de autorização OAuth2 para login social."""
    params = {
        'client_id': OAUTH2_CLIENT_ID,
        'redirect_uri': OAUTH2_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent',
    }
    url = f"{OAUTH2_PROVIDER_URL}/o/oauth2/v2/auth?{urlencode(params)}"
    logger.info(f"URL de autorização gerada: {url}")
    return url

def exchange_code_for_token(code: str) -> dict:
    """Troca código de autorização por token de acesso."""
    token_url = f"{OAUTH2_PROVIDER_URL}/oauth2/v4/token"
    data = {
        'code': code,
        'client_id': OAUTH2_CLIENT_ID,
        'client_secret': OAUTH2_CLIENT_SECRET,
        'redirect_uri': OAUTH2_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        logger.info("Token OAuth2 obtido com sucesso")
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Erro ao obter token OAuth2: {e}")
        raise 