import requests
from tenacity import retry, stop_after_attempt, wait_exponential, RetryError
import logging
import os

EXTERNAL_API_URL = os.getenv('EXTERNAL_API_URL', 'https://api.exemplo.com')
EXTERNAL_API_TOKEN = os.getenv('EXTERNAL_API_TOKEN', 'CHANGEME_TOKEN')

logger = logging.getLogger('external_api_client')

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def call_external_api(endpoint: str, payload: dict = None, method: str = 'GET', headers: dict = None, timeout: int = 10):
    """Chama API externa com retries e logging."""
    url = f"{EXTERNAL_API_URL}{endpoint}"
    if headers is None:
        headers = {}
    headers['Authorization'] = f"Bearer {EXTERNAL_API_TOKEN}"
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method == 'POST':
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        else:
            raise ValueError('Método HTTP não suportado')
        logger.info(f"Chamada {method} para {url} - Status: {response.status_code}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Erro ao chamar API externa: {e}")
        raise
    except RetryError as e:
        logger.error(f"Falha após retries: {e}")
        raise 