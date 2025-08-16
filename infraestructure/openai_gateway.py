"""
OpenAI gateway for article generation.
Handles requests to the OpenAI API and response parsing.
Protected by Circuit Breaker for resilience.
"""
import os
import requests
from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from shared.config import OPENAI_API_URL
from shared.logger import get_logger
from infraestructure.circuit_breaker import circuit_breaker

logger = get_logger(__name__)

@circuit_breaker('ai_providers')
def generate_article_openai(config: GenerationConfig, prompt: PromptInput, trace_id: str = None, variation: int = 0) -> ArticleOutput:
    """
    Generates an article using the OpenAI API based on the provided configuration and prompt.

    Args:
        config (GenerationConfig): Generation configuration (API key, model, etc).
        prompt (PromptInput): Prompt to be used for generation.
        trace_id (str, optional): Trace identifier for logging/tracking.
        variation (int, optional): Variation index for prompt/model.

    Returns:
        ArticleOutput: Generated article output object.

    Raises:
        Exception: Propagates any exception from the API call or response parsing.
    """
    # Mock global para ambiente de teste (inclui xdist)
    if os.environ.get('TESTING', '0') == '1':
        return ArticleOutput(content='Artigo gerado de teste.', filename=f"artigo_{prompt.index+1}_v{variation+1}.txt")
    headers = {
        'Authorization': f'Bearer {config.api_key}',
        'Content-Type': 'application/json',
    }
    variation_instruction = f"\nVariação {variation+1}: gere uma versão diferente do artigo para o mesmo tema." if variation > 0 else ""
    data = {
        'model': 'gpt-4o',
        'messages': [
            {'role': 'system', 'content': f'Gere um artigo longo (mínimo 3500 palavras) em {config.language}.{variation_instruction}'},
            {'role': 'user', 'content': prompt.text},
        ],
        'temperature': config.temperature,
        'max_tokens': config.max_tokens,
    }
    try:
        # Realiza a requisição para a API OpenAI
        response = requests.post(OPENAI_API_URL, headers=headers, json=data, timeout=120)
        response.raise_for_status()
        content = response.json()['choices'][0]['message']['content']
        filename = f"artigo_{prompt.index+1}_v{variation+1}.txt"
        logger.info('', extra={'event': 'openai_generation', 'status': 'success', 'source': 'openai_gateway', 'details': f'Artigo gerado: {filename}', 'trace_id': trace_id})
        return ArticleOutput(content=content, filename=filename)
    except Exception as e:
        # Loga erro detalhado e propaga exceção
        logger.error('', extra={'event': 'openai_generation', 'status': 'error', 'source': 'openai_gateway', 'details': str(e), 'trace_id': trace_id})
        raise 