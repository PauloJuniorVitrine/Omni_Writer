import logging
from typing import Dict
import os
import requests

logger = logging.getLogger("domain.ia_providers")

class IAProvider:
    """
    Interface base para provedores de IA.
    """
    def generate_article(self, prompt: str, config: Dict) -> str:
        raise NotImplementedError

class OpenAIProvider(IAProvider):
    def generate_article(self, prompt: str, config: Dict) -> str:
        logger.info("Gerando artigo via OpenAI...")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY não configurada.")
            raise RuntimeError("OPENAI_API_KEY não configurada.")
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "system", "content": "Você é um redator sênior de SEO e copywriting."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 2048,
                    "temperature": 0.7
                },
                timeout=60
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            logger.info("Artigo gerado com sucesso via OpenAI.")
            return content
        except Exception as e:
            logger.error(f"Erro ao gerar artigo via OpenAI: {e}")
            raise

class GeminiProvider(IAProvider):
    def generate_article(self, prompt: str, config: Dict) -> str:
        logger.info("Gerando artigo via Gemini...")
        # TODO: Implementar chamada real à API Gemini
        # Exemplo de integração: https://ai.google.dev/tutorials/rest_quickstart
        return f"[Gemini] Artigo gerado para prompt: {prompt[:60]}... (INTEGRAÇÃO REAL PENDENTE)"

class ClaudeProvider(IAProvider):
    def generate_article(self, prompt: str, config: Dict) -> str:
        logger.info("Gerando artigo via Claude Opus...")
        # TODO: Implementar chamada real à API Claude Opus
        # Exemplo de integração: https://docs.anthropic.com/claude/reference/complete_post
        return f"[Claude] Artigo gerado para prompt: {prompt[:60]}... (INTEGRAÇÃO REAL PENDENTE)" 