"""
Testes de Integração — DeepSeek Gateway

Cenários cobertos:
- Integração real (ou mockada) com a API DeepSeek.
- Testes de timeout, lentidão e respostas malformadas.
- Testes de autenticação (API key inválida, expirada, etc.).
- Concorrência: múltiplas requisições simultâneas.
- Performance: tempo de resposta sob carga.
- Fallback e logs em cenários de falha real.

Observação: Não misture testes unitários e de integração neste arquivo.
"""

import os
import pytest
import time
from infraestructure import deepseek_gateway
from omni_writer.domain.models import GenerationConfig, PromptInput
import threading

# Exemplo de teste de timeout (mockando requests.post)
def test_deepseek_gateway_timeout(monkeypatch):
    """Testa se o gateway trata timeout corretamente ao chamar a API DeepSeek."""
    def fake_post(*a, **kw):
        time.sleep(2)
        raise Exception("Timeout")
    monkeypatch.setattr("infraestructure.deepseek_gateway.requests.post", fake_post)
    config = GenerationConfig(api_key="k", model_type="deepseek", prompts=[PromptInput(text="t", index=0)])
    with pytest.raises(Exception) as exc:
        deepseek_gateway.generate_article_deepseek(config, config.prompts[0], trace_id="t", variation=0)
    assert "Timeout" in str(exc.value)

# Exemplo de teste de autenticação inválida (mockando requests.post)
def test_deepseek_gateway_api_key_invalida(monkeypatch):
    """Testa se o gateway trata API key inválida corretamente."""
    class FakeResp:
        def raise_for_status(self):
            raise Exception("401 Unauthorized")
        def json(self):
            return {}
    monkeypatch.setattr("infraestructure.deepseek_gateway.requests.post", lambda *a, **kw: FakeResp())
    config = GenerationConfig(api_key="invalida", model_type="deepseek", prompts=[PromptInput(text="t", index=0)])
    with pytest.raises(Exception) as exc:
        deepseek_gateway.generate_article_deepseek(config, config.prompts[0], trace_id="t", variation=0)
    assert "401" in str(exc.value)

# Exemplo de teste de concorrência (múltiplas threads)
def worker_deepseek(config, prompt, results, idx):
    try:
        deepseek_gateway.generate_article_deepseek(config, prompt, trace_id=f"t{idx}", variation=idx)
        results[idx] = True
    except Exception:
        results[idx] = False

def test_deepseek_gateway_concorrencia(monkeypatch):
    """Testa se múltiplas threads conseguem chamar o gateway simultaneamente (mock)."""
    def fake_post(*a, **kw):
        class FakeResp:
            def raise_for_status(self): pass
            def json(self): return {"choices": [{"message": {"content": "ok"}}]}
        return FakeResp()
    monkeypatch.setattr("infraestructure.deepseek_gateway.requests.post", fake_post)
    config = GenerationConfig(api_key="k", model_type="deepseek", prompts=[PromptInput(text="t", index=0)])
    results = [None] * 5
    threads = []
    for i in range(5):
        t = threading.Thread(target=worker_deepseek, args=(config, config.prompts[0], results, i))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    assert all(results) 