import pytest
import requests
from app.celery_worker import gerar_artigos_task
import time

@pytest.mark.integration
def test_openai_gateway_falha(monkeypatch):
    # Monkeypatch para simular falha de requests.post
    def fake_post(*a, **kw):
        raise requests.exceptions.ConnectionError("Simulated failure")
    monkeypatch.setattr(requests, "post", fake_post)
    config = {"api_key": "sk-teste", "model_type": "openai", "prompts": [{"text": "falha gateway", "index": 0}]}
    async_result = gerar_artigos_task.apply_async(args=[config], kwargs={"trace_id": "gateway-falha-test"})
    timeout = 30
    for _ in range(timeout):
        if async_result.ready():
            break
        time.sleep(1)
    assert async_result.ready(), "Tarefa Celery não finalizou em tempo hábil"
    with pytest.raises(Exception):
        async_result.get(timeout=5) 