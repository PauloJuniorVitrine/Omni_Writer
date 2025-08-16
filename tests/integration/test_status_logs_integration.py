import os
import time
import pytest
from app.app_factory import create_app
from app.celery_worker import gerar_artigos_task
from shared.status_repository import get_status
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.mark.integration
def test_status_and_logs(monkeypatch):
    trace_id = 'status-logs-integration-test'
    config = {"api_key": "sk-teste", "model_type": "openai", "prompts": [{"text": "status test", "index": 0}]}
    async_result = gerar_artigos_task.apply_async(args=[config], kwargs={"trace_id": trace_id})
    timeout = 60
    for _ in range(timeout):
        if async_result.ready():
            break
        time.sleep(1)
    assert async_result.ready(), "Tarefa Celery não finalizou em tempo hábil"
    # Consulta status via API
    with client() as client:
        resp = client.get(f'/status/{trace_id}')
        assert resp.status_code == 200
        status = resp.get_json()
        assert status['trace_id'] == trace_id
        assert status['status'] == 'done'
        assert status['total'] >= 1
        assert status['current'] == status['total']
    # Verifica existência de logs
    assert os.path.exists('celery_task_exec.log'), "Log da task Celery não encontrado"
    with open('celery_task_exec.log', encoding='utf-8') as f:
        content = f.read()
        assert trace_id in content, "Trace ID não encontrado no log" 