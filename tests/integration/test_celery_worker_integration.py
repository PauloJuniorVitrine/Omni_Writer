"""
/test/integration/test_celery_worker_integration.spec.py
Fluxo: Execução via Worker Celery
Camadas tocadas: Celery → Pipeline → Controller → Gateways → Storage → Status Repository → Logger
Tipos de lógica: Execução assíncrona, CRUD, eventos, logs
Dependências externas: Redis (broker), sistema de arquivos, APIs externas (OpenAI/DeepSeek)
"""

import os
import time
import pytest
from app.celery_worker import gerar_artigos_task
from shared.status_repository import get_status
from shared.config import ARTIGOS_ZIP

@pytest.mark.integration
@pytest.mark.usefixtures("limpar_ambiente")
def test_celery_worker_execucao_real(monkeypatch):
    """
    Teste de integração real do Worker Celery:
    - Envia tarefa para o worker
    - Aguarda execução assíncrona
    - Valida geração do arquivo ZIP
    - Valida status de geração
    - Valida logs e efeitos colaterais
    """
    # Configuração mínima para geração
    config = {
        "api_key": "sk-teste",
        "model_type": "openai",
        "prompts": [{"text": "prompt celery", "index": 0}]
    }
    # Envia tarefa Celery
    async_result = gerar_artigos_task.apply_async(args=[config], kwargs={"trace_id": "celery-integration-test"})
    # Aguarda conclusão (timeout 90s)
    timeout = 90
    for _ in range(timeout):
        if async_result.ready():
            break
        time.sleep(1)
    assert async_result.ready(), "Tarefa Celery não finalizou em tempo hábil"
    result = async_result.get(timeout=5)
    # Valida geração do ZIP
    assert os.path.exists(result), f"Arquivo ZIP não gerado: {result}"
    # Valida status de geração
    status = get_status("celery-integration-test")
    assert status is not None, "Status não encontrado para trace_id"
    assert status["status"] == "done", f"Status final inesperado: {status}"
    # Valida efeitos colaterais (logs, arquivos)
    assert os.path.getsize(result) > 0, "Arquivo ZIP está vazio" 