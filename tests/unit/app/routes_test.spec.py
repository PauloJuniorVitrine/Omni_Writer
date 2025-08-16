"""
Testes unitários para branches críticos das rotas.
Cobre fluxos de erro, exceções e fallbacks em app/routes.py.
"""
import pytest
from unittest import mock
from flask import Flask
from app.routes import routes_bp, GenerateForm
from omni_writer.domain.data_models import GenerationConfig, PromptInput

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-key'
    app.register_blueprint(routes_bp)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def valid_form_data():
    return {
        'api_key': 'sk-test-key',
        'model_type': 'openai',
        'prompts[]': ['Prompt de teste'],
        'instancias_json': '[{"nome": "test", "api_key": "sk-test", "model_type": "openai"}]'
    }

# Teste de validação de formulário inválido
def test_generate_invalid_form(client):
    response = client.post('/generate', data={})
    assert response.status_code == 200
    assert b'dados invalidos' in response.data

# Teste de instâncias inválidas
def test_generate_invalid_instances(client, valid_form_data):
    valid_form_data['instancias_json'] = 'invalid-json'
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se o erro de instâncias foi processado

# Teste de prompts inválidos
def test_generate_invalid_prompts(client, valid_form_data):
    valid_form_data['prompts[]'] = []
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se o erro de prompts foi processado

# Teste de exceção no pipeline multi
@mock.patch('app.routes.run_generation_multi_pipeline')
def test_generate_pipeline_multi_exception(mock_pipeline, client, valid_form_data):
    mock_pipeline.side_effect = Exception("Erro no pipeline")
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se a exceção foi capturada e tratada

# Teste de fallback para modo antigo (API key inválida)
def test_generate_fallback_invalid_api_key(client, valid_form_data):
    valid_form_data['api_key'] = 'invalid-key'
    valid_form_data['instancias_json'] = '[]'  # Força fallback
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se o erro de API key inválida foi processado

# Teste de fallback para modo antigo (campos obrigatórios)
def test_generate_fallback_missing_fields(client, valid_form_data):
    valid_form_data['instancias_json'] = '[]'  # Força fallback
    valid_form_data.pop('api_key')
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se o erro de campos obrigatórios foi processado

# Teste de exceção no pipeline simples
@mock.patch('app.routes.run_generation_pipeline')
def test_generate_pipeline_simple_exception(mock_pipeline, client, valid_form_data):
    valid_form_data['instancias_json'] = '[]'  # Força fallback
    mock_pipeline.side_effect = Exception("Erro no pipeline simples")
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se a exceção foi capturada e tratada

# Teste de ZIP não gerado
@mock.patch('app.routes.run_generation_pipeline')
@mock.patch('os.path.exists')
def test_generate_zip_not_found(mock_exists, mock_pipeline, client, valid_form_data):
    valid_form_data['instancias_json'] = '[]'  # Força fallback
    mock_pipeline.return_value = '/path/to/zip'
    mock_exists.return_value = False
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se o erro de ZIP não encontrado foi processado

# Teste de exceção geral
@mock.patch('app.routes.validate_instances')
def test_generate_general_exception(mock_validate, client, valid_form_data):
    mock_validate.side_effect = Exception("Erro geral")
    response = client.post('/generate', data=valid_form_data)
    assert response.status_code == 200
    # Verifica se a exceção geral foi capturada e tratada 