import pytest
from unittest import mock
import app.utils as utils

# Teste validate_instances: entrada válida
def test_validate_instances_valid():
    valid_json = '[{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]'
    result, error = utils.validate_instances(valid_json)
    assert isinstance(result, list)
    assert error is None
    assert result[0]["nome"] == "inst1"

# Teste validate_instances: entrada inválida
@pytest.mark.parametrize("input_json", [
    "", "[{}", "[{'nome': 'inst1'}]", None
])
def test_validate_instances_invalid(input_json):
    result, error = utils.validate_instances(input_json)
    assert result is None or result == []
    assert error is not None

# Teste get_prompts: request com prompts
@mock.patch("app.utils.request")
def test_get_prompts_valid(mock_request):
    mock_request.form.get.return_value = '["prompt1", "prompt2"]'
    prompts, error = utils.get_prompts(mock_request)
    assert isinstance(prompts, list)
    assert error is None

# Teste get_prompts: request sem prompts
@mock.patch("app.utils.request")
def test_get_prompts_invalid(mock_request):
    mock_request.form.get.return_value = None
    prompts, error = utils.get_prompts(mock_request)
    assert prompts is None or prompts == []
    assert error is not None 