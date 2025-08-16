import pytest
from app.utils import validate_instances, get_prompts
from flask import Flask, request

class DummyRequest:
    def __init__(self, form):
        self.form = form
        self.files = {}
        self.headers = {}
        self.is_json = False

@pytest.mark.parametrize('input_json,expected_valid', [
    ('[{"api_key": "chavevalida", "modelo": "openai", "prompts": ["Prompt"]}]', True),
    ('[]', True),
    ('{"api_key": "chavevalida"}', False),
    ('', False),
    ('[malformed]', False)
])
def test_validate_instances(input_json, expected_valid):
    instances, error = validate_instances(input_json)
    if expected_valid:
        assert isinstance(instances, list)
        assert error is None
    else:
        assert instances is None or instances == []
        assert error is not None

def test_get_prompts_valid():
    req = DummyRequest({'prompts': 'Prompt válido'})
    prompts, error = get_prompts(req)
    assert isinstance(prompts, list)
    assert error is None

def test_get_prompts_invalid():
    req = DummyRequest({'prompts': ''})
    prompts, error = get_prompts(req)
    assert prompts == []
    assert error is not None 