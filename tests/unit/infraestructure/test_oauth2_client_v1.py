import pytest
from infraestructure.oauth2_client_v1 import get_authorization_url, exchange_code_for_token, OAUTH2_CLIENT_ID, OAUTH2_REDIRECT_URI
from unittest.mock import patch
import requests

def test_get_authorization_url():
    state = 'abc123'
    url = get_authorization_url(state)
    assert OAUTH2_CLIENT_ID in url
    assert OAUTH2_REDIRECT_URI in url
    assert f'state={state}' in url

def test_exchange_code_for_token_success():
    dummy_token = {'access_token': 'tok', 'id_token': 'idtok'}
    class DummyResponse:
        def raise_for_status(self): pass
        def json(self): return dummy_token
    with patch('requests.post', return_value=DummyResponse()):
        result = exchange_code_for_token('code123')
        assert result == dummy_token

def test_exchange_code_for_token_error():
    class DummyResponse:
        def raise_for_status(self): raise requests.HTTPError('fail')
        def json(self): return {}
    with patch('requests.post', return_value=DummyResponse()):
        with pytest.raises(requests.HTTPError):
            exchange_code_for_token('badcode') 