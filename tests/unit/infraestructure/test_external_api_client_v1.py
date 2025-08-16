import pytest
from infraestructure.external_api_client_v1 import call_external_api
import requests
from unittest.mock import patch

def test_call_external_api_success(monkeypatch):
    class DummyResponse:
        status_code = 200
        def json(self): return {"ok": True}
        def raise_for_status(self): pass
    with patch('requests.get', return_value=DummyResponse()):
        result = call_external_api('/test')
        assert result == {"ok": True}

def test_call_external_api_http_error(monkeypatch):
    class DummyResponse:
        status_code = 500
        def json(self): return {"error": "fail"}
        def raise_for_status(self): raise requests.HTTPError("500")
    with patch('requests.get', return_value=DummyResponse()):
        with pytest.raises(requests.HTTPError):
            call_external_api('/fail')

def test_call_external_api_timeout(monkeypatch):
    with patch('requests.get', side_effect=requests.Timeout):
        with pytest.raises(requests.Timeout):
            call_external_api('/timeout') 