import pytest
from flask import Flask, request
from infraestructure.webhook_security_v1 import validate_webhook_request, generate_hmac_signature, WEBHOOK_SECRET

class DummyRequest:
    def __init__(self, data, headers, remote_addr):
        self.data = data.encode()
        self.headers = headers
        self.remote_addr = remote_addr

def test_valid_webhook(monkeypatch):
    payload = '{"msg": "ok"}'
    ts = str(int(__import__('time').time()))
    signature = generate_hmac_signature(payload, WEBHOOK_SECRET)
    req = DummyRequest(payload, {'X-Timestamp': ts, 'X-Signature': signature}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is True

def test_invalid_ip():
    payload = '{"msg": "ok"}'
    ts = str(int(__import__('time').time()))
    signature = generate_hmac_signature(payload, WEBHOOK_SECRET)
    req = DummyRequest(payload, {'X-Timestamp': ts, 'X-Signature': signature}, '8.8.8.8')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'IP não permitido'

def test_missing_timestamp():
    payload = '{"msg": "ok"}'
    signature = generate_hmac_signature(payload, WEBHOOK_SECRET)
    req = DummyRequest(payload, {'X-Signature': signature}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'Timestamp ausente'

def test_invalid_timestamp():
    payload = '{"msg": "ok"}'
    req = DummyRequest(payload, {'X-Timestamp': 'notanumber', 'X-Signature': 'abc'}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'Timestamp inválido'

def test_expired_timestamp():
    payload = '{"msg": "ok"}'
    ts = str(int(__import__('time').time()) - 10000)
    signature = generate_hmac_signature(payload, WEBHOOK_SECRET)
    req = DummyRequest(payload, {'X-Timestamp': ts, 'X-Signature': signature}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'Timestamp fora do intervalo permitido'

def test_missing_signature():
    payload = '{"msg": "ok"}'
    ts = str(int(__import__('time').time()))
    req = DummyRequest(payload, {'X-Timestamp': ts}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'Assinatura ausente'

def test_invalid_signature():
    payload = '{"msg": "ok"}'
    ts = str(int(__import__('time').time()))
    req = DummyRequest(payload, {'X-Timestamp': ts, 'X-Signature': 'invalid'}, '127.0.0.1')
    result = validate_webhook_request(req)
    assert result['valid'] is False
    assert result['reason'] == 'Assinatura HMAC inválida' 