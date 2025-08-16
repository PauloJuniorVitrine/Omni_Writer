import pytest
from unittest.mock import patch, MagicMock
import shared.token_repository as tr
from datetime import datetime, timedelta
import flask

@pytest.fixture(autouse=True)
def clear_state():
    tr.FAILED_ATTEMPTS.clear()
    tr.BLOCKED.clear()

# Teste is_blocked
def test_is_blocked_false():
    assert not tr.is_blocked('key')

def test_is_blocked_true_and_expired():
    key = 'ip1'
    tr.BLOCKED[key] = datetime.utcnow() + timedelta(seconds=10)
    assert tr.is_blocked(key)
    tr.BLOCKED[key] = datetime.utcnow() - timedelta(seconds=10)
    assert not tr.is_blocked(key)

def test_register_failed_attempt_blocks():
    key = 'ip2'
    for _ in range(tr.MAX_ATTEMPTS):
        tr.register_failed_attempt(key)
    assert tr.is_blocked(key)

def test_log_auth_attempt_success_and_fail():
    app = flask.Flask(__name__)
    with app.test_request_context('/', headers={'User-Agent': 'test'}, environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        tr.log_auth_attempt('token', 'user', True)
        tr.log_auth_attempt('token', 'user', False)
        assert 'token' in tr.FAILED_ATTEMPTS or '1.2.3.4' in tr.FAILED_ATTEMPTS

def test_init_db():
    # Apenas cobre o método, sem side effects
    tr.init_db()

def test_create_token_and_validate(monkeypatch):
    session = MagicMock()
    monkeypatch.setattr(tr, 'Session', lambda: session)
    session.add = MagicMock()
    session.commit = MagicMock()
    session.close = MagicMock()
    monkeypatch.setattr(tr, 'log_auth_attempt', lambda *a, **kw: None)
    token = tr.create_token('user', 1)
    assert isinstance(token, str)

def test_validate_token_blocked(monkeypatch):
    monkeypatch.setattr(tr, 'is_blocked', lambda key: True)
    monkeypatch.setattr(tr, 'log_auth_attempt', lambda *a, **kw: None)
    assert not tr.validate_token('token')

def test_validate_token_valid(monkeypatch):
    class Obj: user_id = 'u'; active = True; expires_at = datetime.utcnow() + timedelta(days=1)
    session = MagicMock()
    session.query().get.return_value = Obj()
    session.close = MagicMock()
    monkeypatch.setattr(tr, 'Session', lambda: session)
    monkeypatch.setattr(tr, 'is_blocked', lambda key: False)
    monkeypatch.setattr(tr, 'log_auth_attempt', lambda *a, **kw: None)
    assert tr.validate_token('token')

def test_validate_token_invalid(monkeypatch):
    class Obj: user_id = 'u'; active = False; expires_at = datetime.utcnow() - timedelta(days=1)
    session = MagicMock()
    session.query().get.return_value = Obj()
    session.close = MagicMock()
    monkeypatch.setattr(tr, 'Session', lambda: session)
    monkeypatch.setattr(tr, 'is_blocked', lambda key: False)
    monkeypatch.setattr(tr, 'log_auth_attempt', lambda *a, **kw: None)
    assert not tr.validate_token('token')

def test_rotate_token(monkeypatch):
    session = MagicMock()
    session.query().filter_by().update = MagicMock()
    session.commit = MagicMock()
    session.close = MagicMock()
    monkeypatch.setattr(tr, 'Session', lambda: session)
    monkeypatch.setattr(tr, 'create_token', lambda user_id: 'tok')
    assert tr.rotate_token('user') == 'tok'

def test_revoke_token(monkeypatch):
    class Obj: active = True
    session = MagicMock()
    session.query().get.return_value = Obj()
    session.commit = MagicMock()
    session.close = MagicMock()
    monkeypatch.setattr(tr, 'Session', lambda: session)
    tr.revoke_token('token') 