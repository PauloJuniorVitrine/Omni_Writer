import pytest
from unittest.mock import patch
from ui.context.AuthContext import AuthProvider, useAuth
from ui.hooks.use_api import useApi

class MockResponse:
    def __init__(self, status, json_data=None):
        self.status = status
        self._json = json_data or {}
        self.ok = status == 200
    async def json(self):
        return self._json

@pytest.fixture
def auth_provider():
    # Simula provider para hooks
    return AuthProvider({"children": None})

@pytest.mark.asyncio
async def test_login_success(monkeypatch):
    # Mock fetch para login bem-sucedido
    async def mock_fetch(url, *args, **kwargs):
        assert url == '/token/rotate'
        return MockResponse(200, {"token": "tok123"})
    with patch('ui.context.AuthContext.fetch', mock_fetch):
        ctx = useAuth()
        await ctx.login('user1', 'senha')
        assert ctx.user == 'user1'
        assert ctx.token == 'tok123'

@pytest.mark.asyncio
async def test_login_fail(monkeypatch):
    # Mock fetch para login com falha
    async def mock_fetch(url, *args, **kwargs):
        return MockResponse(401)
    with patch('ui.context.AuthContext.fetch', mock_fetch):
        ctx = useAuth()
        with pytest.raises(Exception):
            await ctx.login('user2', 'errada')
        assert ctx.user is None
        assert ctx.token is None

@pytest.mark.asyncio
async def test_useapi_injects_token(monkeypatch):
    # Mock fetch para endpoint protegido
    async def mock_fetch(url, options=None):
        assert options['headers']['Authorization'] == 'Bearer tok123'
        return MockResponse(200, {"ok": True})
    with patch('ui.hooks.use_api.fetch', mock_fetch):
        ctx = useAuth()
        ctx.token = 'tok123'
        api = useApi()
        resp = await api.request('/api/protegido')
        assert resp['ok'] is True

@pytest.mark.asyncio
async def test_logout_clears_token():
    ctx = useAuth()
    ctx.user = 'user1'
    ctx.token = 'tok123'
    ctx.logout()
    assert ctx.user is None
    assert ctx.token is None

# Observação: Os testes usam patch/mocks para simular backend e garantir isolamento. Logs são validados manualmente via console. 