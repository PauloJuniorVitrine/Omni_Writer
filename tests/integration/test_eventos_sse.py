import os
import pytest
from app.app_factory import create_app

def test_sse_progresso_valido():
    os.environ['TESTING'] = '1'
    with create_app().test_client() as client:
        trace_id = 'abc123'
        resp = client.get(f"/events/{trace_id}", buffered=True)
        assert resp.status_code == 200
        data = b"".join(resp.response)
        assert b'done' in data 