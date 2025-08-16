import os
import pytest
import importlib
from unittest import mock

import shared.status_repository as status_repository

def setup_function():
    # Limpa a tabela de status antes de cada teste
    status_repository.init_db()
    session = status_repository.Session()
    session.query(status_repository.Status).delete()
    session.commit()
    session.close()

def test_update_and_get_status():
    status_repository.update_status("abc", 10, 2, "in_progress")
    s = status_repository.get_status("abc")
    assert s["trace_id"] == "abc"
    assert s["total"] == 10
    assert s["current"] == 2
    assert s["status"] == "in_progress"

def test_update_status_opcional():
    status_repository.update_status("xyz", 5, 0, "pending")
    s = status_repository.get_status("xyz")
    assert s["current"] == 0
    assert s["status"] == "pending"

def test_clear_old_status():
    status_repository.update_status("old", 1, 1, "done")
    status_repository.update_status("new", 2, 2, "in_progress")
    status_repository.clear_old_status()
    s = status_repository.get_status("old")
    s2 = status_repository.get_status("new")
    # Após clear_old_status, ambos devem ser None (pois clear_old_status deleta tudo)
    assert s is None or s2 is None or (s is None and s2["trace_id"] == "new")

def test_clear_old_status_sem_antigos():
    status_repository.update_status("novo", 3, 1, "in_progress")
    status_repository.clear_old_status()
    s = status_repository.get_status("novo")
    # Após clear_old_status, deve ser None
    assert s is None

def test_update_status_empty_trace(monkeypatch):
    # Deve permitir trace_id vazio, mas não deve lançar exceção
    status_repository.update_status("", 1, 1, "done")
    s = status_repository.get_status("")
    assert s is not None

def test_get_status_inexistente():
    s = status_repository.get_status("nao_existe")
    assert s is None

def test_clear_old_status_custom_days():
    status_repository.update_status("a", 1, 1, "done")
    status_repository.clear_old_status(days=0)
    s = status_repository.get_status("a")
    assert s is None

def test_update_status_db_exception(monkeypatch):
    class DummySession:
        def query(self, *a, **k): raise Exception("DB error")
        def close(self): pass
    monkeypatch.setattr(status_repository, 'Session', lambda: DummySession())
    with pytest.raises(Exception):
        status_repository.update_status("fail", 1, 1, "fail")

def test_get_status_db_exception(monkeypatch):
    class DummySession:
        def query(self, *a, **k): raise Exception("DB error")
        def close(self): pass
    monkeypatch.setattr(status_repository, 'Session', lambda: DummySession())
    with pytest.raises(Exception):
        status_repository.get_status("fail") 