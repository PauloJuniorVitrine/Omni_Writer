import os
import sys
import pytest
from unittest import mock
import scripts.chaos as chaos
import importlib.util
import runpy

def test_simulate_api_failure(monkeypatch):
    monkeypatch.delenv('OPENAI_API_URL', raising=False)
    monkeypatch.delenv('DEEPSEEK_API_URL', raising=False)
    chaos.simulate_api_failure()
    assert os.environ['OPENAI_API_URL'] == 'http://localhost:9999/fail'
    assert os.environ['DEEPSEEK_API_URL'] == 'http://localhost:9999/fail'

def test_simulate_disk_failure(tmp_path, monkeypatch):
    d = tmp_path / "artigos_gerados"
    d.mkdir()
    monkeypatch.setenv('ARTIGOS_DIR', str(d))
    # Permissão pode não ser suportada em todos OS, mas não deve lançar
    chaos.simulate_disk_failure()
    # Restaura permissão para cleanup
    try:
        os.chmod(str(d), 0o700)
    except Exception:
        pass

def test_simulate_redis_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, 'redis', mock.Mock())
    # Não deve lançar, mesmo se Redis não estiver disponível
    chaos.simulate_redis_failure()

def test_simulate_redis_failure_exception(monkeypatch):
    def raise_import(*args, **kwargs):
        raise Exception('erro')
    monkeypatch.setitem(sys.modules, 'redis', None)
    monkeypatch.setattr('builtins.__import__', lambda name, *a, **k: (_ for _ in ()).throw(Exception('erro')) if name == 'redis' else __import__(name, *a, **k))
    chaos.simulate_redis_failure()

def test_simulate_disk_failure_exception(monkeypatch):
    monkeypatch.setenv('ARTIGOS_DIR', 'artigos_gerados')
    monkeypatch.setattr(os, 'chmod', lambda *a, **k: (_ for _ in ()).throw(Exception('erro')))
    chaos.simulate_disk_failure()

def test_main_argumentos_invalidos(monkeypatch):
    monkeypatch.setattr('sys.argv', ['chaos.py'])
    with pytest.raises(SystemExit):
        chaos.main()
    monkeypatch.setattr('sys.argv', ['chaos.py', 'foo'])
    with pytest.raises(SystemExit):
        chaos.main()

def test_main_redis(monkeypatch):
    monkeypatch.setattr('sys.argv', ['chaos.py', 'redis'])
    monkeypatch.setattr(chaos, 'simulate_redis_failure', lambda: True)
    chaos.main()

def test_main_api(monkeypatch):
    monkeypatch.setattr('sys.argv', ['chaos.py', 'api'])
    monkeypatch.setattr(chaos, 'simulate_api_failure', lambda: True)
    chaos.main()

def test_main_disk(monkeypatch):
    monkeypatch.setattr('sys.argv', ['chaos.py', 'disk'])
    monkeypatch.setattr(chaos, 'simulate_disk_failure', lambda: True)
    chaos.main()

def test_run_as_main(monkeypatch):
    monkeypatch.setattr('sys.argv', ['scripts/chaos.py', 'api'])
    runpy.run_path('scripts/chaos.py', run_name='__main__') 