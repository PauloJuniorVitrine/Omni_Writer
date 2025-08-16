import pytest
import os
from unittest import mock
import shared.config as config_mod

def test_artigos_dir_default():
    assert hasattr(config_mod, "ARTIGOS_DIR")
    assert isinstance(config_mod.ARTIGOS_DIR, str)

def test_artigos_zip_default():
    assert hasattr(config_mod, "ARTIGOS_ZIP")
    assert isinstance(config_mod.ARTIGOS_ZIP, str)

def test_output_base_dir_default():
    assert hasattr(config_mod, "OUTPUT_BASE_DIR")
    assert isinstance(config_mod.OUTPUT_BASE_DIR, str)

# Teste de leitura de variável de ambiente
@mock.patch.dict(os.environ, {"ARTIGOS_DIR": "/tmp/test_dir"})
def test_env_override_artigos_dir():
    import importlib
    import sys
    if "shared.config" in sys.modules:
        del sys.modules["shared.config"]
    cfg = importlib.import_module("shared.config")
    assert cfg.ARTIGOS_DIR == "/tmp/test_dir" 