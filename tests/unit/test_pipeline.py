import pytest
from unittest import mock
import os
from app import pipeline
from omni_writer.domain.models import GenerationConfig, PromptInput

def make_config():
    return GenerationConfig(api_key="key", model_type="openai", prompts=[PromptInput(text="t", index=0)])

def test_run_generation_pipeline(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    config = make_config()
    fake_article = mock.Mock()
    m_generate = mock.Mock(return_value=fake_article)
    m_save = mock.Mock()
    m_zip = mock.Mock()
    m_status = mock.Mock()
    m_clear = mock.Mock()
    monkeypatch.setattr(pipeline, "generate_article", m_generate)
    monkeypatch.setattr(pipeline, "save_article", m_save)
    monkeypatch.setattr(pipeline, "make_zip", m_zip)
    monkeypatch.setattr(pipeline, "update_status", m_status)
    monkeypatch.setattr(pipeline, "clear_old_status", m_clear)
    monkeypatch.setattr(pipeline, "ARTIGOS_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "ARTIGOS_ZIP", str(tmp_path / "out.zip"))
    result = pipeline.run_generation_pipeline(config, trace_id="abc")
    assert result == str(tmp_path / "out.zip")
    m_generate.assert_called()
    m_save.assert_called()
    m_zip.assert_called_once()
    m_status.assert_called()
    m_clear.assert_called_once()

def test_run_generation_pipeline_traceid_none(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    config = make_config()
    monkeypatch.setattr(pipeline, "generate_article", mock.Mock())
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline, "ARTIGOS_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "ARTIGOS_ZIP", str(tmp_path / "out.zip"))
    result = pipeline.run_generation_pipeline(config, trace_id=None)
    assert result == str(tmp_path / "out.zip")

def test_run_generation_multi_pipeline(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    instancias = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    fake_article = mock.Mock()
    fake_article.content = "conteudo do artigo gerado"
    fake_article.filename = "artigo_1.txt"
    m_generate = mock.Mock(return_value=fake_article)
    m_save = mock.Mock()
    m_zip_multi = mock.Mock()
    m_status = mock.Mock()
    m_clear = mock.Mock()
    monkeypatch.setattr(pipeline, "generate_article", m_generate)
    monkeypatch.setattr(pipeline, "save_article", m_save)
    monkeypatch.setattr(pipeline, "make_zip_multi", m_zip_multi)
    monkeypatch.setattr(pipeline, "update_status", m_status)
    monkeypatch.setattr(pipeline, "clear_old_status", m_clear)
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    result = pipeline.run_generation_multi_pipeline(instancias, ["p1"], trace_id="abc")
    assert result.endswith("omni_artigos.zip")
    m_generate.assert_called()
    m_save.assert_called()
    m_zip_multi.assert_called_once()
    m_status.assert_called()
    m_clear.assert_called_once()

def test_run_generation_multi_pipeline_empty(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    monkeypatch.setattr(pipeline, "generate_article", mock.Mock())
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip_multi", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    result = pipeline.run_generation_multi_pipeline([], [], trace_id="abc")
    assert result.endswith("omni_artigos.zip")

def test_run_generation_pipeline_testing(monkeypatch, tmp_path):
    os.environ["TESTING"] = "1"
    monkeypatch.setattr(pipeline, "ARTIGOS_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "ARTIGOS_ZIP", str(tmp_path / "out.zip"))
    result = pipeline.run_generation_pipeline(make_config(), trace_id="abc")
    assert result == str(tmp_path / "out.zip")

def test_run_generation_multi_pipeline_testing(monkeypatch, tmp_path):
    os.environ["TESTING"] = "1"
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    result = pipeline.run_generation_multi_pipeline([], [], trace_id="abc")
    assert result.endswith("omni_artigos.zip")

def test_run_generation_pipeline_save_article_exception(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    config = make_config()
    m_generate = mock.Mock()
    m_save = mock.Mock(side_effect=Exception("erro"))
    monkeypatch.setattr(pipeline, "generate_article", m_generate)
    monkeypatch.setattr(pipeline, "save_article", m_save)
    monkeypatch.setattr(pipeline, "make_zip", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline, "ARTIGOS_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "ARTIGOS_ZIP", str(tmp_path / "out.zip"))
    with pytest.raises(Exception):
        pipeline.run_generation_pipeline(config, trace_id="abc")

def test_run_generation_multi_pipeline_make_zip_multi_exception(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    instancias = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    m_generate = mock.Mock()
    m_save = mock.Mock()
    m_zip_multi = mock.Mock(side_effect=Exception("erro_zip"))
    m_status = mock.Mock()
    m_clear = mock.Mock()
    monkeypatch.setattr(pipeline, "generate_article", m_generate)
    monkeypatch.setattr(pipeline, "save_article", m_save)
    monkeypatch.setattr(pipeline, "make_zip_multi", m_zip_multi)
    monkeypatch.setattr(pipeline, "update_status", m_status)
    monkeypatch.setattr(pipeline, "clear_old_status", m_clear)
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instancias, ["p1"], trace_id="abc")

def test_run_generation_multi_pipeline_exception(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    def raise_exc(*a, **kw): raise Exception("erro_multi")
    monkeypatch.setattr(pipeline, "generate_article", raise_exc)
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip_multi", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    instancias = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instancias, ["p1"], trace_id="abc")

def test_run_generation_multi_pipeline_logging_exception(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    instancias = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "generate_article", mock.Mock())
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip_multi", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    # Força erro em os.makedirs
    monkeypatch.setattr(pipeline.os, "makedirs", mock.Mock(side_effect=Exception("erro_makedirs")))
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instancias, ["p1"], trace_id="abc")

def test_run_generation_multi_pipeline_logging_open_exception(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    instancias = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    monkeypatch.setattr(pipeline, "OUTPUT_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "generate_article", mock.Mock())
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip_multi", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline.os, "makedirs", mock.Mock(side_effect=Exception("erro_makedirs")))
    # Força erro ao abrir o arquivo de log
    monkeypatch.setattr("builtins.open", mock.Mock(side_effect=Exception("erro_open")))
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instancias, ["p1"], trace_id="abc")

def test_run_generation_pipeline_empty_prompts(monkeypatch, tmp_path):
    os.environ["TESTING"] = "0"
    config = GenerationConfig(api_key="key", model_type="openai", prompts=[])
    monkeypatch.setattr(pipeline, "generate_article", mock.Mock())
    monkeypatch.setattr(pipeline, "save_article", mock.Mock())
    monkeypatch.setattr(pipeline, "make_zip", mock.Mock())
    monkeypatch.setattr(pipeline, "update_status", mock.Mock())
    monkeypatch.setattr(pipeline, "clear_old_status", mock.Mock())
    monkeypatch.setattr(pipeline, "ARTIGOS_DIR", str(tmp_path))
    monkeypatch.setattr(pipeline, "ARTIGOS_ZIP", str(tmp_path / "out.zip"))
    result = pipeline.run_generation_pipeline(config, trace_id="abc")
    assert result == str(tmp_path / "out.zip") 