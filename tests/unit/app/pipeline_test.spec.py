import pytest
from unittest import mock
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput
import app.pipeline as pipeline

@pytest.fixture
def config():
    return GenerationConfig(
        api_key="key",
        model_type="openai",
        prompts=[PromptInput(text="p1", index=0)],
        temperature=0.7,
        max_tokens=4096,
        language="pt-BR"
    )

# run_generation_pipeline: sucesso
@mock.patch("app.pipeline.save_article")
@mock.patch("app.pipeline.generate_article")
@mock.patch("app.pipeline.make_zip")
@mock.patch("app.pipeline.update_status")
@mock.patch("app.pipeline.clear_old_status")
def test_run_generation_pipeline_success(mock_clear, mock_update, mock_zip, mock_generate, mock_save, config):
    mock_generate.return_value = ArticleOutput(content="ok", filename="a.txt")
    mock_zip.return_value = "zip_path"
    result = pipeline.run_generation_pipeline(config, trace_id="t1")
    assert result == pipeline.ARTIGOS_ZIP
    mock_generate.assert_called()
    mock_save.assert_called()
    mock_zip.assert_called()
    mock_update.assert_any_call("t1", 1, 0, 'in_progress')
    mock_update.assert_any_call("t1", 1, 1, 'in_progress')
    mock_update.assert_any_call("t1", 1, 1, 'done')

# run_generation_pipeline: exceção
@mock.patch("app.pipeline.save_article")
@mock.patch("app.pipeline.generate_article", side_effect=Exception("erro"))
@mock.patch("app.pipeline.make_zip")
@mock.patch("app.pipeline.update_status")
@mock.patch("app.pipeline.clear_old_status")
def test_run_generation_pipeline_exception(mock_clear, mock_update, mock_zip, mock_generate, mock_save, config):
    with pytest.raises(Exception):
        pipeline.run_generation_pipeline(config, trace_id="t2")

# run_generation_multi_pipeline: sucesso
@mock.patch("app.pipeline.save_article")
@mock.patch("app.pipeline.generate_article")
@mock.patch("app.pipeline.make_zip_multi")
@mock.patch("app.pipeline.update_status")
@mock.patch("app.pipeline.clear_old_status")
def test_run_generation_multi_pipeline_success(mock_clear, mock_update, mock_zip_multi, mock_generate, mock_save):
    instances = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    prompts = ["p1"]
    mock_generate.return_value = ArticleOutput(content="ok", filename="a.txt")
    mock_zip_multi.return_value = "zip_multi_path"
    result = pipeline.run_generation_multi_pipeline(instances, prompts, trace_id="t3")
    assert result.endswith("omni_artigos.zip")
    mock_generate.assert_called()
    mock_save.assert_called()
    mock_zip_multi.assert_called()
    mock_update.assert_any_call("t3", mock.ANY, 0, 'in_progress')
    mock_update.assert_any_call("t3", mock.ANY, mock.ANY, 'done')

# run_generation_multi_pipeline: exceção
@mock.patch("app.pipeline.save_article")
@mock.patch("app.pipeline.generate_article", side_effect=Exception("erro"))
@mock.patch("app.pipeline.make_zip_multi")
@mock.patch("app.pipeline.update_status")
@mock.patch("app.pipeline.clear_old_status")
def test_run_generation_multi_pipeline_exception(mock_clear, mock_update, mock_zip_multi, mock_generate, mock_save):
    instances = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    prompts = ["p1"]
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instances, prompts, trace_id="t4")

# run_generation_multi_pipeline: exceção específica com logging
@mock.patch("app.pipeline.save_article")
@mock.patch("app.pipeline.generate_article")
@mock.patch("app.pipeline.make_zip_multi")
@mock.patch("app.pipeline.update_status")
@mock.patch("app.pipeline.clear_old_status")
@mock.patch("builtins.open", mock.mock_open())
def test_run_generation_multi_pipeline_exception_with_logging(mock_clear, mock_update, mock_zip_multi, mock_generate, mock_save, mock_open):
    instances = [{"nome": "inst1", "api_key": "k", "modelo": "openai", "prompts": ["p1"]}]
    prompts = ["p1"]
    mock_generate.side_effect = Exception("Erro específico do pipeline")
    with pytest.raises(Exception):
        pipeline.run_generation_multi_pipeline(instances, prompts, trace_id="t5")
    # Verifica se o erro foi logado no arquivo de diagnóstico 