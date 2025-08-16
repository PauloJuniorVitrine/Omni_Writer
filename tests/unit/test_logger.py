import logging
import json
import pytest
from shared.logger import JsonFormatter, get_logger, export_metrics, METRICS

def test_json_formatter_success_event():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Mensagem",
        args=(),
        exc_info=None
    )
    record.event = "openai_generation"
    record.status = "success"
    record.source = "test"
    record.details = "detalhe"
    record.trace_id = "abc"
    formatter = JsonFormatter()
    out = formatter.format(record)
    data = json.loads(out)
    assert data["event"] == "openai_generation"
    assert data["status"] == "success"
    assert data["trace_id"] == "abc"
    assert METRICS["artigos_gerados"] >= 1

def test_json_formatter_error_event():
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="",
        lineno=0,
        msg="Mensagem",
        args=(),
        exc_info=None
    )
    record.event = "openai_generation"
    record.status = "error"
    formatter = JsonFormatter()
    out = formatter.format(record)
    data = json.loads(out)
    assert data["status"] == "error"
    assert METRICS["falhas_geracao"] >= 1

def test_get_logger_returns_logger():
    logger = get_logger("test_logger")
    assert isinstance(logger, logging.Logger)
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

def test_export_metrics_json():
    out = export_metrics()
    data = json.loads(out)
    assert "artigos_gerados" in data
    assert "falhas_geracao" in data

def test_json_formatter_pipeline_event():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Mensagem",
        args=(),
        exc_info=None
    )
    record.event = "pipeline"
    record.status = "success"
    formatter = JsonFormatter()
    before = METRICS["execucoes_pipeline"]
    formatter.format(record)
    after = METRICS["execucoes_pipeline"]
    assert after == before + 1

def test_json_formatter_pipeline_multi_event():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Mensagem",
        args=(),
        exc_info=None
    )
    record.event = "pipeline_multi"
    record.status = "success"
    formatter = JsonFormatter()
    before = METRICS["execucoes_pipeline_multi"]
    formatter.format(record)
    after = METRICS["execucoes_pipeline_multi"]
    assert after == before + 1 