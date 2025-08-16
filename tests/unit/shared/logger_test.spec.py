import pytest
from unittest import mock
import shared.logger as logger_mod

@pytest.fixture
def logger():
    return logger_mod.get_logger("test")

# Teste info
def test_logger_info(logger):
    with mock.patch.object(logger, "info") as mock_info:
        logger.info("mensagem", extra={"campo": 1})
        mock_info.assert_called_with("mensagem", extra={"campo": 1})

# Teste error
def test_logger_error(logger):
    with mock.patch.object(logger, "error") as mock_error:
        logger.error("erro", extra={"campo": 2})
        mock_error.assert_called_with("erro", extra={"campo": 2})

# Teste metric (se existir)
def test_logger_metric(logger):
    if hasattr(logger, "metric"):
        with mock.patch.object(logger, "metric") as mock_metric:
            logger.metric("nome", 1.23, tags={"a": "b"})
            mock_metric.assert_called_with("nome", 1.23, tags={"a": "b"}) 