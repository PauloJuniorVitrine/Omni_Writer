"""
Logger utilities for structured JSON logging and metrics tracking.
Provides a custom formatter, logger factory, and metrics export.
"""
import logging
import json
from datetime import datetime

# Global metrics for article generation and pipeline execution
METRICS = {
    'artigos_gerados': 0,
    'falhas_geracao': 0,
    'execucoes_pipeline': 0,
    'execucoes_pipeline_multi': 0
}

class JsonFormatter(logging.Formatter):
    """
    Custom logging formatter for structured JSON logs with UTC timestamp and event details.
    Increments global metrics based on event type and status.
    """
    def format(self, record):
        # Format log as structured JSON
        log_record = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': getattr(record, 'event', record.getMessage()),
            'status': getattr(record, 'status', 'INFO'),
            'source': getattr(record, 'source', record.name),
            'details': getattr(record, 'details', record.getMessage()),
        }
        trace_id = getattr(record, 'trace_id', None)
        if trace_id:
            log_record['trace_id'] = trace_id
        # Increment global metrics based on event
        if log_record['event'] in ('openai_generation', 'deepseek_generation') and log_record['status'] == 'success':
            METRICS['artigos_gerados'] += 1
        if log_record['event'] in ('openai_generation', 'deepseek_generation') and log_record['status'] == 'error':
            METRICS['falhas_geracao'] += 1
        if log_record['event'] == 'pipeline' and log_record['status'] == 'success':
            METRICS['execucoes_pipeline'] += 1
        if log_record['event'] == 'pipeline_multi' and log_record['status'] == 'success':
            METRICS['execucoes_pipeline_multi'] += 1
        return json.dumps(log_record, ensure_ascii=False)

def get_logger(name: str) -> logging.Logger:
    """
    Returns a logger instance with the custom JSON formatter and INFO level.
    Args:
        name (str): Logger name.
    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

def export_metrics() -> str:
    """
    Exports the current global metrics as a JSON string.
    Returns:
        str: JSON string with metrics.
    """
    return json.dumps(METRICS, ensure_ascii=False) 