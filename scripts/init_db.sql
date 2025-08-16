-- Script de inicialização do banco PostgreSQL para Omni Writer
-- Executado automaticamente na primeira inicialização do container

-- Criação de extensões necessárias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Tabela de status de geração
CREATE TABLE IF NOT EXISTS generation_status (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    total_instances INTEGER DEFAULT 1,
    current_instance INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    result_path VARCHAR(500),
    metadata JSONB
);

-- Tabela de configurações de geração
CREATE TABLE IF NOT EXISTS generation_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id VARCHAR(255) REFERENCES generation_status(trace_id),
    api_key_hash VARCHAR(255) NOT NULL,
    model_type VARCHAR(50) NOT NULL,
    prompts JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de logs de execução
CREATE TABLE IF NOT EXISTS execution_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id VARCHAR(255) REFERENCES generation_status(trace_id),
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Tabela de métricas de performance
CREATE TABLE IF NOT EXISTS performance_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id VARCHAR(255) REFERENCES generation_status(trace_id),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4) NOT NULL,
    unit VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de cache de resultados
CREATE TABLE IF NOT EXISTS result_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cache_key VARCHAR(255) UNIQUE NOT NULL,
    result_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    access_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de tokens de API
CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    usage_count INTEGER DEFAULT 0,
    metadata JSONB
);

-- Tabela de filas de tarefas
CREATE TABLE IF NOT EXISTS task_queues (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    queue_name VARCHAR(100) NOT NULL,
    task_id VARCHAR(255) NOT NULL,
    priority INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    task_data JSONB,
    result_data JSONB,
    error_message TEXT
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_generation_status_trace_id ON generation_status(trace_id);
CREATE INDEX IF NOT EXISTS idx_generation_status_status ON generation_status(status);
CREATE INDEX IF NOT EXISTS idx_generation_status_created_at ON generation_status(created_at);

CREATE INDEX IF NOT EXISTS idx_execution_logs_trace_id ON execution_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_execution_logs_timestamp ON execution_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_execution_logs_level ON execution_logs(level);

CREATE INDEX IF NOT EXISTS idx_performance_metrics_trace_id ON performance_metrics(trace_id);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_name ON performance_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp);

CREATE INDEX IF NOT EXISTS idx_result_cache_key ON result_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_result_cache_expires ON result_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_provider ON api_tokens(provider);
CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(is_active);

CREATE INDEX IF NOT EXISTS idx_task_queues_name ON task_queues(queue_name);
CREATE INDEX IF NOT EXISTS idx_task_queues_status ON task_queues(status);
CREATE INDEX IF NOT EXISTS idx_task_queues_priority ON task_queues(priority);

-- Função para atualizar timestamp de updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers para atualização automática de updated_at
CREATE TRIGGER update_generation_status_updated_at 
    BEFORE UPDATE ON generation_status 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Função para limpeza automática de cache expirado
CREATE OR REPLACE FUNCTION cleanup_expired_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM result_cache WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Função para obter estatísticas do sistema
CREATE OR REPLACE FUNCTION get_system_stats()
RETURNS JSON AS $$
DECLARE
    stats JSON;
BEGIN
    SELECT json_build_object(
        'total_generations', (SELECT COUNT(*) FROM generation_status),
        'pending_generations', (SELECT COUNT(*) FROM generation_status WHERE status = 'pending'),
        'completed_generations', (SELECT COUNT(*) FROM generation_status WHERE status = 'completed'),
        'failed_generations', (SELECT COUNT(*) FROM generation_status WHERE status = 'failed'),
        'active_tokens', (SELECT COUNT(*) FROM api_tokens WHERE is_active = TRUE),
        'cache_entries', (SELECT COUNT(*) FROM result_cache),
        'pending_tasks', (SELECT COUNT(*) FROM task_queues WHERE status = 'pending'),
        'avg_generation_time', (
            SELECT AVG(EXTRACT(EPOCH FROM (completed_at - created_at)))
            FROM generation_status 
            WHERE status = 'completed' AND completed_at IS NOT NULL
        )
    ) INTO stats;
    
    RETURN stats;
END;
$$ LANGUAGE plpgsql;

-- Comentários nas tabelas
COMMENT ON TABLE generation_status IS 'Status das gerações de artigos';
COMMENT ON TABLE generation_configs IS 'Configurações de geração';
COMMENT ON TABLE execution_logs IS 'Logs de execução do sistema';
COMMENT ON TABLE performance_metrics IS 'Métricas de performance';
COMMENT ON TABLE result_cache IS 'Cache de resultados';
COMMENT ON TABLE api_tokens IS 'Tokens de API para provedores';
COMMENT ON TABLE task_queues IS 'Filas de tarefas do Celery';

-- Inserir dados iniciais se necessário
INSERT INTO generation_status (trace_id, status, progress, total_instances) 
VALUES ('system-init', 'completed', 100, 1)
ON CONFLICT (trace_id) DO NOTHING;

-- Log da inicialização
INSERT INTO execution_logs (trace_id, level, message, metadata)
VALUES (
    'system-init', 
    'INFO', 
    'Database initialized successfully', 
    '{"version": "1.0", "tables_created": 7, "indexes_created": 12}'
); 