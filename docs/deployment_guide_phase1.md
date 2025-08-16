# 🚀 GUIA DE DEPLOY - FASE 1: BANCO DE DADOS

## **📋 RESUMO**
Este guia documenta o deploy da Fase 1 do checklist: migração completa para PostgreSQL.

## **🎯 OBJETIVOS**
- ✅ Migração completa para PostgreSQL
- ✅ Pool de conexões otimizado
- ✅ Retry logic robusta
- ✅ Validação de integridade

## **🔧 PRÉ-REQUISITOS**

### **1. Ambiente**
- Docker e Docker Compose instalados
- Python 3.8+ configurado
- PostgreSQL 15+ disponível
- Redis 7+ disponível

### **2. Configurações**
```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Editar configurações
nano .env
```

### **3. Dependências**
```bash
# Instalar dependências Python
pip install -r requirements.txt

# Verificar PostgreSQL driver
pip install psycopg2-binary
```

## **🚀 PASSOS DE DEPLOY**

### **Passo 1: Backup dos Dados Existentes**
```bash
# Backup SQLite
python scripts/backup_sqlite.py

# Backup feedback
python scripts/backup_feedback.py
```

### **Passo 2: Iniciar Infraestrutura**
```bash
# Iniciar PostgreSQL e Redis
docker compose up -d postgres redis

# Verificar status
docker compose ps
```

### **Passo 3: Executar Migrações**
```bash
# Migrar status SQLite → PostgreSQL
python scripts/migrate_status_sqlite_to_postgres.py

# Migrar feedback JSON → PostgreSQL
python scripts/migrate_feedback_json_to_postgres.py
```

### **Passo 4: Validar Integridade**
```bash
# Validar migração
python scripts/validate_migration_integrity.py
```

### **Passo 5: Iniciar Aplicação**
```bash
# Iniciar aplicação completa
docker compose up -d

# Verificar logs
docker compose logs -f app
```

## **📊 VALIDAÇÃO**

### **1. Testes de Integração**
```bash
# Executar testes PostgreSQL
pytest tests/integration/test_postgresql.py -v
```

### **2. Verificar Métricas**
- Acessar Prometheus: http://localhost:9090
- Acessar Grafana: http://localhost:3000
- Verificar logs: `logs/exec_trace/`

### **3. Testar Funcionalidades**
- Gerar artigo via API
- Verificar persistência no PostgreSQL
- Validar cache no Redis

## **🔍 TROUBLESHOOTING**

### **Problema: Conexão PostgreSQL falha**
```bash
# Verificar se PostgreSQL está rodando
docker compose ps postgres

# Verificar logs
docker compose logs postgres

# Testar conexão manual
psql -h localhost -U omniwriter -d omniwriter
```

### **Problema: Migração falha**
```bash
# Verificar backup
ls -la backups/

# Restaurar backup se necessário
cp backups/YYYYMMDD_HHMMSS/status_backup.db status.db
```

### **Problema: Performance ruim**
```bash
# Verificar pool de conexões
python -c "from shared.postgresql_pool_config import get_connection_pool_stats; print(get_connection_pool_stats(engine))"

# Ajustar configurações no .env
POSTGRES_POOL_SIZE=20
POSTGRES_MAX_OVERFLOW=30
```

## **📈 MÉTRICAS DE SUCESSO**

| Métrica | Meta | Como Medir |
|---------|------|------------|
| **Tempo de Resposta** | < 100ms | Prometheus / Grafana |
| **Uptime** | > 99.9% | Monitoramento |
| **Cobertura de Testes** | > 85% | pytest --cov |
| **Integridade de Dados** | 100% | Script de validação |

## **🔄 ROLLBACK**

### **Se necessário reverter:**
```bash
# Parar aplicação
docker compose down

# Restaurar SQLite
cp backups/YYYYMMDD_HHMMSS/status_backup.db status.db

# Restaurar feedback
cp backups/YYYYMMDD_HHMMSS/feedback_backup.json feedback/feedback_data.json

# Reiniciar com configuração anterior
docker compose up -d
```

## **📞 SUPORTE**

- **Logs**: `logs/exec_trace/checklist_phase1_manual.log`
- **Documentação**: `docs/checklist_phase1_implementation_report.md`
- **Issues**: Criar issue no repositório

---

**Data de Criação**: 2025-01-27T12:30:00Z  
**Tracing ID**: CHECKLIST_PHASE1_MANUAL_20250127_001  
**Status**: ✅ Implementado 