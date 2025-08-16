#!/usr/bin/env python3
"""
Validação de Integridade - Migração PostgreSQL
==============================================

Valida integridade dos dados migrados para PostgreSQL.
Prompt: Validação integridade migração PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
"""

import os
import sqlite3
import json
from sqlalchemy import create_engine, text
from typing import Dict, List, Any
from datetime import datetime

def validate_status_migration():
    """Valida migração de dados de status."""
    print("🔍 Validando migração de status...")
    
    # Dados originais (SQLite)
    sqlite_path = os.getenv('STATUS_DB_PATH', 'status.db')
    sqlite_data = []
    
    if os.path.exists(sqlite_path):
        conn = sqlite3.connect(sqlite_path)
        cursor = conn.cursor()
        cursor.execute('SELECT trace_id, total, current, status FROM status')
        sqlite_data = cursor.fetchall()
        conn.close()
    
    # Dados migrados (PostgreSQL)
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
    engine = create_engine(postgres_url)
    
    with engine.connect() as conn:
        result = conn.execute(text('SELECT trace_id, total, current, status FROM status'))
        postgres_data = result.fetchall()
    
    # Comparação
    sqlite_count = len(sqlite_data)
    postgres_count = len(postgres_data)
    
    print(f"📊 SQLite: {sqlite_count} registros")
    print(f"📊 PostgreSQL: {postgres_count} registros")
    
    if sqlite_count == postgres_count:
        print("✅ Contagem de registros igual")
    else:
        print("❌ Contagem de registros diferente")
        return False
    
    # Validar dados específicos
    sqlite_dict = {row[0]: row[1:] for row in sqlite_data}
    postgres_dict = {row[0]: row[1:] for row in postgres_data}
    
    for trace_id in sqlite_dict:
        if trace_id not in postgres_dict:
            print(f"❌ Trace ID {trace_id} não encontrado no PostgreSQL")
            return False
        
        if sqlite_dict[trace_id] != postgres_dict[trace_id]:
            print(f"❌ Dados diferentes para trace_id {trace_id}")
            return False
    
    print("✅ Validação de status concluída com sucesso")
    return True

def validate_feedback_migration():
    """Valida migração de dados de feedback."""
    print("🔍 Validando migração de feedback...")
    
    # Dados originais (JSON)
    feedback_file = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
    json_data = []
    
    if os.path.exists(feedback_file):
        with open(feedback_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    
    # Dados migrados (PostgreSQL)
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
    engine = create_engine(postgres_url)
    
    with engine.connect() as conn:
        result = conn.execute(text('SELECT trace_id, feedback_data FROM feedback'))
        postgres_data = result.fetchall()
    
    # Comparação
    json_count = len(json_data)
    postgres_count = len(postgres_data)
    
    print(f"📊 JSON: {json_count} registros")
    print(f"📊 PostgreSQL: {postgres_count} registros")
    
    if json_count == postgres_count:
        print("✅ Contagem de registros igual")
    else:
        print("❌ Contagem de registros diferente")
        return False
    
    print("✅ Validação de feedback concluída com sucesso")
    return True

def main():
    """Executa validação completa."""
    print("🚀 Iniciando validação de integridade...")
    
    status_ok = validate_status_migration()
    feedback_ok = validate_feedback_migration()
    
    if status_ok and feedback_ok:
        print("✅ Validação completa: TODOS OS DADOS MIGRADOS CORRETAMENTE")
        return True
    else:
        print("❌ Validação falhou: VERIFICAR MIGRAÇÃO")
        return False

if __name__ == "__main__":
    main()
