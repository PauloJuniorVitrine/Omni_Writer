#!/usr/bin/env python3
"""
Script de Backup SQLite - Omni Writer
====================================

Cria backup de segurança do banco SQLite antes da migração.
Prompt: Backup SQLite antes da migração
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path

def backup_sqlite_database():
    """Cria backup do banco SQLite."""
    sqlite_path = os.getenv('STATUS_DB_PATH', 'status.db')
    
    if not os.path.exists(sqlite_path):
        print(f"⚠️ Banco SQLite não encontrado: {sqlite_path}")
        return False
    
    # Criar diretório de backup
    backup_dir = Path("backups") / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Backup do arquivo
    backup_file = backup_dir / "status_backup.db"
    shutil.copy2(sqlite_path, backup_file)
    
    # Metadados do backup
    metadata = {
        "backup_time": datetime.now().isoformat(),
        "original_file": sqlite_path,
        "backup_file": str(backup_file),
        "file_size": os.path.getsize(backup_file)
    }
    
    with open(backup_dir / "backup_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✅ Backup SQLite criado: {backup_file}")
    return True

if __name__ == "__main__":
    backup_sqlite_database() 