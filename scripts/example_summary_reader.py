#!/usr/bin/env python3
"""
🚀 Example Summary Reader Script
📅 Criado: 2025-01-27
🔧 Tracing ID: AUTO_HEALING_CONFIG_001_20250127
📝 Demonstra como adicionar guardas para o arquivo summary.json
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional


def ensure_summary_file_exists() -> str:
    """
    🛟 Garante que o arquivo .ci/config/summary.json existe.
    
    Returns:
        str: Caminho para o arquivo summary.json
    """
    summary_path = Path(".ci/config/summary.json")
    
    # Se o arquivo não existir, criar com valores padrão
    if not summary_path.exists():
        # Criar diretório se não existir
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Conteúdo padrão do summary.json
        default_summary = {
            "version": "3.0.0",
            "environment": "production",
            "tracing_id": "AUTO_HEALING_CONFIG_001_20250127",
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
            "sha": os.environ.get("GITHUB_SHA", "unknown"),
            "branch": os.environ.get("GITHUB_REF_NAME", "unknown"),
            "jobs_completed": {},
            "totals": {
                "healing_attempts": 0,
                "patches_created": 0,
                "tests_passed": 0,
                "tests_failed": 0
            },
            "timestamp": "2025-01-27T00:00:00Z"
        }
        
        # Salvar arquivo padrão
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(default_summary, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Arquivo summary.json criado em: {summary_path}")
    
    return str(summary_path)


def read_summary_file() -> Dict[str, Any]:
    """
    📖 Lê o arquivo summary.json com fallback automático.
    
    Returns:
        Dict[str, Any]: Conteúdo do arquivo summary.json
    """
    summary_path = ensure_summary_file_exists()
    
    try:
        with open(summary_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"✅ Arquivo summary.json lido com sucesso: {summary_path}")
        return data
    except (json.JSONDecodeError, IOError) as e:
        print(f"⚠️ Erro ao ler {summary_path}: {e}")
        # Retornar dados padrão em caso de erro
        return {
            "version": "3.0.0",
            "environment": "production",
            "tracing_id": "AUTO_HEALING_CONFIG_001_20250127",
            "repository": "unknown",
            "run_id": "unknown",
            "sha": "unknown",
            "branch": "unknown",
            "jobs_completed": {},
            "totals": {
                "healing_attempts": 0,
                "patches_created": 0,
                "tests_passed": 0,
                "tests_failed": 0
            },
            "timestamp": "2025-01-27T00:00:00Z"
        }


def update_summary_totals(healing_attempts: int = 0, 
                          patches_created: int = 0,
                          tests_passed: int = 0,
                          tests_failed: int = 0) -> None:
    """
    📝 Atualiza os totais no arquivo summary.json.
    
    Args:
        healing_attempts: Número de tentativas de healing
        patches_created: Número de patches criados
        tests_passed: Número de testes aprovados
        tests_failed: Número de testes falhados
    """
    summary_path = ensure_summary_file_exists()
    
    try:
        # Ler dados existentes
        with open(summary_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Atualizar totais
        data["totals"]["healing_attempts"] += healing_attempts
        data["totals"]["patches_created"] += patches_created
        data["totals"]["tests_passed"] += tests_passed
        data["totals"]["tests_failed"] += tests_failed
        
        # Salvar dados atualizados
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Totais atualizados em {summary_path}")
        print(f"   - Healing attempts: {data['totals']['healing_attempts']}")
        print(f"   - Patches created: {data['totals']['patches_created']}")
        print(f"   - Tests passed: {data['totals']['tests_passed']}")
        print(f"   - Tests failed: {data['totals']['tests_failed']}")
        
    except (json.JSONDecodeError, IOError) as e:
        print(f"❌ Erro ao atualizar {summary_path}: {e}")


def main():
    """
    🚀 Função principal do script.
    """
    print("🚀 Example Summary Reader Script")
    print("=" * 50)
    
    # Garantir que o arquivo existe
    summary_path = ensure_summary_file_exists()
    print(f"📁 Caminho do arquivo: {summary_path}")
    
    # Ler dados do arquivo
    data = read_summary_file()
    print(f"📊 Versão: {data['version']}")
    print(f"🌍 Ambiente: {data['environment']}")
    print(f"🔧 Tracing ID: {data['tracing_id']}")
    
    # Exemplo de atualização de totais
    print("\n📝 Atualizando totais...")
    update_summary_totals(
        healing_attempts=1,
        patches_created=1,
        tests_passed=10,
        tests_failed=0
    )
    
    print("\n✅ Script executado com sucesso!")


if __name__ == "__main__":
    main()
