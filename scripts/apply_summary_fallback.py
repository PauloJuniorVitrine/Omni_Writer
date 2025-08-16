#!/usr/bin/env python3
"""
🛟 Script para Aplicar Summary Fallback em Workflows
📅 Criado: 2025-01-27
🔧 Tracing ID: APPLY_SUMMARY_FALLBACK_001_20250127
"""

import os
import re
import argparse
from pathlib import Path
from typing import List, Tuple, Optional


def ensure_summary_file_exists() -> None:
    """Garante que o arquivo .ci/config/summary.json existe."""
    summary_path = Path(".ci/config/summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not summary_path.exists():
        default_content = {
            "version": "3.0.0",
            "environment": "production",
            "tracing_id": "AUTO_HEALING_CONFIG_001_20250127",
            "repository": "",
            "run_id": "",
            "sha": "",
            "branch": "",
            "jobs_completed": {},
            "totals": {
                "healing_attempts": 0,
                "patches_created": 0,
                "tests_passed": 0,
                "tests_failed": 0
            },
            "timestamp": "1970-01-01T00:00:00Z"
        }
        
        import json
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(default_content, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Arquivo baseline criado: {summary_path}")


def apply_workflow_fallback(file_path: str, dry_run: bool = False) -> bool:
    """Aplica fallback em um workflow YAML."""
    print(f"📝 Processando workflow: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verificar se já tem os steps necessários
        if "Download ci-summary" in content and "Ensure.*summary.json" in content:
            print("  ✅ Já possui fallback configurado")
            return False
        
        # Verificar se é um workflow válido
        if "name:" not in content or "jobs:" not in content:
            print("  ⚠️ Não parece ser um workflow válido, pulando...")
            return False
        
        modified = False
        
        # Adicionar step de download antes do primeiro step ensure
        if "Ensure.*summary.json" in content and "Download ci-summary" not in content:
            download_step = '''
      - name: 📥 Download ci-summary (optional)
        uses: actions/download-artifact@v4
        with:
          name: ci-summary
          path: .ci/config
        continue-on-error: true
      
'''
            
            # Inserir antes do primeiro step ensure
            pattern = r'(\s+-\s+name:\s*[🛟🛡️].*summary\.json.*\n)'
            if re.search(pattern, content):
                content = re.sub(pattern, f"{download_step}\\1", content)
                modified = True
                print("  ➕ Adicionado step de download")
        
        # Adicionar step de upload no final dos jobs
        if "Ensure.*summary.json" in content and "Upload summary.json" not in content:
            upload_step = '''
      - name: 📦 Upload summary.json
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ci-summary
          path: .ci/config/summary.json
          if-no-files-found: warn
'''
            
            # Inserir antes do fechamento do job
            pattern = r'(\n\s+[#]\s*[=]+.*\n)'
            if re.search(pattern, content):
                content = re.sub(pattern, f"{upload_step}\\1", content)
                modified = True
                print("  ➕ Adicionado step de upload")
        
        if modified:
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print("  💾 Workflow atualizado")
            else:
                print("  🔍 Modificações simuladas (Dry Run)")
            return True
        else:
            print("  ℹ️ Nenhuma modificação necessária")
            return False
            
    except Exception as e:
        print(f"  ❌ Erro ao processar workflow: {e}")
        return False


def apply_script_guards(file_path: str, dry_run: bool = False) -> bool:
    """Aplica guardas em scripts."""
    print(f"📝 Processando script: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        modified = False
        
        # Verificar se é um script shell
        if file_path.endswith('.sh') and "summary.json" in content:
            if "SUMMARY_FILE.*summary.json" not in content:
                guard = '''# 🛟 Garantir que o arquivo summary.json existe
SUMMARY_FILE=".ci/config/summary.json"
[ -f "$SUMMARY_FILE" ] || { mkdir -p .ci/config; echo '{}' > "$SUMMARY_FILE"; }

'''
                
                # Inserir após o shebang
                if content.startswith('#!/'):
                    lines = content.split('\n')
                    lines.insert(1, guard.rstrip())
                    content = '\n'.join(lines)
                    modified = True
                    print("  ➕ Adicionado guarda shell")
        
        # Verificar se é um script Python
        elif file_path.endswith('.py') and "summary.json" in content:
            if "Path.*summary.json" not in content:
                guard = '''# 🛟 Garantir que o arquivo summary.json existe
from pathlib import Path
summary_path = Path(".ci/config/summary.json")
summary_path.parent.mkdir(parents=True, exist_ok=True)
if not summary_path.exists():
    summary_path.write_text("{}", encoding="utf-8")

'''
                
                # Inserir após imports
                import_pattern = r'^(import|from).*$'
                import_lines = re.findall(import_pattern, content, re.MULTILINE)
                
                if import_lines:
                    last_import = import_lines[-1]
                    last_import_pos = content.rfind(last_import)
                    if last_import_pos != -1:
                        insert_pos = last_import_pos + len(last_import)
                        content = content[:insert_pos] + '\n' + guard + content[insert_pos:]
                        modified = True
                        print("  ➕ Adicionado guarda Python")
        
        if modified:
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print("  💾 Script atualizado")
            else:
                print("  🔍 Modificações simuladas (Dry Run)")
            return True
        else:
            print("  ℹ️ Nenhuma modificação necessária")
            return False
            
    except Exception as e:
        print(f"  ❌ Erro ao processar script: {e}")
        return False


def main():
    """Função principal."""
    parser = argparse.ArgumentParser(description="Aplicar Summary Fallback em Workflows e Scripts")
    parser.add_argument("--workflows-path", default=".github/workflows", help="Caminho para workflows")
    parser.add_argument("--scripts-path", default="scripts", help="Caminho para scripts")
    parser.add_argument("--dry-run", action="store_true", help="Simular modificações sem salvar")
    parser.add_argument("--verbose", action="store_true", help="Modo verboso")
    
    args = parser.parse_args()
    
    print("🚀 Aplicando Summary Fallback em Workflows e Scripts")
    print("==================================================")
    
    # Garantir arquivo baseline
    ensure_summary_file_exists()
    
    # Processar workflows
    print("\n🔧 Processando Workflows...")
    workflows_path = Path(args.workflows_path)
    workflow_files = []
    
    if workflows_path.exists():
        workflow_files.extend(workflows_path.glob("*.yml"))
        workflow_files.extend(workflows_path.glob("*.yaml"))
    
    workflows_modified = 0
    for file_path in workflow_files:
        if apply_workflow_fallback(str(file_path), args.dry_run):
            workflows_modified += 1
    
    # Processar scripts
    print("\n🔧 Processando Scripts...")
    scripts_path = Path(args.scripts_path)
    script_files = []
    
    if scripts_path.exists():
        script_files.extend(scripts_path.glob("*.sh"))
        script_files.extend(scripts_path.glob("*.py"))
    
    scripts_modified = 0
    for file_path in script_files:
        if apply_script_guards(str(file_path), args.dry_run):
            scripts_modified += 1
    
    # Resumo
    print("\n📊 Resumo das Modificações")
    print("==================================================")
    print(f"Workflows processados: {len(workflow_files)}")
    print(f"Workflows modificados: {workflows_modified}")
    print(f"Scripts processados: {len(script_files)}")
    print(f"Scripts modificados: {scripts_modified}")
    
    if args.dry_run:
        print("\n🔍 Modo Dry Run - Nenhuma alteração foi salva")
    else:
        print("\n✅ Todas as modificações foram aplicadas!")
    
    print("\n🎯 Próximos passos:")
    print("1. Verificar se os workflows estão funcionando")
    print("2. Testar em commits antigos")
    print("3. Validar que não há falhas por ausência do summary.json")


if __name__ == "__main__":
    main()
