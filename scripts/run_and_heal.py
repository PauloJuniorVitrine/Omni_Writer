#!/usr/bin/env python3
"""
🚀 Enterprise Auto-Healing Script v3.0
Omni Writer - Intelligent Test Healing with OpenAI Codex

Este script executa testes e aplica correções inteligentes usando OpenAI Codex
quando os testes falham, com auditoria completa e geração de patches.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import openai
import git
from git import Repo
import requests
import difflib
import re

# ===== CONFIGURAÇÕES =====
class Config:
    """Configurações globais do sistema de auto-healing"""
    
    # OpenAI Configuration
    OPENAI_MODEL = "code-davinci-002"
    MAX_TOKENS = 4000
    TEMPERATURE = 0.1
    
    # File Patterns
    SENSITIVE_FILES = [
        '.env', '.env.*', 'secrets.json', 'config.json',
        '*.key', '*.pem', '*.p12', '*.pfx'
    ]
    
    # Test Patterns
    TEST_PATTERNS = {
        'unit': 'tests/unit/**/*.py',
        'integration': 'tests/integration/**/*.py',
        'e2e': 'tests/e2e/**/*.py'
    }
    
    # Healing Settings
    MAX_ATTEMPTS = 8
    PATCH_DIR = "patches"
    LOGS_DIR = "logs"
    BRANCH_PREFIX = "auto-heal"

class HealingReport:
    """Relatório detalhado de tentativas de healing"""
    
    def __init__(self, stage: str, attempt: int):
        self.stage = stage
        self.attempt = attempt
        self.timestamp = datetime.now().isoformat()
        self.status = "pending"
        self.files_modified = []
        self.lines_impacted = []
        self.diff_content = ""
        self.correction_type = ""
        self.explanation = ""
        self.tests_modified = False
        self.test_modification_reason = ""
        self.error_logs = ""
        self.stack_trace = ""
        self.healing_prompt = ""
        self.codex_response = ""
        
    def to_dict(self) -> Dict:
        """Converte o relatório para dicionário"""
        return {
            "stage": self.stage,
            "attempt": self.attempt,
            "timestamp": self.timestamp,
            "status": self.status,
            "files_modified": self.files_modified,
            "lines_impacted": self.lines_impacted,
            "diff_content": self.diff_content,
            "correction_type": self.correction_type,
            "explanation": self.explanation,
            "tests_modified": self.tests_modified,
            "test_modification_reason": self.test_modification_reason,
            "error_logs": self.error_logs,
            "stack_trace": self.stack_trace,
            "healing_prompt": self.healing_prompt,
            "codex_response": self.codex_response
        }
    
    def save(self, filepath: str):
        """Salva o relatório em arquivo JSON"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

class CodexHealer:
    """Classe principal para healing inteligente com OpenAI Codex"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        openai.api_key = api_key
        self.repo = Repo('.')
        self.config = Config()
        
    def is_sensitive_file(self, filepath: str) -> bool:
        """Verifica se o arquivo é sensível e não deve ser modificado"""
        for pattern in self.config.SENSITIVE_FILES:
            if re.match(pattern, filepath):
                return True
        return False
    
    def extract_error_context(self, test_output: str) -> Tuple[str, str, str]:
        """Extrai contexto do erro dos testes"""
        # Extrair stack trace
        stack_trace = ""
        if "Traceback (most recent call last):" in test_output:
            start = test_output.find("Traceback (most recent call last):")
            end = test_output.find("\n\n", start)
            if end == -1:
                end = len(test_output)
            stack_trace = test_output[start:end]
        
        # Extrair logs de erro
        error_logs = ""
        if "ERROR" in test_output or "FAILED" in test_output:
            lines = test_output.split('\n')
            error_lines = [line for line in lines if 'ERROR' in line or 'FAILED' in line]
            error_logs = '\n'.join(error_lines[-10:])  # Últimas 10 linhas de erro
        
        # Identificar arquivo e função afetada
        affected_code = ""
        if stack_trace:
            # Procurar por arquivo.py:linha in função
            match = re.search(r'File "([^"]+\.py)", line (\d+), in (\w+)', stack_trace)
            if match:
                filepath, line_num, function_name = match.groups()
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        start_line = max(0, int(line_num) - 10)
                        end_line = min(len(lines), int(line_num) + 10)
                        affected_code = ''.join(lines[start_line:end_line])
                except Exception:
                    pass
        
        return stack_trace, error_logs, affected_code
    
    def generate_healing_prompt(self, stage: str, test_output: str, 
                               stack_trace: str, error_logs: str, 
                               affected_code: str) -> str:
        """Gera prompt inteligente para o Codex"""
        
        prompt = f"""
# 🚀 Auto-Healing Request - {stage.upper()} Tests

## Context
- Stage: {stage}
- Timestamp: {datetime.now().isoformat()}
- Repository: {self.repo.remotes.origin.url if self.repo.remotes else 'Local'}

## Test Output
```
{test_output[:2000]}
```

## Error Analysis
### Stack Trace
```
{stack_trace}
```

### Error Logs
```
{error_logs}
```

## Affected Code
```python
{affected_code}
```

## Instructions
1. **Analyze the error** and identify the root cause
2. **Fix the code** with minimal changes to resolve the test failure
3. **Preserve existing comments and documentation**
4. **Do NOT modify sensitive files** (.env, secrets, etc.)
5. **Only modify tests if there's a clear logical inconsistency**
6. **Provide a clear explanation** of what was fixed and why

## Response Format
Return ONLY the corrected code block with this format:

```python
# File: path/to/file.py
# Lines: start-end
# Fix: brief explanation of the fix

[corrected code here]
```

## Safety Rules
- NEVER expose secrets or sensitive data
- NEVER delete large code blocks without justification
- NEVER modify configuration files
- ALWAYS preserve function signatures unless absolutely necessary
- ALWAYS maintain backward compatibility when possible
"""
        
        return prompt
    
    def call_codex(self, prompt: str) -> str:
        """Chama a API do OpenAI Codex"""
        try:
            response = openai.Completion.create(
                model=self.config.OPENAI_MODEL,
                prompt=prompt,
                max_tokens=self.config.MAX_TOKENS,
                temperature=self.config.TEMPERATURE,
                stop=["```"]
            )
            return response.choices[0].text.strip()
        except Exception as e:
            print(f"❌ Error calling OpenAI Codex: {e}")
            return ""
    
    def parse_codex_response(self, response: str) -> List[Dict]:
        """Parseia a resposta do Codex e extrai as correções"""
        corrections = []
        
        # Procurar por blocos de código com metadados
        pattern = r'# File: (.+?)\n# Lines: (\d+)-(\d+)\n# Fix: (.+?)\n\n(.*?)(?=\n# File:|$)'
        matches = re.findall(pattern, response, re.DOTALL)
        
        for match in matches:
            filepath, start_line, end_line, fix_explanation, code = match
            corrections.append({
                'filepath': filepath.strip(),
                'start_line': int(start_line),
                'end_line': int(end_line),
                'fix_explanation': fix_explanation.strip(),
                'code': code.strip()
            })
        
        return corrections
    
    def apply_correction(self, correction: Dict) -> bool:
        """Aplica uma correção no código"""
        try:
            filepath = correction['filepath']
            
            # Verificar se é arquivo sensível
            if self.is_sensitive_file(filepath):
                print(f"⚠️ Skipping sensitive file: {filepath}")
                return False
            
            # Ler arquivo atual
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Aplicar correção
            start_line = correction['start_line'] - 1  # 0-based index
            end_line = correction['end_line']
            new_code = correction['code'].split('\n')
            
            # Substituir linhas
            lines[start_line:end_line] = [line + '\n' for line in new_code]
            
            # Salvar arquivo
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            print(f"✅ Applied correction to {filepath}: {correction['fix_explanation']}")
            return True
            
        except Exception as e:
            print(f"❌ Error applying correction: {e}")
            return False
    
    def create_patch(self, stage: str, attempt: int) -> str:
        """Cria um patch das mudanças"""
        try:
            # Verificar se há mudanças
            if not self.repo.is_dirty():
                return ""
            
            # Criar branch para o patch
            branch_name = f"{self.config.BRANCH_PREFIX}/{stage}/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Stash mudanças atuais
            self.repo.git.stash()
            
            # Criar nova branch
            current_branch = self.repo.active_branch
            new_branch = self.repo.create_head(branch_name)
            new_branch.checkout()
            
            # Aplicar mudanças
            self.repo.git.stash('pop')
            
            # Adicionar e commitar mudanças
            self.repo.git.add('.')
            commit_message = f"🔧 Auto-healing: {stage} tests (attempt {attempt})"
            self.repo.git.commit('-m', commit_message)
            
            # Gerar patch
            patch_content = self.repo.git.diff(f'{current_branch.name}..{branch_name}')
            
            # Salvar patch
            patch_dir = f"{self.config.PATCH_DIR}/{stage}"
            os.makedirs(patch_dir, exist_ok=True)
            patch_file = f"{patch_dir}/patch_attempt_{attempt}.diff"
            
            with open(patch_file, 'w', encoding='utf-8') as f:
                f.write(patch_content)
            
            print(f"📝 Patch saved: {patch_file}")
            return patch_content
            
        except Exception as e:
            print(f"❌ Error creating patch: {e}")
            return ""
    
    def create_pull_request(self, stage: str, attempt: int, 
                          report: HealingReport) -> Optional[str]:
        """Cria Pull Request automático"""
        try:
            # Verificar se estamos em um fork ou repo próprio
            if not self.repo.remotes.origin:
                print("⚠️ No remote origin found, skipping PR creation")
                return None
            
            # Dados do PR
            branch_name = f"{self.config.BRANCH_PREFIX}/{stage}/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            title = f"🔧 Auto-healing: {stage} tests (attempt {attempt})"
            
            body = f"""
## 🤖 Auto-Healing Pull Request

**Stage:** {stage}
**Attempt:** {attempt}
**Status:** {report.status}

### 📊 Changes Summary
- **Files Modified:** {len(report.files_modified)}
- **Lines Impacted:** {len(report.lines_impacted)}
- **Correction Type:** {report.correction_type}
- **Tests Modified:** {report.tests_modified}

### 🔧 Fix Details
{report.explanation}

### 📋 Files Changed
{chr(10).join(f"- {file}" for file in report.files_modified)}

### ⚠️ Review Required
This PR was automatically generated by the auto-healing system. Please review the changes before merging.

### 📊 Healing Report
- **Error Logs:** {len(report.error_logs)} characters
- **Stack Trace:** {len(report.stack_trace)} characters
- **Codex Response:** {len(report.codex_response)} characters

---
*Generated by Omni Writer Auto-Healing Pipeline v3.0*
"""
            
            # Criar PR via GitHub API
            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                print("⚠️ GITHUB_TOKEN not found, skipping PR creation")
                return None
            
            # Extrair owner/repo do remote
            remote_url = self.repo.remotes.origin.url
            if remote_url.endswith('.git'):
                remote_url = remote_url[:-4]
            
            if 'github.com' in remote_url:
                parts = remote_url.split('github.com/')[-1].split('/')
                owner, repo_name = parts[0], parts[1]
            else:
                print("⚠️ Not a GitHub repository, skipping PR creation")
                return None
            
            # API call para criar PR
            headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            data = {
                'title': title,
                'body': body,
                'head': branch_name,
                'base': 'main'
            }
            
            response = requests.post(
                f'https://api.github.com/repos/{owner}/{repo_name}/pulls',
                headers=headers,
                json=data
            )
            
            if response.status_code == 201:
                pr_data = response.json()
                pr_url = pr_data['html_url']
                print(f"✅ Pull Request created: {pr_url}")
                return pr_url
            else:
                print(f"❌ Failed to create PR: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error creating Pull Request: {e}")
            return None
    
    def run_tests(self, test_path: str) -> Tuple[bool, str]:
        """Executa os testes e retorna resultado"""
        try:
            # Executar pytest
            cmd = [
                sys.executable, '-m', 'pytest',
                test_path,
                '--tb=short',
                '--junitxml=test-results.xml',
                '-v'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            return success, output
            
        except subprocess.TimeoutExpired:
            return False, "Test execution timed out after 5 minutes"
        except Exception as e:
            return False, f"Error running tests: {e}"
    
    def heal_tests(self, stage: str, test_path: str, max_attempts: int, 
                  current_attempt: int) -> HealingReport:
        """Executa o processo de healing para os testes"""
        
        report = HealingReport(stage, current_attempt)
        
        print(f"🚀 Starting healing for {stage} tests (attempt {current_attempt}/{max_attempts})")
        
        # Executar testes
        success, test_output = self.run_tests(test_path)
        
        if success:
            report.status = "success"
            report.explanation = "Tests passed without healing needed"
            print("✅ Tests passed without healing needed")
            return report
        
        # Extrair contexto do erro
        stack_trace, error_logs, affected_code = self.extract_error_context(test_output)
        report.error_logs = error_logs
        report.stack_trace = stack_trace
        
        # Gerar prompt para o Codex
        healing_prompt = self.generate_healing_prompt(
            stage, test_output, stack_trace, error_logs, affected_code
        )
        report.healing_prompt = healing_prompt
        
        # Chamar Codex
        print("🤖 Calling OpenAI Codex for healing...")
        codex_response = self.call_codex(healing_prompt)
        report.codex_response = codex_response
        
        if not codex_response:
            report.status = "failed"
            report.explanation = "Failed to get response from Codex"
            print("❌ No response from Codex")
            return report
        
        # Parsear resposta do Codex
        corrections = self.parse_codex_response(codex_response)
        
        if not corrections:
            report.status = "failed"
            report.explanation = "No valid corrections found in Codex response"
            print("❌ No valid corrections found in Codex response")
            return report
        
        # Aplicar correções
        print(f"🔧 Applying {len(corrections)} corrections...")
        applied_corrections = 0
        
        for correction in corrections:
            if self.apply_correction(correction):
                applied_corrections += 1
                report.files_modified.append(correction['filepath'])
                report.lines_impacted.extend(range(correction['start_line'], correction['end_line'] + 1))
                report.correction_type = correction.get('fix_explanation', 'bugfix')
        
        if applied_corrections == 0:
            report.status = "failed"
            report.explanation = "No corrections could be applied"
            print("❌ No corrections could be applied")
            return report
        
        # Criar patch
        patch_content = self.create_patch(stage, current_attempt)
        report.diff_content = patch_content
        
        # Re-executar testes
        print("🔄 Re-running tests after healing...")
        success, test_output = self.run_tests(test_path)
        
        if success:
            report.status = "success"
            report.explanation = f"Successfully healed with {applied_corrections} corrections"
            print("✅ Healing successful!")
            
            # Criar Pull Request
            pr_url = self.create_pull_request(stage, current_attempt, report)
            if pr_url:
                report.explanation += f" | PR: {pr_url}"
        else:
            report.status = "failed"
            report.explanation = f"Healing applied but tests still failing"
            print("❌ Healing applied but tests still failing")
        
        return report

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description="🚀 Enterprise Auto-Healing Script v3.0"
    )
    parser.add_argument('--tests', required=True, help='Path to test directory')
    parser.add_argument('--stage', required=True, choices=['unit', 'integration', 'e2e'], 
                       help='Test stage')
    parser.add_argument('--max-attempts', type=int, default=8, help='Maximum healing attempts')
    parser.add_argument('--attempt', type=int, default=1, help='Current attempt number')
    parser.add_argument('--openai-key', help='OpenAI API key (or set OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Configurar OpenAI API key
    api_key = args.openai_key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OpenAI API key not provided. Set OPENAI_API_KEY environment variable or use --openai-key")
        sys.exit(1)
    
    # Criar diretórios necessários
    os.makedirs(Config.PATCH_DIR, exist_ok=True)
    os.makedirs(Config.LOGS_DIR, exist_ok=True)
    
    # Inicializar healer
    healer = CodexHealer(api_key)
    
    # Executar healing
    report = healer.heal_tests(
        args.stage, 
        args.tests, 
        args.max_attempts, 
        args.attempt
    )
    
    # Salvar relatório
    report_file = f"{Config.LOGS_DIR}/{args.stage}_healing_report.json"
    report.save(report_file)
    
    print(f"📊 Healing report saved: {report_file}")
    print(f"📈 Status: {report.status}")
    print(f"📝 Explanation: {report.explanation}")
    
    # Exit code baseado no resultado
    sys.exit(0 if report.status == "success" else 1)

if __name__ == "__main__":
    main()


