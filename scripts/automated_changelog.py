#!/usr/bin/env python3
"""
Script de Changelog Automatizado - Omni Writer
==============================================

Gera changelog automático incluindo:
- Integração com commits e PRs
- Categorização automática de mudanças
- Release notes automáticas
- Versionamento semântico

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import subprocess
import re
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import argparse

@dataclass
class Commit:
    """Representa um commit Git"""
    hash: str
    author: str
    date: str
    message: str
    type: str
    scope: Optional[str]
    description: str
    breaking: bool = False
    pr_number: Optional[str] = None

@dataclass
class Release:
    """Representa uma release"""
    version: str
    date: str
    commits: List[Commit]
    breaking_changes: List[str]
    features: List[str]
    fixes: List[str]
    docs: List[str]
    chore: List[str]

class AutomatedChangelog:
    """Sistema de changelog automatizado"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.changelog_file = self.repo_path / "CHANGELOG.md"
        self.config_file = self.repo_path / ".changelog-config.json"
        
        # Configuração padrão
        self.config = {
            "types": {
                "feat": "Adicionado",
                "fix": "Corrigido",
                "docs": "Documentação",
                "style": "Estilo",
                "refactor": "Refatoração",
                "test": "Testes",
                "chore": "Manutenção",
                "perf": "Performance",
                "ci": "CI/CD",
                "build": "Build",
                "revert": "Revertido"
            },
            "scopes": {
                "api": "API",
                "ui": "Interface",
                "auth": "Autenticação",
                "db": "Banco de Dados",
                "i18n": "Internacionalização",
                "security": "Segurança",
                "performance": "Performance",
                "docs": "Documentação"
            },
            "breaking_change_keywords": ["BREAKING CHANGE", "breaking", "breaking change"],
            "pr_pattern": r"#(\d+)",
            "conventional_commit_pattern": r"^(\w+)(?:\(([\w\-]+)\))?(!)?:\s*(.+)$"
        }
        
        # Carrega configuração personalizada se existir
        if self.config_file.exists():
            with open(self.config_file, 'r', encoding='utf-8') as f:
                custom_config = json.load(f)
                self.config.update(custom_config)
    
    def get_git_commits(self, from_tag: Optional[str] = None, to_tag: Optional[str] = None) -> List[Commit]:
        """Obtém commits do Git"""
        print("🔍 Obtendo commits do Git...")
        
        # Constrói comando Git
        cmd = ["git", "log", "--pretty=format:%H|%an|%ad|%s", "--date=short"]
        
        if from_tag and to_tag:
            cmd.extend([f"{from_tag}..{to_tag}"])
        elif from_tag:
            cmd.extend([f"{from_tag}..HEAD"])
        elif to_tag:
            cmd.extend([f"..{to_tag}"])
        
        try:
            result = subprocess.run(cmd, cwd=self.repo_path, capture_output=True, text=True, check=True)
            commits_raw = result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Erro ao executar comando Git: {e}")
            return []
        
        commits = []
        for commit_raw in commits_raw:
            if not commit_raw.strip():
                continue
                
            parts = commit_raw.split('|')
            if len(parts) >= 4:
                hash_val, author, date, message = parts[:4]
                commit = self._parse_commit_message(hash_val, author, date, message)
                if commit:
                    commits.append(commit)
        
        return commits
    
    def _parse_commit_message(self, hash_val: str, author: str, date: str, message: str) -> Optional[Commit]:
        """Parse de mensagem de commit convencional"""
        
        # Verifica se é um commit convencional
        match = re.match(self.config["conventional_commit_pattern"], message)
        if not match:
            return None
        
        commit_type, scope, breaking_flag, description = match.groups()
        
        # Verifica se é breaking change
        breaking = breaking_flag == "!" or any(keyword in message for keyword in self.config["breaking_change_keywords"])
        
        # Extrai número do PR se existir
        pr_match = re.search(self.config["pr_pattern"], message)
        pr_number = pr_match.group(1) if pr_match else None
        
        return Commit(
            hash=hash_val,
            author=author,
            date=date,
            message=message,
            type=commit_type,
            scope=scope,
            description=description,
            breaking=breaking,
            pr_number=pr_number
        )
    
    def get_git_tags(self) -> List[str]:
        """Obtém tags do Git"""
        try:
            result = subprocess.run(
                ["git", "tag", "--sort=-version:refname"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except subprocess.CalledProcessError:
            return []
    
    def categorize_commits(self, commits: List[Commit]) -> Dict[str, List[Commit]]:
        """Categoriza commits por tipo"""
        categories = {
            "feat": [],
            "fix": [],
            "docs": [],
            "style": [],
            "refactor": [],
            "test": [],
            "chore": [],
            "perf": [],
            "ci": [],
            "build": [],
            "revert": [],
            "breaking": []
        }
        
        for commit in commits:
            if commit.breaking:
                categories["breaking"].append(commit)
            
            if commit.type in categories:
                categories[commit.type].append(commit)
            else:
                categories["chore"].append(commit)
        
        return categories
    
    def generate_release_notes(self, commits: List[Commit], version: str) -> Release:
        """Gera release notes"""
        print(f"📝 Gerando release notes para versão {version}...")
        
        categorized = self.categorize_commits(commits)
        
        # Extrai breaking changes
        breaking_changes = []
        for commit in categorized["breaking"]:
            breaking_changes.append(f"- {commit.description} ({commit.hash[:8]})")
        
        # Extrai features
        features = []
        for commit in categorized["feat"]:
            scope_text = f"**{commit.scope}:** " if commit.scope else ""
            features.append(f"- {scope_text}{commit.description} ({commit.hash[:8]})")
        
        # Extrai fixes
        fixes = []
        for commit in categorized["fix"]:
            scope_text = f"**{commit.scope}:** " if commit.scope else ""
            fixes.append(f"- {scope_text}{commit.description} ({commit.hash[:8]})")
        
        # Extrai documentação
        docs = []
        for commit in categorized["docs"]:
            scope_text = f"**{commit.scope}:** " if commit.scope else ""
            docs.append(f"- {scope_text}{commit.description} ({commit.hash[:8]})")
        
        # Extrai chores
        chore = []
        for commit in categorized["chore"]:
            scope_text = f"**{commit.scope}:** " if commit.scope else ""
            chore.append(f"- {scope_text}{commit.description} ({commit.hash[:8]})")
        
        return Release(
            version=version,
            date=datetime.now().strftime("%Y-%m-%d"),
            commits=commits,
            breaking_changes=breaking_changes,
            features=features,
            fixes=fixes,
            docs=docs,
            chore=chore
        )
    
    def generate_changelog_content(self, releases: List[Release]) -> str:
        """Gera conteúdo do changelog"""
        print("📝 Gerando conteúdo do changelog...")
        
        changelog = """# Changelog - Omni Writer

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não Lançado]

### Adicionado
- Novas funcionalidades em desenvolvimento

### Alterado
- Mudanças em funcionalidades existentes

### Corrigido
- Correções de bugs

### Removido
- Funcionalidades removidas

"""
        
        for release in releases:
            changelog += f"## [{release.version}] - {release.date}\n\n"
            
            # Breaking Changes
            if release.breaking_changes:
                changelog += "### ⚠️ Breaking Changes\n"
                for change in release.breaking_changes:
                    changelog += f"{change}\n"
                changelog += "\n"
            
            # Features
            if release.features:
                changelog += "### Adicionado\n"
                for feature in release.features:
                    changelog += f"{feature}\n"
                changelog += "\n"
            
            # Fixes
            if release.fixes:
                changelog += "### Corrigido\n"
                for fix in release.fixes:
                    changelog += f"{fix}\n"
                changelog += "\n"
            
            # Documentation
            if release.docs:
                changelog += "### Documentação\n"
                for doc in release.docs:
                    changelog += f"{doc}\n"
                changelog += "\n"
            
            # Chores
            if release.chore:
                changelog += "### Manutenção\n"
                for chore in release.chore:
                    changelog += f"{chore}\n"
                changelog += "\n"
            
            changelog += "---\n\n"
        
        return changelog
    
    def suggest_version(self, commits: List[Commit], current_version: str) -> str:
        """Sugere próxima versão baseada nos commits"""
        print("🔍 Analisando commits para sugerir versão...")
        
        # Parse da versão atual
        version_parts = current_version.split('.')
        major = int(version_parts[0])
        minor = int(version_parts[1])
        patch = int(version_parts[2]) if len(version_parts) > 2 else 0
        
        categorized = self.categorize_commits(commits)
        
        # Breaking changes = major version
        if categorized["breaking"]:
            return f"{major + 1}.0.0"
        
        # Features = minor version
        if categorized["feat"]:
            return f"{major}.{minor + 1}.0"
        
        # Fixes, docs, etc = patch version
        if any(categorized[key] for key in ["fix", "docs", "style", "refactor", "test", "chore", "perf", "ci", "build"]):
            return f"{major}.{minor}.{patch + 1}"
        
        return current_version
    
    def create_release_commit(self, version: str, changelog_content: str):
        """Cria commit de release"""
        print(f"📝 Criando commit de release {version}...")
        
        # Salva changelog
        with open(self.changelog_file, 'w', encoding='utf-8') as f:
            f.write(changelog_content)
        
        # Adiciona arquivo
        subprocess.run(["git", "add", str(self.changelog_file)], cwd=self.repo_path, check=True)
        
        # Cria commit
        commit_message = f"chore: release {version}\n\n- Atualiza changelog\n- Versiona {version}"
        subprocess.run(["git", "commit", "-m", commit_message], cwd=self.repo_path, check=True)
        
        # Cria tag
        subprocess.run(["git", "tag", "-a", version, "-m", f"Release {version}"], cwd=self.repo_path, check=True)
        
        print(f"✅ Release {version} criada com sucesso!")
    
    def generate_pr_summary(self, pr_number: str) -> str:
        """Gera resumo de PR para changelog"""
        try:
            # Tenta obter informações do PR via GitHub CLI
            result = subprocess.run(
                ["gh", "pr", "view", pr_number, "--json", "title,body,labels"],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                pr_data = json.loads(result.stdout)
                title = pr_data.get("title", "")
                body = pr_data.get("body", "")
                labels = [label["name"] for label in pr_data.get("labels", [])]
                
                summary = f"**PR #{pr_number}:** {title}\n"
                if body:
                    summary += f"  {body[:100]}...\n"
                if labels:
                    summary += f"  Labels: {', '.join(labels)}\n"
                
                return summary
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        
        return f"**PR #{pr_number}:** (Informações não disponíveis)\n"
    
    def analyze_commit_patterns(self, commits: List[Commit]) -> Dict[str, Any]:
        """Analisa padrões nos commits"""
        print("📊 Analisando padrões nos commits...")
        
        analysis = {
            "total_commits": len(commits),
            "authors": {},
            "types": {},
            "scopes": {},
            "breaking_changes": 0,
            "prs": 0,
            "conventional_commits": 0
        }
        
        for commit in commits:
            # Conta autores
            analysis["authors"][commit.author] = analysis["authors"].get(commit.author, 0) + 1
            
            # Conta tipos
            analysis["types"][commit.type] = analysis["types"].get(commit.type, 0) + 1
            
            # Conta escopos
            if commit.scope:
                analysis["scopes"][commit.scope] = analysis["scopes"].get(commit.scope, 0) + 1
            
            # Conta breaking changes
            if commit.breaking:
                analysis["breaking_changes"] += 1
            
            # Conta PRs
            if commit.pr_number:
                analysis["prs"] += 1
            
            # Conta commits convencionais
            analysis["conventional_commits"] += 1
        
        return analysis
    
    def generate_analysis_report(self, analysis: Dict[str, Any]) -> str:
        """Gera relatório de análise"""
        report = f"""# Relatório de Análise de Commits

## Resumo Geral
- **Total de commits:** {analysis['total_commits']}
- **Commits convencionais:** {analysis['conventional_commits']} ({analysis['conventional_commits']/analysis['total_commits']*100:.1f}%)
- **Breaking changes:** {analysis['breaking_changes']}
- **PRs referenciados:** {analysis['prs']}

## Autores
"""
        
        for author, count in sorted(analysis["authors"].items(), key=lambda x: x[1], reverse=True):
            report += f"- **{author}:** {count} commits\n"
        
        report += "\n## Tipos de Commit\n"
        for commit_type, count in sorted(analysis["types"].items(), key=lambda x: x[1], reverse=True):
            type_name = self.config["types"].get(commit_type, commit_type)
            report += f"- **{type_name}:** {count} commits\n"
        
        if analysis["scopes"]:
            report += "\n## Escopos\n"
            for scope, count in sorted(analysis["scopes"].items(), key=lambda x: x[1], reverse=True):
                scope_name = self.config["scopes"].get(scope, scope)
                report += f"- **{scope_name}:** {count} commits\n"
        
        return report
    
    def run(self, from_tag: Optional[str] = None, to_tag: Optional[str] = None, 
            create_release: bool = False, version: Optional[str] = None):
        """Executa o processo completo de changelog"""
        print("🚀 Iniciando changelog automatizado...")
        
        # Obtém commits
        commits = self.get_git_commits(from_tag, to_tag)
        print(f"📊 Encontrados {len(commits)} commits")
        
        if not commits:
            print("⚠️ Nenhum commit encontrado no intervalo especificado")
            return
        
        # Analisa padrões
        analysis = self.analyze_commit_patterns(commits)
        
        # Obtém versão atual
        tags = self.get_git_tags()
        current_version = tags[0] if tags else "0.1.0"
        
        # Sugere próxima versão se não fornecida
        if not version:
            version = self.suggest_version(commits, current_version)
            print(f"💡 Versão sugerida: {version}")
        
        # Gera release
        release = self.generate_release_notes(commits, version)
        
        # Gera changelog
        releases = [release]
        changelog_content = self.generate_changelog_content(releases)
        
        # Salva changelog
        with open(self.changelog_file, 'w', encoding='utf-8') as f:
            f.write(changelog_content)
        
        # Salva relatório de análise
        analysis_report = self.generate_analysis_report(analysis)
        with open(self.repo_path / "docs" / "commit_analysis.md", 'w', encoding='utf-8') as f:
            f.write(analysis_report)
        
        # Cria release se solicitado
        if create_release:
            self.create_release_commit(version, changelog_content)
        
        print("✅ Changelog automatizado concluído!")
        print(f"📄 Changelog salvo em: {self.changelog_file}")
        print(f"📊 Relatório de análise salvo em: docs/commit_analysis.md")

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Gera changelog automatizado")
    parser.add_argument("--from-tag", help="Tag inicial (ex: v1.0.0)")
    parser.add_argument("--to-tag", help="Tag final (ex: v1.1.0)")
    parser.add_argument("--version", help="Versão para release")
    parser.add_argument("--create-release", action="store_true", help="Cria release automaticamente")
    parser.add_argument("--repo-path", default=".", help="Caminho do repositório")
    
    args = parser.parse_args()
    
    changelog_generator = AutomatedChangelog(args.repo_path)
    changelog_generator.run(
        from_tag=args.from_tag,
        to_tag=args.to_tag,
        create_release=args.create_release,
        version=args.version
    )

if __name__ == "__main__":
    main() 