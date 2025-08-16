#!/usr/bin/env python3
"""
Sistema de Changelog Automatizado para Omni Writer.
Gera changelog incremental baseado em commits e PRs.
"""

import os
import re
import json
import subprocess
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import logging

# Configuração de logging
changelog_logger = logging.getLogger('automated_changelog')
changelog_logger.setLevel(logging.INFO)

@dataclass
class CommitInfo:
    """Informações de um commit."""
    hash: str
    author: str
    date: str
    message: str
    type: str
    scope: str
    description: str
    breaking: bool = False
    pr_number: Optional[str] = None

@dataclass
class ChangelogEntry:
    """Entrada do changelog."""
    version: str
    date: str
    changes: Dict[str, List[str]]
    breaking_changes: List[str]
    contributors: List[str]
    prs: List[str]

class AutomatedChangelog:
    """
    Sistema de changelog automatizado.
    
    Funcionalidades:
    - Análise de commits com convenção semântica
    - Integração com Pull Requests
    - Categorização automática de mudanças
    - Geração de release notes
    - Versionamento semântico
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.commit_types = {
            'feat': '✨ Novas funcionalidades',
            'fix': '🐛 Correções de bugs',
            'docs': '📚 Documentação',
            'style': '🎨 Melhorias de estilo',
            'refactor': '♻️ Refatoração',
            'perf': '⚡ Melhorias de performance',
            'test': '🧪 Testes',
            'chore': '🔧 Tarefas de manutenção',
            'ci': '👷 CI/CD',
            'build': '📦 Build',
            'revert': '⏪ Reversões'
        }
        
        # Padrões para análise de commits
        self.commit_pattern = re.compile(
            r'^(\w+)(?:\(([\w\-]+)\))?: (.+)$'
        )
        
        self.breaking_pattern = re.compile(
            r'BREAKING CHANGE: (.+)'
        )
        
        self.pr_pattern = re.compile(
            r'#(\d+)'
        )
    
    def get_commits_since(self, since: str = None, until: str = None) -> List[CommitInfo]:
        """
        Obtém commits desde uma data específica.
        
        Args:
            since: Data inicial (formato: YYYY-MM-DD)
            until: Data final (formato: YYYY-MM-DD)
        
        Returns:
            Lista de commits
        """
        try:
            # Constrói comando git
            cmd = ['git', 'log', '--pretty=format:%H|%an|%ad|%s', '--date=short']
            
            if since:
                cmd.append(f'--since={since}')
            if until:
                cmd.append(f'--until={until}')
            
            # Executa comando
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    commit_info = self._parse_commit_line(line)
                    if commit_info:
                        commits.append(commit_info)
            
            return commits
            
        except subprocess.CalledProcessError as e:
            changelog_logger.error(f"Erro ao executar git log: {e}")
            return []
    
    def _parse_commit_line(self, line: str) -> Optional[CommitInfo]:
        """
        Analisa uma linha de commit.
        
        Args:
            line: Linha do git log
        
        Returns:
            Informações do commit ou None
        """
        try:
            parts = line.split('|')
            if len(parts) != 4:
                return None
            
            hash_val, author, date, message = parts
            
            # Analisa mensagem do commit
            match = self.commit_pattern.match(message)
            if not match:
                return None
            
            commit_type, scope, description = match.groups()
            
            # Verifica se é breaking change
            breaking = 'BREAKING CHANGE' in message
            
            # Extrai número do PR
            pr_match = self.pr_pattern.search(message)
            pr_number = pr_match.group(1) if pr_match else None
            
            return CommitInfo(
                hash=hash_val,
                author=author,
                date=date,
                message=message,
                type=commit_type,
                scope=scope or '',
                description=description,
                breaking=breaking,
                pr_number=pr_number
            )
            
        except Exception as e:
            changelog_logger.error(f"Erro ao analisar commit: {e}")
            return None
    
    def categorize_changes(self, commits: List[CommitInfo]) -> Dict[str, List[str]]:
        """
        Categoriza mudanças por tipo.
        
        Args:
            commits: Lista de commits
        
        Returns:
            Mudanças categorizadas
        """
        changes = {}
        
        for commit in commits:
            if commit.type in self.commit_types:
                category = self.commit_types[commit.type]
                
                if category not in changes:
                    changes[category] = []
                
                # Formata descrição
                description = commit.description
                if commit.scope:
                    description = f"**{commit.scope}**: {description}"
                
                if commit.pr_number:
                    description += f" (#{commit.pr_number})"
                
                changes[category].append(description)
        
        return changes
    
    def get_breaking_changes(self, commits: List[CommitInfo]) -> List[str]:
        """
        Obtém mudanças breaking.
        
        Args:
            commits: Lista de commits
        
        Returns:
            Lista de breaking changes
        """
        breaking_changes = []
        
        for commit in commits:
            if commit.breaking:
                # Extrai descrição do breaking change
                match = self.breaking_pattern.search(commit.message)
                if match:
                    description = match.group(1)
                else:
                    description = commit.description
                
                breaking_changes.append(description)
        
        return breaking_changes
    
    def get_contributors(self, commits: List[CommitInfo]) -> List[str]:
        """
        Obtém lista de contribuidores.
        
        Args:
            commits: Lista de commits
        
        Returns:
            Lista de contribuidores únicos
        """
        contributors = set()
        
        for commit in commits:
            contributors.add(commit.author)
        
        return sorted(list(contributors))
    
    def get_prs(self, commits: List[CommitInfo]) -> List[str]:
        """
        Obtém números de PRs.
        
        Args:
            commits: Lista de commits
        
        Returns:
            Lista de números de PRs únicos
        """
        prs = set()
        
        for commit in commits:
            if commit.pr_number:
                prs.add(commit.pr_number)
        
        return sorted(list(prs), key=int)
    
    def determine_version_bump(self, commits: List[CommitInfo], current_version: str) -> str:
        """
        Determina bump de versão baseado nos commits.
        
        Args:
            commits: Lista de commits
            current_version: Versão atual
        
        Returns:
            Nova versão
        """
        major = 0
        minor = 0
        patch = 0
        
        for commit in commits:
            if commit.breaking:
                major += 1
            elif commit.type in ['feat']:
                minor += 1
            elif commit.type in ['fix', 'perf']:
                patch += 1
        
        # Parse versão atual
        version_parts = current_version.split('.')
        current_major = int(version_parts[0])
        current_minor = int(version_parts[1])
        current_patch = int(version_parts[2])
        
        # Calcula nova versão
        if major > 0:
            new_version = f"{current_major + major}.0.0"
        elif minor > 0:
            new_version = f"{current_major}.{current_minor + minor}.0"
        elif patch > 0:
            new_version = f"{current_major}.{current_minor}.{current_patch + patch}"
        else:
            new_version = current_version
        
        return new_version
    
    def generate_changelog_entry(self, commits: List[CommitInfo], version: str) -> ChangelogEntry:
        """
        Gera entrada do changelog.
        
        Args:
            commits: Lista de commits
            version: Versão
        
        Returns:
            Entrada do changelog
        """
        changes = self.categorize_changes(commits)
        breaking_changes = self.get_breaking_changes(commits)
        contributors = self.get_contributors(commits)
        prs = self.get_prs(commits)
        
        return ChangelogEntry(
            version=version,
            date=datetime.now().strftime('%Y-%m-%d'),
            changes=changes,
            breaking_changes=breaking_changes,
            contributors=contributors,
            prs=prs
        )
    
    def format_changelog_entry(self, entry: ChangelogEntry) -> str:
        """
        Formata entrada do changelog em markdown.
        
        Args:
            entry: Entrada do changelog
        
        Returns:
            Changelog formatado
        """
        changelog = f"""# Changelog - v{entry.version}

## Data: {entry.date}

"""
        
        # Breaking changes
        if entry.breaking_changes:
            changelog += "## ⚠️ Breaking Changes\n\n"
            for change in entry.breaking_changes:
                changelog += f"- {change}\n"
            changelog += "\n"
        
        # Mudanças por categoria
        for category, changes in entry.changes.items():
            if changes:
                changelog += f"## {category}\n\n"
                for change in changes:
                    changelog += f"- {change}\n"
                changelog += "\n"
        
        # Contribuidores
        if entry.contributors:
            changelog += "## 👥 Contribuidores\n\n"
            for contributor in entry.contributors:
                changelog += f"- {contributor}\n"
            changelog += "\n"
        
        # Pull Requests
        if entry.prs:
            changelog += "## 🔗 Pull Requests\n\n"
            for pr in entry.prs:
                changelog += f"- #{pr}\n"
            changelog += "\n"
        
        changelog += f"""
---
*Gerado automaticamente em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return changelog
    
    def generate_full_changelog(self, since_version: str = None, current_version: str = "1.0.0") -> str:
        """
        Gera changelog completo.
        
        Args:
            since_version: Versão desde quando gerar
            current_version: Versão atual
        
        Returns:
            Changelog completo
        """
        # Obtém commits desde a versão anterior
        commits = self.get_commits_since(since_version)
        
        # Determina nova versão
        new_version = self.determine_version_bump(commits, current_version)
        
        # Gera entrada
        entry = self.generate_changelog_entry(commits, new_version)
        
        return self.format_changelog_entry(entry)
    
    def save_changelog(self, content: str, filename: str = None) -> str:
        """
        Salva changelog em arquivo.
        
        Args:
            content: Conteúdo do changelog
            filename: Nome do arquivo (opcional)
        
        Returns:
            Caminho do arquivo salvo
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"CHANGELOG_{timestamp}.md"
        
        os.makedirs('docs', exist_ok=True)
        filepath = os.path.join('docs', filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        changelog_logger.info(f"Changelog salvo em: {filepath}")
        return filepath
    
    def update_main_changelog(self, entry: ChangelogEntry, main_file: str = "CHANGELOG.md"):
        """
        Atualiza changelog principal.
        
        Args:
            entry: Entrada do changelog
            main_file: Arquivo principal do changelog
        """
        content = self.format_changelog_entry(entry)
        
        # Lê changelog existente
        existing_content = ""
        if os.path.exists(main_file):
            with open(main_file, 'r', encoding='utf-8') as f:
                existing_content = f.read()
        
        # Adiciona nova entrada no topo
        new_content = content + "\n\n" + existing_content
        
        # Salva
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        changelog_logger.info(f"Changelog principal atualizado: {main_file}")
    
    def generate_release_notes(self, entry: ChangelogEntry) -> str:
        """
        Gera release notes para GitHub/GitLab.
        
        Args:
            entry: Entrada do changelog
        
        Returns:
            Release notes formatadas
        """
        notes = f"""# Release v{entry.version}

## 📋 Resumo

Esta release inclui {sum(len(changes) for changes in entry.changes.values())} mudanças.

"""
        
        # Breaking changes
        if entry.breaking_changes:
            notes += "## ⚠️ Breaking Changes\n\n"
            for change in entry.breaking_changes:
                notes += f"- {change}\n"
            notes += "\n"
        
        # Mudanças principais
        for category, changes in entry.changes.items():
            if changes:
                notes += f"## {category}\n\n"
                for change in changes:
                    notes += f"- {change}\n"
                notes += "\n"
        
        # Contribuidores
        if entry.contributors:
            notes += "## 👥 Agradecimentos\n\n"
            for contributor in entry.contributors:
                notes += f"@{contributor} "
            notes += "\n\n"
        
        # Pull Requests
        if entry.prs:
            notes += "## 🔗 Pull Requests\n\n"
            for pr in entry.prs:
                notes += f"#{pr} "
            notes += "\n\n"
        
        notes += f"""
---
*Release gerado automaticamente em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return notes
    
    def get_commit_statistics(self, commits: List[CommitInfo]) -> Dict[str, Any]:
        """
        Obtém estatísticas dos commits.
        
        Args:
            commits: Lista de commits
        
        Returns:
            Estatísticas
        """
        stats = {
            'total_commits': len(commits),
            'types': {},
            'contributors': {},
            'breaking_changes': 0,
            'prs': 0,
            'date_range': {
                'start': None,
                'end': None
            }
        }
        
        if commits:
            # Estatísticas por tipo
            for commit in commits:
                if commit.type not in stats['types']:
                    stats['types'][commit.type] = 0
                stats['types'][commit.type] += 1
            
            # Estatísticas por contribuidor
            for commit in commits:
                if commit.author not in stats['contributors']:
                    stats['contributors'][commit.author] = 0
                stats['contributors'][commit.author] += 1
            
            # Breaking changes
            stats['breaking_changes'] = sum(1 for c in commits if c.breaking)
            
            # PRs
            stats['prs'] = len(set(c.pr_number for c in commits if c.pr_number))
            
            # Range de datas
            dates = [c.date for c in commits]
            stats['date_range']['start'] = min(dates)
            stats['date_range']['end'] = max(dates)
        
        return stats

# Instância global
automated_changelog = AutomatedChangelog() 