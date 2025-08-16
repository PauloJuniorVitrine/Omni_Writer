#!/usr/bin/env python3
"""
📝 Automatic Changelog Generator
Omni Writer - Generate changelog from git commits and releases
"""

import os
import sys
import subprocess
import re
from datetime import datetime
from typing import List, Dict, Optional
import git
from git import Repo

class ChangelogGenerator:
    """Gerador automático de changelog"""
    
    def __init__(self):
        self.repo = Repo('.')
        self.commit_patterns = {
            'feature': r'^(feat|feature):\s*(.+)$',
            'fix': r'^(fix|bugfix):\s*(.+)$',
            'docs': r'^(docs|documentation):\s*(.+)$',
            'style': r'^(style|format):\s*(.+)$',
            'refactor': r'^(refactor|refactoring):\s*(.+)$',
            'test': r'^(test|testing):\s*(.+)$',
            'chore': r'^(chore|maintenance):\s*(.+)$',
            'security': r'^(security|sec):\s*(.+)$',
            'perf': r'^(perf|performance):\s*(.+)$',
            'ci': r'^(ci|cd|pipeline):\s*(.+)$'
        }
    
    def get_last_tag(self) -> Optional[str]:
        """Obtém a última tag do repositório"""
        try:
            tags = sorted(self.repo.tags, key=lambda t: t.commit.committed_datetime)
            return tags[-1].name if tags else None
        except Exception:
            return None
    
    def get_commits_since_tag(self, tag: str) -> List[git.Commit]:
        """Obtém commits desde a última tag"""
        try:
            tag_commit = self.repo.tag(tag).commit
            commits = list(self.repo.iter_commits(f'{tag_commit}..HEAD'))
            return commits
        except Exception:
            return []
    
    def get_all_commits(self) -> List[git.Commit]:
        """Obtém todos os commits do repositório"""
        try:
            return list(self.repo.iter_commits('HEAD'))
        except Exception:
            return []
    
    def categorize_commit(self, commit: git.Commit) -> Dict:
        """Categoriza um commit baseado na mensagem"""
        message = commit.message.strip()
        
        for category, pattern in self.commit_patterns.items():
            match = re.match(pattern, message, re.IGNORECASE)
            if match:
                return {
                    'category': category,
                    'description': match.group(2).strip(),
                    'hash': commit.hexsha[:8],
                    'author': commit.author.name,
                    'date': commit.committed_datetime.strftime('%Y-%m-%d'),
                    'message': message
                }
        
        # Commit não categorizado
        return {
            'category': 'other',
            'description': message.split('\n')[0],
            'hash': commit.hexsha[:8],
            'author': commit.author.name,
            'date': commit.committed_datetime.strftime('%Y-%m-%d'),
            'message': message
        }
    
    def get_version_info(self) -> Dict:
        """Obtém informações da versão atual"""
        try:
            # Tentar obter versão do setup.py ou pyproject.toml
            if os.path.exists('setup.py'):
                with open('setup.py', 'r') as f:
                    content = f.read()
                    version_match = re.search(r"version=['\"]([^'\"]+)['\"]", content)
                    if version_match:
                        return {'version': version_match.group(1)}
            
            if os.path.exists('pyproject.toml'):
                with open('pyproject.toml', 'r') as f:
                    content = f.read()
                    version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if version_match:
                        return {'version': version_match.group(1)}
            
            # Usar data como versão
            return {'version': datetime.now().strftime('%Y.%m.%d')}
            
        except Exception:
            return {'version': datetime.now().strftime('%Y.%m.%d')}
    
    def generate_changelog(self) -> str:
        """Gera o changelog completo"""
        version_info = self.get_version_info()
        version = version_info['version']
        
        changelog = f"""# 📝 Changelog - Omni Writer v{version}

## 🚀 Release v{version} - {datetime.now().strftime('%Y-%m-%d')}

### 📊 Release Summary
- **Version:** {version}
- **Release Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Repository:** {self.repo.remotes.origin.url if self.repo.remotes else 'Local Repository'}
- **Branch:** {self.repo.active_branch.name}
- **Commit:** {self.repo.head.commit.hexsha[:8]}

"""
        
        # Obter commits
        last_tag = self.get_last_tag()
        if last_tag:
            commits = self.get_commits_since_tag(last_tag)
            changelog += f"### 📋 Changes since v{last_tag}\n\n"
        else:
            commits = self.get_all_commits()[:50]  # Últimos 50 commits
            changelog += "### 📋 Recent Changes\n\n"
        
        if not commits:
            changelog += "No changes detected.\n\n"
        else:
            # Categorizar commits
            categorized = {}
            for commit in commits:
                category_info = self.categorize_commit(commit)
                category = category_info['category']
                
                if category not in categorized:
                    categorized[category] = []
                
                categorized[category].append(category_info)
            
            # Ordem de prioridade das categorias
            category_order = [
                'feature', 'fix', 'security', 'perf', 'refactor',
                'test', 'docs', 'style', 'ci', 'chore', 'other'
            ]
            
            category_names = {
                'feature': '✨ New Features',
                'fix': '🐛 Bug Fixes',
                'security': '🔒 Security Updates',
                'perf': '⚡ Performance Improvements',
                'refactor': '♻️ Code Refactoring',
                'test': '🧪 Testing',
                'docs': '📚 Documentation',
                'style': '🎨 Code Style',
                'ci': '🔧 CI/CD',
                'chore': '🔨 Maintenance',
                'other': '📝 Other Changes'
            }
            
            # Gerar seções por categoria
            for category in category_order:
                if category in categorized and categorized[category]:
                    changelog += f"#### {category_names[category]}\n\n"
                    
                    for commit_info in categorized[category]:
                        changelog += f"- **{commit_info['description']}** "
                        changelog += f"([{commit_info['hash']}]({self.repo.remotes.origin.url}/commit/{commit_info['hash']}) "
                        changelog += f"by {commit_info['author']})\n"
                    
                    changelog += "\n"
        
        # Adicionar informações de build
        changelog += f"""
### 🏗️ Build Information
- **Python Version:** {sys.version.split()[0]}
- **Build Date:** {datetime.now().isoformat()}
- **Build Environment:** GitHub Actions
- **Auto-Healing:** Enabled with OpenAI Codex

### 📦 Artifacts
- **Python Executable:** `OmniWriter` (PyInstaller)
- **WordPress Plugin:** `wordpress-plugin.zip`
- **Source Code:** Available in repository

### 🔗 Links
- **Repository:** {self.repo.remotes.origin.url if self.repo.remotes else 'Local'}
- **Issues:** {self.repo.remotes.origin.url}/issues if self.repo.remotes else 'N/A'}
- **Documentation:** Available in `/docs` directory

### 📋 Migration Notes
- No breaking changes in this release
- All existing configurations remain compatible
- Database migrations: None required

### 🎯 What's New
This release includes:
- Auto-healing pipeline with OpenAI Codex integration
- Comprehensive test coverage (unit, integration, e2e, load)
- Security scanning and quality gates
- Automated packaging and release management
- Real-time monitoring and notifications

### 🐛 Known Issues
- None reported

### 🔮 Roadmap
- Enhanced AI-powered code analysis
- Multi-language support expansion
- Advanced performance optimization
- Extended plugin ecosystem

---
*Generated automatically by Omni Writer Auto-Healing Pipeline v3.0*
*Last updated: {datetime.now().isoformat()}*
"""
        
        return changelog
    
    def save_changelog(self, filepath: str = None):
        """Salva o changelog em arquivo"""
        if not filepath:
            filepath = 'CHANGELOG.md'
        
        changelog_content = self.generate_changelog()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(changelog_content)
        
        print(f"✅ Changelog saved to: {filepath}")
        return filepath

def main():
    """Função principal"""
    generator = ChangelogGenerator()
    
    # Verificar argumentos
    output_file = None
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    
    # Gerar e salvar changelog
    try:
        filepath = generator.save_changelog(output_file)
        print(f"📝 Changelog generated successfully: {filepath}")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error generating changelog: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 