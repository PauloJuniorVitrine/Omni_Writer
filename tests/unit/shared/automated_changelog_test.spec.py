#!/usr/bin/env python3
"""
Testes unitários para o sistema de changelog automatizado.
Cobre análise de commits, categorização e geração de changelog.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from shared.automated_changelog import (
    AutomatedChangelog, 
    CommitInfo, 
    ChangelogEntry
)

class TestAutomatedChangelog:
    """Testes para AutomatedChangelog."""
    
    @pytest.fixture
    def changelog(self):
        """Instância do changelog para testes."""
        return AutomatedChangelog()
    
    @pytest.fixture
    def sample_commits(self):
        """Commits de exemplo para testes."""
        return [
            CommitInfo(
                hash="abc123",
                author="João Silva",
                date="2025-01-27",
                message="feat: adiciona nova funcionalidade de cache",
                type="feat",
                scope="",
                description="adiciona nova funcionalidade de cache",
                breaking=False,
                pr_number="123"
            ),
            CommitInfo(
                hash="def456",
                author="Maria Santos",
                date="2025-01-26",
                message="fix(cache): corrige bug de invalidação",
                type="fix",
                scope="cache",
                description="corrige bug de invalidação",
                breaking=False,
                pr_number="124"
            ),
            CommitInfo(
                hash="ghi789",
                author="Pedro Costa",
                date="2025-01-25",
                message="BREAKING CHANGE: altera API de autenticação",
                type="feat",
                scope="",
                description="altera API de autenticação",
                breaking=True,
                pr_number="125"
            )
        ]
    
    def test_init(self, changelog):
        """Testa inicialização do changelog."""
        assert len(changelog.commit_types) == 11
        assert 'feat' in changelog.commit_types
        assert 'fix' in changelog.commit_types
        assert changelog.repo_path == "."
    
    def test_parse_commit_line_valid(self, changelog):
        """Testa análise de linha de commit válida."""
        line = "abc123|João Silva|2025-01-27|feat: adiciona nova funcionalidade"
        
        commit = changelog._parse_commit_line(line)
        
        assert commit is not None
        assert commit.hash == "abc123"
        assert commit.author == "João Silva"
        assert commit.date == "2025-01-27"
        assert commit.type == "feat"
        assert commit.description == "adiciona nova funcionalidade"
        assert commit.breaking is False
    
    def test_parse_commit_line_with_scope(self, changelog):
        """Testa análise de commit com escopo."""
        line = "def456|Maria Santos|2025-01-26|fix(cache): corrige bug"
        
        commit = changelog._parse_commit_line(line)
        
        assert commit is not None
        assert commit.type == "fix"
        assert commit.scope == "cache"
        assert commit.description == "corrige bug"
    
    def test_parse_commit_line_with_pr(self, changelog):
        """Testa análise de commit com PR."""
        line = "ghi789|Pedro Costa|2025-01-25|feat: nova funcionalidade #123"
        
        commit = changelog._parse_commit_line(line)
        
        assert commit is not None
        assert commit.pr_number == "123"
    
    def test_parse_commit_line_breaking(self, changelog):
        """Testa análise de commit breaking change."""
        line = "jkl012|Ana Silva|2025-01-24|feat: BREAKING CHANGE: altera API"
        
        commit = changelog._parse_commit_line(line)
        
        assert commit is not None
        assert commit.breaking is True
    
    def test_parse_commit_line_invalid(self, changelog):
        """Testa análise de linha de commit inválida."""
        line = "invalid commit message"
        
        commit = changelog._parse_commit_line(line)
        
        assert commit is None
    
    def test_categorize_changes(self, changelog, sample_commits):
        """Testa categorização de mudanças."""
        changes = changelog.categorize_changes(sample_commits)
        
        assert "✨ Novas funcionalidades" in changes
        assert "🐛 Correções de bugs" in changes
        
        # Verifica se mudanças foram categorizadas corretamente
        feat_changes = changes["✨ Novas funcionalidades"]
        assert len(feat_changes) == 2  # feat + breaking change
        
        fix_changes = changes["🐛 Correções de bugs"]
        assert len(fix_changes) == 1
        assert "**cache**: corrige bug de invalidação (#124)" in fix_changes[0]
    
    def test_get_breaking_changes(self, changelog, sample_commits):
        """Testa obtenção de breaking changes."""
        breaking_changes = changelog.get_breaking_changes(sample_commits)
        
        assert len(breaking_changes) == 1
        assert "altera API de autenticação" in breaking_changes[0]
    
    def test_get_contributors(self, changelog, sample_commits):
        """Testa obtenção de contribuidores."""
        contributors = changelog.get_contributors(sample_commits)
        
        assert len(contributors) == 3
        assert "João Silva" in contributors
        assert "Maria Santos" in contributors
        assert "Pedro Costa" in contributors
    
    def test_get_prs(self, changelog, sample_commits):
        """Testa obtenção de PRs."""
        prs = changelog.get_prs(sample_commits)
        
        assert len(prs) == 3
        assert "123" in prs
        assert "124" in prs
        assert "125" in prs
    
    def test_determine_version_bump_major(self, changelog):
        """Testa determinação de bump major."""
        commits = [
            CommitInfo(
                hash="abc123",
                author="Test",
                date="2025-01-27",
                message="feat: BREAKING CHANGE: altera API",
                type="feat",
                scope="",
                description="altera API",
                breaking=True
            )
        ]
        
        new_version = changelog.determine_version_bump(commits, "1.0.0")
        assert new_version == "2.0.0"
    
    def test_determine_version_bump_minor(self, changelog):
        """Testa determinação de bump minor."""
        commits = [
            CommitInfo(
                hash="abc123",
                author="Test",
                date="2025-01-27",
                message="feat: nova funcionalidade",
                type="feat",
                scope="",
                description="nova funcionalidade",
                breaking=False
            )
        ]
        
        new_version = changelog.determine_version_bump(commits, "1.0.0")
        assert new_version == "1.1.0"
    
    def test_determine_version_bump_patch(self, changelog):
        """Testa determinação de bump patch."""
        commits = [
            CommitInfo(
                hash="abc123",
                author="Test",
                date="2025-01-27",
                message="fix: corrige bug",
                type="fix",
                scope="",
                description="corrige bug",
                breaking=False
            )
        ]
        
        new_version = changelog.determine_version_bump(commits, "1.0.0")
        assert new_version == "1.0.1"
    
    def test_determine_version_bump_no_change(self, changelog):
        """Testa determinação sem mudança de versão."""
        commits = [
            CommitInfo(
                hash="abc123",
                author="Test",
                date="2025-01-27",
                message="docs: atualiza documentação",
                type="docs",
                scope="",
                description="atualiza documentação",
                breaking=False
            )
        ]
        
        new_version = changelog.determine_version_bump(commits, "1.0.0")
        assert new_version == "1.0.0"
    
    def test_generate_changelog_entry(self, changelog, sample_commits):
        """Testa geração de entrada do changelog."""
        entry = changelog.generate_changelog_entry(sample_commits, "1.1.0")
        
        assert entry.version == "1.1.0"
        assert entry.date == changelog._get_current_date()
        assert len(entry.changes) > 0
        assert len(entry.breaking_changes) == 1
        assert len(entry.contributors) == 3
        assert len(entry.prs) == 3
    
    def test_format_changelog_entry(self, changelog, sample_commits):
        """Testa formatação de entrada do changelog."""
        entry = changelog.generate_changelog_entry(sample_commits, "1.1.0")
        formatted = changelog.format_changelog_entry(entry)
        
        assert "Changelog - v1.1.0" in formatted
        assert "Breaking Changes" in formatted
        assert "✨ Novas funcionalidades" in formatted
        assert "🐛 Correções de bugs" in formatted
        assert "👥 Contribuidores" in formatted
        assert "🔗 Pull Requests" in formatted
    
    def test_generate_release_notes(self, changelog, sample_commits):
        """Testa geração de release notes."""
        entry = changelog.generate_changelog_entry(sample_commits, "1.1.0")
        notes = changelog.generate_release_notes(entry)
        
        assert "Release v1.1.0" in notes
        assert "Breaking Changes" in notes
        assert "Resumo" in notes
        assert "Agradecimentos" in notes
    
    def test_get_commit_statistics(self, changelog, sample_commits):
        """Testa obtenção de estatísticas de commits."""
        stats = changelog.get_commit_statistics(sample_commits)
        
        assert stats['total_commits'] == 3
        assert stats['breaking_changes'] == 1
        assert stats['prs'] == 3
        assert len(stats['types']) == 2  # feat e fix
        assert len(stats['contributors']) == 3
        assert stats['date_range']['start'] == "2025-01-25"
        assert stats['date_range']['end'] == "2025-01-27"
    
    def test_save_changelog(self, changelog):
        """Testa salvamento de changelog."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Muda para diretório temporário
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Cria diretório docs
                os.makedirs('docs', exist_ok=True)
                
                # Salva changelog
                content = "# Test Changelog\n\nTest content"
                filepath = changelog.save_changelog(content, 'test_changelog.md')
                
                # Verifica se arquivo foi criado
                assert os.path.exists(filepath)
                
                # Verifica conteúdo
                with open(filepath, 'r', encoding='utf-8') as f:
                    saved_content = f.read()
                
                assert saved_content == content
                
            finally:
                os.chdir(original_cwd)
    
    def test_update_main_changelog(self, changelog, sample_commits):
        """Testa atualização do changelog principal."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Muda para diretório temporário
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Cria changelog principal existente
                existing_content = "# Existing Changelog\n\nOld content"
                with open('CHANGELOG.md', 'w', encoding='utf-8') as f:
                    f.write(existing_content)
                
                # Gera entrada
                entry = changelog.generate_changelog_entry(sample_commits, "1.1.0")
                
                # Atualiza changelog principal
                changelog.update_main_changelog(entry)
                
                # Verifica se foi atualizado
                with open('CHANGELOG.md', 'r', encoding='utf-8') as f:
                    updated_content = f.read()
                
                assert "Changelog - v1.1.0" in updated_content
                assert "Existing Changelog" in updated_content
                
            finally:
                os.chdir(original_cwd)
    
    @patch('subprocess.run')
    def test_get_commits_since_success(self, mock_run, changelog):
        """Testa obtenção de commits com sucesso."""
        # Mock do resultado do git log
        mock_result = Mock()
        mock_result.stdout = """abc123|João Silva|2025-01-27|feat: nova funcionalidade
def456|Maria Santos|2025-01-26|fix: corrige bug"""
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        commits = changelog.get_commits_since("2025-01-01")
        
        assert len(commits) == 2
        assert commits[0].author == "João Silva"
        assert commits[1].author == "Maria Santos"
    
    @patch('subprocess.run')
    def test_get_commits_since_error(self, mock_run, changelog):
        """Testa obtenção de commits com erro."""
        # Mock de erro
        mock_run.side_effect = subprocess.CalledProcessError(1, "git log")
        
        commits = changelog.get_commits_since("2025-01-01")
        
        assert len(commits) == 0
    
    def test_commit_info_dataclass(self):
        """Testa dataclass CommitInfo."""
        commit = CommitInfo(
            hash="abc123",
            author="Test Author",
            date="2025-01-27",
            message="feat: test",
            type="feat",
            scope="test",
            description="test",
            breaking=False,
            pr_number="123"
        )
        
        assert commit.hash == "abc123"
        assert commit.author == "Test Author"
        assert commit.type == "feat"
        assert commit.scope == "test"
        assert commit.breaking is False
        assert commit.pr_number == "123"
    
    def test_changelog_entry_dataclass(self):
        """Testa dataclass ChangelogEntry."""
        entry = ChangelogEntry(
            version="1.1.0",
            date="2025-01-27",
            changes={"feat": ["nova funcionalidade"]},
            breaking_changes=["breaking change"],
            contributors=["João Silva"],
            prs=["123"]
        )
        
        assert entry.version == "1.1.0"
        assert entry.date == "2025-01-27"
        assert "feat" in entry.changes
        assert len(entry.breaking_changes) == 1
        assert len(entry.contributors) == 1
        assert len(entry.prs) == 1 