"""
Testes para Secrets Scanner - Baseados em Código Real

Prompt: Integração Externa - Item 1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:05:00Z
Tracing ID: INT_CHECKLIST_20250127_001

Política de Testes:
- ✅ Baseados em código real do SecretsScanner
- ✅ Cenários reais de detecção de secrets
- ✅ Edge cases reais do sistema
- ❌ Nenhum teste sintético ou genérico
"""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime

from scripts.secrets_scanner import SecretsScanner, SecretMatch, ScanResult


class TestSecretsScanner:
    """Testes para o SecretsScanner baseados em funcionalidades reais."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.tracing_id = f"test_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.scanner = SecretsScanner(tracing_id=self.tracing_id)
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_secrets_scanner_detects_api_key_in_config_file(self):
        """Testa se o scanner detecta chaves de API reais em arquivo de configuração."""
        # Criar arquivo de configuração real
        config_content = """
# Configuração da aplicação
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
DATABASE_URL = "postgresql://user:password@localhost:5432/db"
        """
        
        config_file = os.path.join(self.temp_dir, "config.py")
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se detectou a API key
        api_key_matches = [m for m in result.matches if m.secret_type == 'api_key']
        assert len(api_key_matches) == 1
        assert "sk-1234567890abcdef1234567890abcdef1234567890abcdef" in api_key_matches[0].matched_text
        assert api_key_matches[0].file_path == config_file
        assert api_key_matches[0].line_number == 3
    
    def test_secrets_scanner_detects_database_url_with_credentials(self):
        """Testa se o scanner detecta URLs de banco com credenciais reais."""
        # Criar arquivo com database URL real
        db_content = """
# Configuração do banco
DATABASE_URL = "postgresql://admin:secretpass123@db.example.com:5432/production"
        """
        
        db_file = os.path.join(self.temp_dir, "database.py")
        with open(db_file, 'w', encoding='utf-8') as f:
            f.write(db_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se detectou a database URL
        db_matches = [m for m in result.matches if m.secret_type == 'database_url']
        assert len(db_matches) == 1
        assert "postgresql://admin:secretpass123@db.example.com:5432/production" in db_matches[0].matched_text
        assert db_matches[0].confidence == 0.9
    
    def test_secrets_scanner_identifies_false_positive_in_comment(self):
        """Testa se o scanner identifica corretamente falsos positivos em comentários."""
        # Criar arquivo com secret em comentário
        comment_content = """
# Exemplo de API key (não é real)
# API_KEY = "sk-example1234567890abcdef"
        """
        
        comment_file = os.path.join(self.temp_dir, "example.py")
        with open(comment_file, 'w', encoding='utf-8') as f:
            f.write(comment_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se identificou como falso positivo
        matches = [m for m in result.matches if m.secret_type == 'api_key']
        assert len(matches) == 1
        assert matches[0].is_false_positive is True
        assert "comentário" in matches[0].false_positive_reason.lower()
    
    def test_secrets_scanner_ignores_test_files(self):
        """Testa se o scanner ignora arquivos de teste conforme configuração real."""
        # Criar arquivo de teste com secret
        test_content = """
def test_something():
    api_key = "sk-test1234567890abcdef"
    assert api_key is not None
        """
        
        test_file = os.path.join(self.temp_dir, "test_file.py")
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se identificou como falso positivo por ser arquivo de teste
        matches = [m for m in result.matches if m.secret_type == 'api_key']
        assert len(matches) == 1
        assert matches[0].is_false_positive is True
        assert "teste" in matches[0].false_positive_reason.lower()
    
    def test_secrets_scanner_detects_oauth_token_in_headers(self):
        """Testa se o scanner detecta tokens OAuth reais em headers."""
        # Criar arquivo com OAuth token real
        oauth_content = """
headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
        """
        
        oauth_file = os.path.join(self.temp_dir, "auth.py")
        with open(oauth_file, 'w', encoding='utf-8') as f:
            f.write(oauth_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se detectou o OAuth token
        oauth_matches = [m for m in result.matches if m.secret_type == 'oauth_token']
        assert len(oauth_matches) == 1
        assert "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" in oauth_matches[0].matched_text
        assert oauth_matches[0].confidence == 0.7
    
    def test_secrets_scanner_calculates_risk_score_correctly(self):
        """Testa se o scanner calcula o score de risco baseado em secrets reais."""
        # Criar arquivo com múltiplos secrets reais
        secrets_content = """
# Configuração real da aplicação
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
DATABASE_URL = "postgresql://admin:secretpass123@db.example.com:5432/production"
PASSWORD = "mypassword123"
        """
        
        secrets_file = os.path.join(self.temp_dir, "secrets.py")
        with open(secrets_file, 'w', encoding='utf-8') as f:
            f.write(secrets_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se calculou score de risco
        assert result.risk_score > 0
        assert result.risk_score <= 100
        assert result.secrets_found == 3
        assert result.false_positives == 0
    
    def test_secrets_scanner_ignores_irrelevant_files(self):
        """Testa se o scanner ignora arquivos irrelevantes conforme configuração real."""
        # Criar arquivo com extensão irrelevante
        irrelevant_content = "This is a text file with no secrets"
        irrelevant_file = os.path.join(self.temp_dir, "document.txt")
        with open(irrelevant_file, 'w', encoding='utf-8') as f:
            f.write(irrelevant_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se ignorou arquivo irrelevante
        assert result.files_scanned == 0
        assert result.secrets_found == 0
    
    def test_secrets_scanner_extracts_context_correctly(self):
        """Testa se o scanner extrai contexto real das linhas."""
        # Criar arquivo com secret no meio
        context_content = """
# Linha anterior
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
# Linha posterior
        """
        
        context_file = os.path.join(self.temp_dir, "context.py")
        with open(context_file, 'w', encoding='utf-8') as f:
            f.write(context_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se extraiu contexto
        matches = [m for m in result.matches if m.secret_type == 'api_key']
        assert len(matches) == 1
        context = matches[0].context
        assert "Linha anterior" in context
        assert "Linha posterior" in context
        assert ">>> 2:" in context  # Linha com o secret
    
    def test_secrets_scanner_handles_encoding_errors_gracefully(self):
        """Testa se o scanner lida graciosamente com erros de encoding reais."""
        # Criar arquivo com encoding problemático
        binary_file = os.path.join(self.temp_dir, "binary.py")
        with open(binary_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
        
        # Executar scan (não deve falhar)
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se continuou funcionando
        assert result.files_scanned == 0  # Arquivo binário ignorado
        assert result.secrets_found == 0
    
    def test_secrets_scanner_export_results_creates_valid_json(self):
        """Testa se o scanner exporta resultados em formato JSON válido."""
        # Criar arquivo com secret
        secret_content = 'API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"'
        secret_file = os.path.join(self.temp_dir, "secret.py")
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write(secret_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Exportar resultados
        output_file = os.path.join(self.temp_dir, "results.json")
        exported_file = self.scanner.export_results(result, output_file)
        
        # Verificar se arquivo foi criado e é JSON válido
        assert os.path.exists(exported_file)
        with open(exported_file, 'r', encoding='utf-8') as f:
            import json
            data = json.load(f)
            assert data['scan_id'] == self.tracing_id
            assert data['secrets_found'] == 1
            assert len(data['matches']) == 1
    
    def test_secrets_scanner_generate_report_creates_markdown(self):
        """Testa se o scanner gera relatório em formato Markdown válido."""
        # Criar arquivo com secret
        secret_content = 'API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"'
        secret_file = os.path.join(self.temp_dir, "secret.py")
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write(secret_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Gerar relatório
        report_file = self.scanner.generate_report(result)
        
        # Verificar se arquivo foi criado e contém conteúdo esperado
        assert os.path.exists(report_file)
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "# Relatório de Secrets Scanner" in content
            assert "Secrets encontrados: 1" in content
            assert "sk-1234567890abcdef" in content
    
    def test_secrets_scanner_handles_empty_directory(self):
        """Testa se o scanner lida corretamente com diretório vazio."""
        # Executar scan em diretório vazio
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar resultados
        assert result.files_scanned == 0
        assert result.secrets_found == 0
        assert result.false_positives == 0
        assert result.risk_score == 0.0
        assert len(result.matches) == 0
    
    def test_secrets_scanner_detects_private_key_pem_format(self):
        """Testa se o scanner detecta chaves privadas em formato PEM real."""
        # Criar arquivo com chave privada PEM
        pem_content = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef1234567890abcdef1234567890abcdef
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
-----END RSA PRIVATE KEY-----
        """
        
        pem_file = os.path.join(self.temp_dir, "private_key.pem")
        with open(pem_file, 'w', encoding='utf-8') as f:
            f.write(pem_content)
        
        # Executar scan
        result = self.scanner.scan_directory(self.temp_dir)
        
        # Verificar se detectou a chave privada
        pem_matches = [m for m in result.matches if m.secret_type == 'private_key']
        assert len(pem_matches) == 1
        assert pem_matches[0].confidence == 0.95
        assert "-----BEGIN RSA PRIVATE KEY-----" in pem_matches[0].matched_text
        assert "-----END RSA PRIVATE KEY-----" in pem_matches[0].matched_text


class TestSecretMatch:
    """Testes para a classe SecretMatch baseados em uso real."""
    
    def test_secret_match_creation_with_real_data(self):
        """Testa criação de SecretMatch com dados reais."""
        match = SecretMatch(
            file_path="/path/to/config.py",
            line_number=42,
            secret_type="api_key",
            matched_text='API_KEY = "sk-1234567890abcdef"',
            confidence=0.8,
            context="   41: # Configuração\n>>> 42: API_KEY = \"sk-1234567890abcdef\"\n   43: # Fim"
        )
        
        assert match.file_path == "/path/to/config.py"
        assert match.line_number == 42
        assert match.secret_type == "api_key"
        assert match.confidence == 0.8
        assert match.is_false_positive is False
        assert match.false_positive_reason is None
    
    def test_secret_match_false_positive_flagging(self):
        """Testa flagging de falso positivo com dados reais."""
        match = SecretMatch(
            file_path="/path/to/example.py",
            line_number=10,
            secret_type="api_key",
            matched_text='# API_KEY = "sk-example123"',
            confidence=0.8,
            context="   9: # Exemplo\n>>> 10: # API_KEY = \"sk-example123\"\n   11: # Fim"
        )
        
        # Marcar como falso positivo
        match.is_false_positive = True
        match.false_positive_reason = "Match em comentário"
        
        assert match.is_false_positive is True
        assert match.false_positive_reason == "Match em comentário"


class TestScanResult:
    """Testes para a classe ScanResult baseados em uso real."""
    
    def test_scan_result_creation_with_real_data(self):
        """Testa criação de ScanResult com dados reais."""
        matches = [
            SecretMatch(
                file_path="/path/to/config.py",
                line_number=1,
                secret_type="api_key",
                matched_text='API_KEY = "sk-123"',
                confidence=0.8,
                context=">>> 1: API_KEY = \"sk-123\""
            )
        ]
        
        result = ScanResult(
            scan_id="test_scan_123",
            timestamp=datetime.now(),
            files_scanned=1,
            secrets_found=1,
            false_positives=0,
            scan_duration=1.5,
            matches=matches,
            risk_score=45.2
        )
        
        assert result.scan_id == "test_scan_123"
        assert result.files_scanned == 1
        assert result.secrets_found == 1
        assert result.false_positives == 0
        assert result.scan_duration == 1.5
        assert len(result.matches) == 1
        assert result.risk_score == 45.2 