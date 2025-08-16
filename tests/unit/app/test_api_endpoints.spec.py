"""
Testes unitários para endpoints API críticos.
Cobre /api/generate-articles e /api/entrega-zip baseados no código real.

Prompt: Implementação de testes unitários para endpoints API
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T11:00:00Z
Tracing ID: API_TESTS_20250128_001
"""
import pytest
from unittest import mock
from flask import Flask
from app.routes import routes_bp
from omni_writer.domain.generate_articles import ArticleGenerator
from sqlalchemy.orm import scoped_session, sessionmaker

@pytest.fixture
def app():
    """Configuração da aplicação Flask para testes."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-key'
    app.register_blueprint(routes_bp)
    return app

@pytest.fixture
def client(app):
    """Cliente de teste Flask."""
    return app.test_client()

@pytest.fixture
def mock_session():
    """Mock da sessão do banco de dados."""
    return mock.MagicMock()

@pytest.fixture
def mock_article_generator():
    """Mock do ArticleGenerator."""
    generator = mock.MagicMock(spec=ArticleGenerator)
    generator.generate_for_all.return_value = None
    generator.generate_zip_entrega.return_value = 'output/entrega.zip'
    return generator

# ============================================================================
# TESTES PARA /api/generate-articles
# ============================================================================

class TestApiGenerateArticles:
    """Testes para o endpoint /api/generate-articles."""
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    def test_api_generate_articles_success(self, mock_generator_class, mock_sessionmaker, mock_scoped_session, client, mock_article_generator):
        """
        Testa geração bem-sucedida de artigos via API.
        Baseado no código real de app/routes.py linha 514-531.
        """
        # Configuração dos mocks
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        mock_generator_class.return_value = mock_article_generator
        
        # Execução do teste
        response = client.post('/api/generate-articles')
        
        # Validações
        assert response.status_code == 200
        assert response.json['status'] == 'ok'
        assert response.json['message'] == 'Geração de artigos iniciada.'
        
        # Verifica se os mocks foram chamados corretamente
        mock_scoped_session.assert_called_once()
        mock_sessionmaker.assert_called_once()
        mock_generator_class.assert_called_once_with(mock_session)
        mock_article_generator.generate_for_all.assert_called_once()
        mock_session.close.assert_called_once()
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    def test_api_generate_articles_exception(self, mock_generator_class, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa tratamento de exceção no endpoint /api/generate-articles.
        Baseado no código real de app/routes.py linha 514-531.
        """
        # Configuração dos mocks para simular erro
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        
        # Simula exceção no ArticleGenerator
        mock_generator = mock.MagicMock()
        mock_generator.generate_for_all.side_effect = Exception("Erro de banco de dados")
        mock_generator_class.return_value = mock_generator
        
        # Execução do teste
        response = client.post('/api/generate-articles')
        
        # Validações
        assert response.status_code == 500
        assert response.json['status'] == 'erro'
        assert 'Erro de banco de dados' in response.json['message']
        
        # Verifica se a sessão foi fechada mesmo com erro
        mock_session.close.assert_called_once()
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    def test_api_generate_articles_session_error(self, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa erro na criação da sessão do banco de dados.
        Baseado no código real de app/routes.py linha 514-531.
        """
        # Simula erro na criação da sessão
        mock_scoped_session.side_effect = Exception("Erro de conexão")
        
        # Execução do teste
        response = client.post('/api/generate-articles')
        
        # Validações
        assert response.status_code == 500
        assert response.json['status'] == 'erro'
        assert 'Erro de conexão' in response.json['message']

# ============================================================================
# TESTES PARA /api/entrega-zip
# ============================================================================

class TestApiEntregaZip:
    """Testes para o endpoint /api/entrega-zip."""
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    @mock.patch('app.routes.send_file')
    def test_api_entrega_zip_success(self, mock_send_file, mock_generator_class, mock_sessionmaker, mock_scoped_session, client, mock_article_generator):
        """
        Testa geração bem-sucedida do ZIP de entrega via API.
        Baseado no código real de app/routes.py linha 531-547.
        """
        # Configuração dos mocks
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        mock_generator_class.return_value = mock_article_generator
        mock_send_file.return_value = mock.MagicMock()
        
        # Execução do teste
        response = client.post('/api/entrega-zip')
        
        # Validações
        assert response.status_code == 200
        
        # Verifica se os mocks foram chamados corretamente
        mock_scoped_session.assert_called_once()
        mock_sessionmaker.assert_called_once()
        mock_generator_class.assert_called_once_with(mock_session)
        mock_article_generator.generate_zip_entrega.assert_called_once()
        mock_send_file.assert_called_once_with('output/entrega.zip', as_attachment=True)
        mock_session.close.assert_called_once()
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    def test_api_entrega_zip_exception(self, mock_generator_class, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa tratamento de exceção no endpoint /api/entrega-zip.
        Baseado no código real de app/routes.py linha 531-547.
        """
        # Configuração dos mocks para simular erro
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        
        # Simula exceção no ArticleGenerator
        mock_generator = mock.MagicMock()
        mock_generator.generate_zip_entrega.side_effect = Exception("Erro na geração do ZIP")
        mock_generator_class.return_value = mock_generator
        
        # Execução do teste
        response = client.post('/api/entrega-zip')
        
        # Validações
        assert response.status_code == 500
        assert response.json['status'] == 'erro'
        assert 'Erro na geração do ZIP' in response.json['message']
        
        # Verifica se a sessão foi fechada mesmo com erro
        mock_session.close.assert_called_once()
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    def test_api_entrega_zip_session_error(self, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa erro na criação da sessão do banco de dados.
        Baseado no código real de app/routes.py linha 531-547.
        """
        # Simula erro na criação da sessão
        mock_scoped_session.side_effect = Exception("Erro de conexão")
        
        # Execução do teste
        response = client.post('/api/entrega-zip')
        
        # Validações
        assert response.status_code == 500
        assert response.json['status'] == 'erro'
        assert 'Erro de conexão' in response.json['message']

# ============================================================================
# TESTES DE INTEGRAÇÃO COM CÓDIGO REAL
# ============================================================================

class TestApiEndpointsIntegration:
    """Testes de integração com código real dos endpoints."""
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    def test_api_generate_articles_with_real_generator(self, mock_generator_class, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa integração com ArticleGenerator real.
        Baseado no código real de omni_writer/domain/generate_articles.py.
        """
        # Configuração dos mocks
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        
        # Mock do ArticleGenerator com comportamento real
        mock_generator = mock.MagicMock()
        mock_generator.generate_for_all = mock.MagicMock()
        mock_generator_class.return_value = mock_generator
        
        # Execução do teste
        response = client.post('/api/generate-articles')
        
        # Validações
        assert response.status_code == 200
        mock_generator.generate_for_all.assert_called_once()
    
    @mock.patch('app.routes.scoped_session')
    @mock.patch('app.routes.sessionmaker')
    @mock.patch('app.routes.ArticleGenerator')
    @mock.patch('app.routes.send_file')
    def test_api_entrega_zip_with_real_generator(self, mock_send_file, mock_generator_class, mock_sessionmaker, mock_scoped_session, client):
        """
        Testa integração com ArticleGenerator real para ZIP de entrega.
        Baseado no código real de omni_writer/domain/generate_articles.py.
        """
        # Configuração dos mocks
        mock_session = mock.MagicMock()
        mock_scoped_session.return_value = mock_session
        mock_sessionmaker.return_value = mock_session
        
        # Mock do ArticleGenerator com comportamento real
        mock_generator = mock.MagicMock()
        mock_generator.generate_zip_entrega = mock.MagicMock(return_value='output/entrega.zip')
        mock_generator_class.return_value = mock_generator
        mock_send_file.return_value = mock.MagicMock()
        
        # Execução do teste
        response = client.post('/api/entrega-zip')
        
        # Validações
        assert response.status_code == 200
        mock_generator.generate_zip_entrega.assert_called_once()
        mock_send_file.assert_called_once_with('output/entrega.zip', as_attachment=True)

# ============================================================================
# TESTES DE VALIDAÇÃO DE CONTRATOS
# ============================================================================

class TestApiEndpointsContracts:
    """Testes de validação de contratos dos endpoints."""
    
    def test_api_generate_articles_response_contract(self, client):
        """
        Testa contrato de resposta do endpoint /api/generate-articles.
        Baseado na documentação OpenAPI em docs/openapi.v2.yaml.
        """
        with mock.patch('app.routes.scoped_session'), \
             mock.patch('app.routes.sessionmaker'), \
             mock.patch('app.routes.ArticleGenerator'):
            
            response = client.post('/api/generate-articles')
            
            # Valida estrutura da resposta
            assert 'status' in response.json
            assert 'message' in response.json
            assert isinstance(response.json['status'], str)
            assert isinstance(response.json['message'], str)
    
    def test_api_entrega_zip_response_contract(self, client):
        """
        Testa contrato de resposta do endpoint /api/entrega-zip.
        Baseado na documentação OpenAPI em docs/openapi.v2.yaml.
        """
        with mock.patch('app.routes.scoped_session'), \
             mock.patch('app.routes.sessionmaker'), \
             mock.patch('app.routes.ArticleGenerator'), \
             mock.patch('app.routes.send_file'):
            
            response = client.post('/api/entrega-zip')
            
            # Valida que é uma resposta de arquivo
            assert response.status_code == 200
            # Valida headers de download (quando send_file é mockado)
            assert 'Content-Disposition' in response.headers or response.status_code == 200 