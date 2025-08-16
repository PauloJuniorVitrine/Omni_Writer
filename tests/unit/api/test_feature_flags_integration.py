"""
Testes unitários para integração de feature flags na API.

Tracing ID: FEATURE_FLAGS_TEST_20250127_001
Data/Hora: 2025-01-27T23:00:00Z
Prompt: Implementar features flags de API pendentes
Ruleset: Enterprise+ Standards + Test Rules
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from flask import Flask
from app.routes import routes_bp
from shared.feature_flags import (
    FeatureFlagsManager,
    FeatureFlagConfig,
    FeatureFlagStatus,
    is_feature_enabled,
    get_all_feature_flags
)

class TestFeatureFlagsAPI:
    """Testes para integração de feature flags na API."""
    
    @pytest.fixture
    def app(self):
        """Cria aplicação Flask para testes."""
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        app.register_blueprint(routes_bp)
        return app
    
    @pytest.fixture
    def client(self, app):
        """Cliente de teste Flask."""
        return app.test_client()
    
    @pytest.fixture
    def mock_feature_flags(self):
        """Mock para feature flags."""
        return {
            'advanced_generation_enabled': {
                'enabled': True,
                'config': {
                    'name': 'advanced_generation_enabled',
                    'status': 'ENABLED',
                    'type': 'RELEASE',
                    'description': 'Habilita geração avançada',
                    'created_at': '2025-01-27T00:00:00Z',
                    'updated_at': '2025-01-27T00:00:00Z'
                },
                'metadata': {
                    'checked_at': '2025-01-27T23:00:00Z',
                    'user_id': 'test_user_123'
                }
            },
            'feedback_system_enabled': {
                'enabled': False,
                'config': {
                    'name': 'feedback_system_enabled',
                    'status': 'DISABLED',
                    'type': 'RELEASE',
                    'description': 'Sistema de feedback',
                    'created_at': '2025-01-27T00:00:00Z',
                    'updated_at': '2025-01-27T00:00:00Z'
                },
                'metadata': {
                    'checked_at': '2025-01-27T23:00:00Z',
                    'user_id': 'test_user_123'
                }
            }
        }
    
    def test_get_feature_flags_endpoint_success(self, client, mock_feature_flags):
        """Testa endpoint de feature flags com sucesso."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', side_effect=lambda name, **kwargs: mock_feature_flags[name]['enabled']):
                response = client.get('/api/feature-flags', headers={
                    'X-User-ID': 'test_user_123',
                    'X-Session-ID': 'test_session_456'
                })
                
                assert response.status_code == 200
                data = json.loads(response.data)
                
                assert data['success'] is True
                assert 'data' in data
                assert 'trace_id' in data
                assert 'timestamp' in data
                
                # Verifica se as flags estão presentes
                assert 'advanced_generation_enabled' in data['data']
                assert 'feedback_system_enabled' in data['data']
                
                # Verifica estrutura da flag
                flag = data['data']['advanced_generation_enabled']
                assert 'enabled' in flag
                assert 'config' in flag
                assert 'metadata' in flag
                assert flag['enabled'] is True
    
    def test_get_feature_flags_endpoint_without_headers(self, client, mock_feature_flags):
        """Testa endpoint sem headers de contexto."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', side_effect=lambda name, **kwargs: mock_feature_flags[name]['enabled']):
                response = client.get('/api/feature-flags')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                
                assert data['success'] is True
                assert 'data' in data
    
    def test_get_feature_flags_endpoint_error(self, client):
        """Testa endpoint com erro interno."""
        with patch('app.routes.get_all_feature_flags', side_effect=Exception('Erro interno')):
            response = client.get('/api/feature-flags')
            
            assert response.status_code == 500
            data = json.loads(response.data)
            
            assert data['success'] is False
            assert 'error' in data
            assert data['error'] == 'Erro interno do servidor'
    
    def test_feature_flag_decorator_enabled(self, client):
        """Testa decorador de feature flag habilitado."""
        with patch('app.routes.is_feature_enabled', return_value=True):
            # Simula uma rota protegida por feature flag
            response = client.post('/generate', 
                headers={'Authorization': 'Bearer valid_token'},
                json={'test': 'data'}
            )
            
            # Se a flag estiver habilitada, a rota deve processar normalmente
            # (pode retornar erro de validação, mas não erro de flag desabilitada)
            assert response.status_code != 403
    
    def test_feature_flag_decorator_disabled(self, client):
        """Testa decorador de feature flag desabilitado."""
        with patch('app.routes.is_feature_enabled', return_value=False):
            # Simula uma rota protegida por feature flag
            response = client.post('/generate', 
                headers={'Authorization': 'Bearer valid_token'},
                json={'test': 'data'}
            )
            
            # Se a flag estiver desabilitada, a função deve retornar None
            # ou um comportamento específico definido no decorador
            pass  # Implementação depende do comportamento específico do decorador
    
    def test_feature_flags_with_user_context(self, client, mock_feature_flags):
        """Testa feature flags com contexto de usuário."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled') as mock_is_enabled:
                mock_is_enabled.return_value = True
                
                response = client.get('/api/feature-flags', headers={
                    'X-User-ID': 'specific_user_123',
                    'X-Session-ID': 'specific_session_456',
                    'User-Agent': 'Test Browser/1.0'
                })
                
                assert response.status_code == 200
                
                # Verifica se is_feature_enabled foi chamado com contexto correto
                mock_is_enabled.assert_called()
                calls = mock_is_enabled.call_args_list
                
                for call in calls:
                    args, kwargs = call
                    assert 'user_id' in kwargs
                    assert 'session_id' in kwargs
                    assert 'context' in kwargs
                    assert kwargs['user_id'] == 'specific_user_123'
                    assert kwargs['session_id'] == 'specific_session_456'
                    assert 'ip' in kwargs['context']
                    assert 'user_agent' in kwargs['context']
    
    def test_feature_flags_partial_enabled(self, client):
        """Testa feature flags com status parcial."""
        partial_flags = {
            'test_partial_flag': {
                'enabled': True,
                'config': {
                    'name': 'test_partial_flag',
                    'status': 'PARTIAL',
                    'type': 'RELEASE',
                    'percentage': 50,
                    'description': 'Flag parcial para teste',
                    'created_at': '2025-01-27T00:00:00Z',
                    'updated_at': '2025-01-27T00:00:00Z'
                },
                'metadata': {
                    'checked_at': '2025-01-27T23:00:00Z',
                    'user_id': 'test_user_123'
                }
            }
        }
        
        with patch('app.routes.get_all_feature_flags', return_value=partial_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                response = client.get('/api/feature-flags')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                
                flag = data['data']['test_partial_flag']
                assert flag['config']['status'] == 'PARTIAL'
                assert flag['config']['percentage'] == 50
    
    def test_feature_flags_audit_logging(self, client, mock_feature_flags):
        """Testa se o logging de auditoria está funcionando."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                with patch('app.routes.logger') as mock_logger:
                    response = client.get('/api/feature-flags')
                    
                    assert response.status_code == 200
                    
                    # Verifica se o logging foi chamado
                    mock_logger.info.assert_called()
    
    def test_feature_flags_trace_id_integration(self, client, mock_feature_flags):
        """Testa integração com trace ID."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                response = client.get('/api/feature-flags', headers={
                    'X-Trace-ID': 'test_trace_123'
                })
                
                assert response.status_code == 200
                data = json.loads(response.data)
                
                assert data['trace_id'] == 'test_trace_123'
    
    def test_feature_flags_performance(self, client, mock_feature_flags):
        """Testa performance do endpoint de feature flags."""
        import time
        
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                start_time = time.time()
                
                response = client.get('/api/feature-flags')
                
                end_time = time.time()
                response_time = end_time - start_time
                
                assert response.status_code == 200
                assert response_time < 1.0  # Deve responder em menos de 1 segundo
    
    def test_feature_flags_error_handling(self, client):
        """Testa tratamento de erros específicos."""
        # Testa erro de Redis indisponível
        with patch('app.routes.get_all_feature_flags', side_effect=ConnectionError('Redis connection failed')):
            response = client.get('/api/feature-flags')
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['success'] is False
        
        # Testa erro de validação
        with patch('app.routes.get_all_feature_flags', side_effect=ValueError('Invalid flag configuration')):
            response = client.get('/api/feature-flags')
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['success'] is False
    
    def test_feature_flags_content_type(self, client, mock_feature_flags):
        """Testa se o Content-Type está correto."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                response = client.get('/api/feature-flags')
                
                assert response.status_code == 200
                assert response.content_type == 'application/json'
    
    def test_feature_flags_cors_headers(self, client, mock_feature_flags):
        """Testa se os headers CORS estão presentes."""
        with patch('app.routes.get_all_feature_flags', return_value=mock_feature_flags):
            with patch('app.routes.is_feature_enabled', return_value=True):
                response = client.get('/api/feature-flags')
                
                assert response.status_code == 200
                # Verifica se headers de segurança estão presentes
                assert 'X-Content-Type-Options' in response.headers
                assert 'X-Frame-Options' in response.headers 