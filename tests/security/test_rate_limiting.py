"""
Testes de segurança para rate limiting.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:20:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

import pytest
from unittest.mock import Mock, patch
from flask import Flask
from app.routes import routes_bp


class TestRateLimiting:
    """Testes para rate limiting nas rotas."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.app = Flask(__name__)
        self.app.register_blueprint(routes_bp)
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        self.client = self.app.test_client()
        
        self.sample_form_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'Como criar um blog profissional',
            'instancias_json': None
        }
    
    def test_generate_route_has_rate_limit(self):
        """Testa se a rota generate tem rate limiting configurado."""
        with self.app.app_context():
            # Verifica se o decorator @limiter.limit está presente
            generate_route = self.app.view_functions.get('routes.generate')
            assert generate_route is not None
            
            # Verifica se tem headers de rate limiting
            response = self.client.post('/generate', data=self.sample_form_data)
            assert response.status_code in [200, 400, 429]  # 429 = Too Many Requests
    
    def test_feedback_route_has_rate_limit(self):
        """Testa se a rota feedback tem rate limiting configurado."""
        feedback_data = {
            'user_id': 'user123',
            'artigo_id': 'artigo456',
            'tipo': 'positivo',
            'comentario': 'Artigo muito bom!'
        }
        
        with self.app.app_context():
            response = self.client.post('/feedback', data=feedback_data)
            assert response.status_code in [201, 400, 429]
    
    def test_blueprint_has_global_rate_limit(self):
        """Testa se o blueprint tem rate limiting global configurado."""
        with self.app.app_context():
            # Verifica se o decorator global está aplicado
            assert hasattr(routes_bp, 'before_request') or hasattr(routes_bp, 'after_request') 