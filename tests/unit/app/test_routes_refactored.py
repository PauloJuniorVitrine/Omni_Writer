"""
Testes unitários para rotas refatoradas - Baseados em código real

Prompt: Refatoração Enterprise+ - IMP-001
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:40:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from flask import Flask
from app.routes import routes_bp, GenerateForm
from app.services.generation_service import GenerationResult


class TestRoutesRefactored:
    """Testes unitários para rotas refatoradas"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.app = Flask(__name__)
        self.app.register_blueprint(routes_bp)
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        self.client = self.app.test_client()
        
        self.sample_form_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'gpt-4',
            'prompt_0': 'Como criar um blog profissional',
            'prompt_1': 'Dicas para marketing digital',
            'instancias_json': None
        }
    
    def test_generate_form_validation_success(self):
        """Testa validação bem-sucedida do formulário"""
        with self.app.app_context():
            form = GenerateForm(data=self.sample_form_data)
            assert form.validate() is True
            assert form.api_key.data == 'test-api-key-123456789'
            assert form.model_type.data == 'gpt-4'
    
    def test_generate_form_validation_failure_missing_api_key(self):
        """Testa falha na validação do formulário sem API key"""
        invalid_data = self.sample_form_data.copy()
        del invalid_data['api_key']
        
        with self.app.app_context():
            form = GenerateForm(data=invalid_data)
            assert form.validate() is False
            assert 'api_key' in form.errors
    
    def test_generate_form_validation_failure_short_api_key(self):
        """Testa falha na validação do formulário com API key muito curta"""
        invalid_data = self.sample_form_data.copy()
        invalid_data['api_key'] = 'short'
        
        with self.app.app_context():
            form = GenerateForm(data=invalid_data)
            assert form.validate() is False
            assert 'api_key' in form.errors
    
    def test_generate_form_validation_failure_missing_model_type(self):
        """Testa falha na validação do formulário sem model_type"""
        invalid_data = self.sample_form_data.copy()
        del invalid_data['model_type']
        
        with self.app.app_context():
            form = GenerateForm(data=invalid_data)
            assert form.validate() is False
            assert 'model_type' in form.errors
    
    @patch('app.routes.GenerationService')
    def test_generate_route_success_multi_instance(self, mock_service_class):
        """Testa rota generate com sucesso multi-instância"""
        # Mock do service
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        
        # Mock do resultado de sucesso
        mock_result = GenerationResult(
            success=True,
            zip_path='/path/to/artigos.zip',
            download_url='download_multi'
        )
        mock_service.generate_articles.return_value = mock_result
        
        # Mock do formulário válido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = True
            mock_form_class.return_value = mock_form
            
            # Mock do url_for
            with patch('app.routes.url_for') as mock_url_for:
                mock_url_for.return_value = '/download_multi'
                
                # Mock do render_template
                with patch('app.routes.render_template') as mock_render:
                    mock_render.return_value = 'success template'
                    
                    # Execução da rota
                    with self.app.app_context():
                        response = self.client.post('/generate', data=self.sample_form_data)
                        
                        # Verificações
                        assert response.status_code == 200
                        mock_service.generate_articles.assert_called_once_with(self.sample_form_data)
                        mock_render.assert_called_once()
                        call_args = mock_render.call_args
                        assert 'download_link' in call_args[1]
    
    @patch('app.routes.GenerationService')
    def test_generate_route_success_single_instance(self, mock_service_class):
        """Testa rota generate com sucesso single-instância"""
        # Mock do service
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        
        # Mock do resultado de sucesso
        mock_result = GenerationResult(
            success=True,
            zip_path='/path/to/artigos.zip',
            download_url='download'
        )
        mock_service.generate_articles.return_value = mock_result
        
        # Mock do formulário válido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = True
            mock_form_class.return_value = mock_form
            
            # Mock do url_for
            with patch('app.routes.url_for') as mock_url_for:
                mock_url_for.return_value = '/download'
                
                # Mock do render_template
                with patch('app.routes.render_template') as mock_render:
                    mock_render.return_value = 'success template'
                    
                    # Execução da rota
                    with self.app.app_context():
                        response = self.client.post('/generate', data=self.sample_form_data)
                        
                        # Verificações
                        assert response.status_code == 200
                        mock_service.generate_articles.assert_called_once_with(self.sample_form_data)
                        mock_render.assert_called_once()
                        call_args = mock_render.call_args
                        assert 'download_link' in call_args[1]
    
    @patch('app.routes.GenerationService')
    def test_generate_route_service_failure(self, mock_service_class):
        """Testa rota generate com falha no service"""
        # Mock do service
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        
        # Mock do resultado de falha
        mock_result = GenerationResult(
            success=False,
            error_message='Erro na geração de artigos'
        )
        mock_service.generate_articles.return_value = mock_result
        
        # Mock do formulário válido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = True
            mock_form_class.return_value = mock_form
            
            # Mock do flash
            with patch('app.routes.flash') as mock_flash:
                # Mock do render_template
                with patch('app.routes.render_template') as mock_render:
                    mock_render.return_value = 'error template'
                    
                    # Execução da rota
                    with self.app.app_context():
                        response = self.client.post('/generate', data=self.sample_form_data)
                        
                        # Verificações
                        assert response.status_code == 200
                        mock_service.generate_articles.assert_called_once_with(self.sample_form_data)
                        mock_flash.assert_called_once_with('Erro na geração de artigos', 'error')
                        mock_render.assert_called_once()
    
    def test_generate_route_form_validation_failure(self):
        """Testa rota generate com falha na validação do formulário"""
        # Mock do formulário inválido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = False
            mock_form_class.return_value = mock_form
            
            # Mock do render_template
            with patch('app.routes.render_template') as mock_render:
                mock_render.return_value = 'error template'
                
                # Execução da rota
                with self.app.app_context():
                    response = self.client.post('/generate', data=self.sample_form_data)
                    
                    # Verificações
                    assert response.status_code == 200
                    mock_render.assert_called_once()
                    call_args = mock_render.call_args
                    assert 'error' in call_args[1]
    
    def test_generate_route_form_validation_failure_json_request(self):
        """Testa rota generate com falha na validação do formulário para requisição JSON"""
        # Mock do formulário inválido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = False
            mock_form_class.return_value = mock_form
            
            # Execução da rota com headers JSON
            with self.app.app_context():
                response = self.client.post(
                    '/generate', 
                    data=self.sample_form_data,
                    headers={'Content-Type': 'application/json'}
                )
                
                # Verificações
                assert response.status_code == 400
                assert b'dados invalidos' in response.data
    
    def test_generate_route_form_validation_failure_ajax_request(self):
        """Testa rota generate com falha na validação do formulário para requisição AJAX"""
        # Mock do formulário inválido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = False
            mock_form_class.return_value = mock_form
            
            # Execução da rota com headers AJAX
            with self.app.app_context():
                response = self.client.post(
                    '/generate', 
                    data=self.sample_form_data,
                    headers={'X-Requested-With': 'XMLHttpRequest'}
                )
                
                # Verificações
                assert response.status_code == 400
                assert b'dados invalidos' in response.data
    
    def test_generate_route_form_validation_failure_pytest_request(self):
        """Testa rota generate com falha na validação do formulário para requisição pytest"""
        # Mock do formulário inválido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = False
            mock_form_class.return_value = mock_form
            
            # Execução da rota com User-Agent pytest
            with self.app.app_context():
                response = self.client.post(
                    '/generate', 
                    data=self.sample_form_data,
                    headers={'User-Agent': 'pytest/7.0.0'}
                )
                
                # Verificações
                assert response.status_code == 400
                assert b'dados invalidos' in response.data
    
    @patch('app.routes.GenerationService')
    def test_generate_route_exception_handling(self, mock_service_class):
        """Testa tratamento de exceção na rota generate"""
        # Mock do service que lança exceção
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.generate_articles.side_effect = Exception("Service error")
        
        # Mock do formulário válido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = True
            mock_form_class.return_value = mock_form
            
            # Mock do flash
            with patch('app.routes.flash') as mock_flash:
                # Mock do render_template
                with patch('app.routes.render_template') as mock_render:
                    mock_render.return_value = 'error template'
                    
                    # Execução da rota
                    with self.app.app_context():
                        response = self.client.post('/generate', data=self.sample_form_data)
                        
                        # Verificações
                        assert response.status_code == 200
                        mock_flash.assert_called_once()
                        mock_render.assert_called_once()
    
    def test_generate_route_with_multi_instance_data(self):
        """Testa rota generate com dados multi-instância"""
        multi_instance_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'gpt-4',
            'prompt_0': 'Como criar um blog profissional',
            'instancias_json': json.dumps([
                {'name': 'blog1', 'url': 'https://blog1.com'},
                {'name': 'blog2', 'url': 'https://blog2.com'}
            ])
        }
        
        # Mock do service
        with patch('app.routes.GenerationService') as mock_service_class:
            mock_service = Mock()
            mock_service_class.return_value = mock_service
            
            mock_result = GenerationResult(
                success=True,
                zip_path='/path/to/artigos.zip',
                download_url='download_multi'
            )
            mock_service.generate_articles.return_value = mock_result
            
            # Mock do formulário válido
            with patch('app.routes.GenerateForm') as mock_form_class:
                mock_form = Mock()
                mock_form.validate.return_value = True
                mock_form_class.return_value = mock_form
                
                # Mock do url_for
                with patch('app.routes.url_for') as mock_url_for:
                    mock_url_for.return_value = '/download_multi'
                    
                    # Mock do render_template
                    with patch('app.routes.render_template') as mock_render:
                        mock_render.return_value = 'success template'
                        
                        # Execução da rota
                        with self.app.app_context():
                            response = self.client.post('/generate', data=multi_instance_data)
                            
                            # Verificações
                            assert response.status_code == 200
                            mock_service.generate_articles.assert_called_once_with(multi_instance_data)
                            mock_render.assert_called_once()
                            call_args = mock_render.call_args
                            assert 'download_link' in call_args[1]
    
    def test_generate_route_diagnostic_logging(self):
        """Testa logging de diagnóstico na rota generate"""
        # Mock do formulário válido
        with patch('app.routes.GenerateForm') as mock_form_class:
            mock_form = Mock()
            mock_form.validate.return_value = True
            mock_form_class.return_value = mock_form
            
            # Mock do service
            with patch('app.routes.GenerationService') as mock_service_class:
                mock_service = Mock()
                mock_service_class.return_value = mock_service
                
                mock_result = GenerationResult(
                    success=True,
                    zip_path='/path/to/artigos.zip',
                    download_url='download'
                )
                mock_service.generate_articles.return_value = mock_result
                
                # Mock do url_for
                with patch('app.routes.url_for') as mock_url_for:
                    mock_url_for.return_value = '/download'
                    
                    # Mock do render_template
                    with patch('app.routes.render_template') as mock_render:
                        mock_render.return_value = 'success template'
                        
                        # Mock do arquivo de diagnóstico
                        with patch('builtins.open', create=True) as mock_open:
                            mock_file = Mock()
                            mock_open.return_value.__enter__.return_value = mock_file
                            
                            # Execução da rota
                            with self.app.app_context():
                                response = self.client.post('/generate', data=self.sample_form_data)
                                
                                # Verificações
                                assert response.status_code == 200
                                mock_open.assert_called()
                                mock_file.write.assert_called()
                                # Verifica se o log contém informações de diagnóstico
                                write_calls = mock_file.write.call_args_list
                                assert any('INICIO REFATORADO' in str(call) for call in write_calls)
                                assert any('SERVICE RESULT' in str(call) for call in write_calls) 