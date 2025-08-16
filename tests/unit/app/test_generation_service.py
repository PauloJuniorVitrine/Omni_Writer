"""
Testes unitários para GenerationService - Baseados em código real

Prompt: Refatoração Enterprise+ - IMP-001
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:40:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from app.services.generation_service import (
    GenerationService, 
    GenerationRequest, 
    GenerationResult
)
from domain.models import GenerationConfig, PromptInput


class TestGenerationService:
    """Testes unitários para GenerationService"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.service = GenerationService()
        self.sample_request_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'gpt-4',
            'prompt_0': 'Como criar um blog profissional',
            'prompt_1': 'Dicas para marketing digital',
            'instancias_json': None
        }
    
    def test_generation_service_initialization(self):
        """Testa inicialização do service"""
        service = GenerationService()
        assert service is not None
        assert hasattr(service, 'logger')
    
    def test_validate_instances_with_valid_json(self):
        """Testa validação de instâncias com JSON válido"""
        valid_instances = [
            {'name': 'blog1', 'url': 'https://blog1.com'},
            {'name': 'blog2', 'url': 'https://blog2.com'}
        ]
        instances_json = json.dumps(valid_instances)
        
        instances, error = self.service._validate_instances(instances_json)
        
        assert error is None
        assert instances == valid_instances
        assert len(instances) == 2
    
    def test_validate_instances_with_invalid_json(self):
        """Testa validação de instâncias com JSON inválido"""
        invalid_json = "{invalid json}"
        
        instances, error = self.service._validate_instances(invalid_json)
        
        assert error == "JSON inválido"
        assert instances == []
    
    def test_validate_instances_with_empty_string(self):
        """Testa validação de instâncias com string vazia"""
        instances, error = self.service._validate_instances("")
        
        assert error is None
        assert instances == []
    
    def test_validate_instances_with_none(self):
        """Testa validação de instâncias com None"""
        instances, error = self.service._validate_instances(None)
        
        assert error is None
        assert instances == []
    
    def test_validate_instances_with_invalid_format(self):
        """Testa validação de instâncias com formato inválido"""
        invalid_format = json.dumps("not a list")
        
        instances, error = self.service._validate_instances(invalid_format)
        
        assert error == "Formato inválido: deve ser uma lista"
        assert instances == []
    
    def test_get_prompts_from_request_with_valid_prompts(self):
        """Testa extração de prompts válidos da requisição"""
        request_data = {
            'prompt_0': 'Como criar um blog profissional',
            'prompt_1': 'Dicas para marketing digital',
            'prompt_2': 'SEO para iniciantes'
        }
        
        prompts, error = self.service._get_prompts_from_request(request_data)
        
        assert error is None
        assert len(prompts) == 3
        assert 'Como criar um blog profissional' in prompts
        assert 'Dicas para marketing digital' in prompts
        assert 'SEO para iniciantes' in prompts
    
    def test_get_prompts_from_request_with_empty_prompts(self):
        """Testa extração de prompts vazios"""
        request_data = {
            'prompt_0': '',
            'prompt_1': '   ',
            'prompt_2': None
        }
        
        prompts, error = self.service._get_prompts_from_request(request_data)
        
        assert error == "Nenhum prompt fornecido"
        assert prompts == []
    
    def test_get_prompts_from_request_with_no_prompts(self):
        """Testa extração quando não há prompts"""
        request_data = {'api_key': 'test-key'}
        
        prompts, error = self.service._get_prompts_from_request(request_data)
        
        assert error == "Nenhum prompt fornecido"
        assert prompts == []
    
    def test_validate_request_with_valid_multi_instance(self):
        """Testa validação de requisição válida multi-instância"""
        request_data = {
            'instancias_json': json.dumps([{'name': 'blog1'}]),
            'prompt_0': 'Como criar um blog profissional'
        }
        
        result = self.service._validate_request(request_data)
        
        assert result['valid'] is True
        assert len(result['instances']) == 1
        assert len(result['prompts']) == 1
    
    def test_validate_request_with_valid_single_instance(self):
        """Testa validação de requisição válida single-instância"""
        request_data = {
            'api_key': 'valid-api-key',
            'model_type': 'gpt-4',
            'prompt_0': 'Como criar um blog profissional'
        }
        
        result = self.service._validate_request(request_data)
        
        assert result['valid'] is True
        assert result['instances'] == []
        assert len(result['prompts']) == 1
    
    def test_validate_request_with_invalid_api_key(self):
        """Testa validação com API key inválida"""
        request_data = {
            'api_key': 'invalid-key',
            'model_type': 'gpt-4',
            'prompt_0': 'Como criar um blog profissional'
        }
        
        result = self.service._validate_request(request_data)
        
        assert result['valid'] is False
        assert 'API key inválida' in result['error']
    
    def test_validate_request_with_missing_fields(self):
        """Testa validação com campos obrigatórios ausentes"""
        request_data = {
            'prompt_0': 'Como criar um blog profissional'
            # api_key e model_type ausentes
        }
        
        result = self.service._validate_request(request_data)
        
        assert result['valid'] is False
        assert 'campos_obrigatorios' in result['error']
    
    @patch('app.services.generation_service.run_generation_multi_pipeline')
    @patch('app.services.generation_service.notify_webhooks')
    @patch('os.path.exists')
    def test_generate_multi_instance_success(self, mock_exists, mock_notify, mock_pipeline):
        """Testa geração multi-instância com sucesso"""
        mock_pipeline.return_value = '/path/to/artigos.zip'
        mock_exists.return_value = True
        mock_notify.return_value = None
        
        instances = [{'name': 'blog1'}, {'name': 'blog2'}]
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_multi_instance(instances, prompts)
        
        assert result.success is True
        assert result.zip_path == '/path/to/artigos.zip'
        assert result.download_url == 'download_multi'
        mock_pipeline.assert_called_once_with(instances, prompts)
        mock_notify.assert_called_once_with({'zip_path': '/path/to/artigos.zip'})
    
    @patch('app.services.generation_service.run_generation_multi_pipeline')
    @patch('app.services.generation_service.notify_webhooks')
    @patch('os.path.exists')
    def test_generate_multi_instance_zip_not_found(self, mock_exists, mock_notify, mock_pipeline):
        """Testa geração multi-instância com ZIP não encontrado"""
        mock_pipeline.return_value = '/path/to/artigos.zip'
        mock_exists.return_value = False
        mock_notify.return_value = None
        
        instances = [{'name': 'blog1'}]
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_multi_instance(instances, prompts)
        
        assert result.success is False
        assert 'Arquivo ZIP não gerado' in result.error_message
    
    @patch('app.services.generation_service.run_generation_multi_pipeline')
    def test_generate_multi_instance_exception(self, mock_pipeline):
        """Testa geração multi-instância com exceção"""
        mock_pipeline.side_effect = Exception("Pipeline error")
        
        instances = [{'name': 'blog1'}]
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_multi_instance(instances, prompts)
        
        assert result.success is False
        assert 'Pipeline error' in result.error_message
    
    @patch('app.services.generation_service.run_generation_pipeline')
    @patch('app.services.generation_service.notify_webhooks')
    @patch('os.path.exists')
    def test_generate_single_instance_success(self, mock_exists, mock_notify, mock_pipeline):
        """Testa geração single-instância com sucesso"""
        mock_pipeline.return_value = '/path/to/artigos.zip'
        mock_exists.return_value = True
        mock_notify.return_value = None
        
        api_key = 'test-api-key'
        model_type = 'gpt-4'
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_single_instance(api_key, model_type, prompts)
        
        assert result.success is True
        assert result.zip_path == '/path/to/artigos.zip'
        assert result.download_url == 'download'
        mock_pipeline.assert_called_once()
        mock_notify.assert_called_once_with({'zip_path': '/path/to/artigos.zip'})
    
    @patch('app.services.generation_service.run_generation_pipeline')
    @patch('app.services.generation_service.notify_webhooks')
    @patch('os.path.exists')
    def test_generate_single_instance_zip_not_found(self, mock_exists, mock_notify, mock_pipeline):
        """Testa geração single-instância com ZIP não encontrado"""
        mock_pipeline.return_value = '/path/to/artigos.zip'
        mock_exists.return_value = False
        mock_notify.return_value = None
        
        api_key = 'test-api-key'
        model_type = 'gpt-4'
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_single_instance(api_key, model_type, prompts)
        
        assert result.success is False
        assert 'Arquivo ZIP não gerado' in result.error_message
    
    @patch('app.services.generation_service.run_generation_pipeline')
    def test_generate_single_instance_exception(self, mock_pipeline):
        """Testa geração single-instância com exceção"""
        mock_pipeline.side_effect = Exception("Pipeline error")
        
        api_key = 'test-api-key'
        model_type = 'gpt-4'
        prompts = ['Como criar um blog profissional']
        
        result = self.service._generate_single_instance(api_key, model_type, prompts)
        
        assert result.success is False
        assert 'Pipeline error' in result.error_message
    
    @patch.object(GenerationService, '_validate_request')
    @patch.object(GenerationService, '_generate_multi_instance')
    def test_generate_articles_multi_instance_success(self, mock_multi, mock_validate):
        """Testa geração de artigos multi-instância com sucesso"""
        mock_validate.return_value = {
            'valid': True,
            'instances': [{'name': 'blog1'}],
            'prompts': ['Como criar um blog profissional']
        }
        mock_multi.return_value = GenerationResult(
            success=True,
            zip_path='/path/to/artigos.zip',
            download_url='download_multi'
        )
        
        result = self.service.generate_articles(self.sample_request_data)
        
        assert result.success is True
        assert result.zip_path == '/path/to/artigos.zip'
        assert result.download_url == 'download_multi'
        mock_validate.assert_called_once_with(self.sample_request_data)
        mock_multi.assert_called_once()
    
    @patch.object(GenerationService, '_validate_request')
    @patch.object(GenerationService, '_generate_single_instance')
    def test_generate_articles_single_instance_success(self, mock_single, mock_validate):
        """Testa geração de artigos single-instância com sucesso"""
        mock_validate.return_value = {
            'valid': True,
            'instances': [],
            'prompts': ['Como criar um blog profissional']
        }
        mock_single.return_value = GenerationResult(
            success=True,
            zip_path='/path/to/artigos.zip',
            download_url='download'
        )
        
        result = self.service.generate_articles(self.sample_request_data)
        
        assert result.success is True
        assert result.zip_path == '/path/to/artigos.zip'
        assert result.download_url == 'download'
        mock_validate.assert_called_once_with(self.sample_request_data)
        mock_single.assert_called_once()
    
    @patch.object(GenerationService, '_validate_request')
    def test_generate_articles_validation_failure(self, mock_validate):
        """Testa geração de artigos com falha na validação"""
        mock_validate.return_value = {
            'valid': False,
            'error': 'Erro de validação'
        }
        
        result = self.service.generate_articles(self.sample_request_data)
        
        assert result.success is False
        assert result.error_message == 'Erro de validação'
        mock_validate.assert_called_once_with(self.sample_request_data)
    
    def test_generate_articles_exception_handling(self):
        """Testa tratamento de exceção na geração de artigos"""
        # Simula exceção no service
        with patch.object(self.service, '_validate_request', side_effect=Exception("Service error")):
            result = self.service.generate_articles(self.sample_request_data)
            
            assert result.success is False
            assert 'Service error' in result.error_message


class TestGenerationRequest:
    """Testes para dataclass GenerationRequest"""
    
    def test_generation_request_creation(self):
        """Testa criação de GenerationRequest"""
        request = GenerationRequest(
            api_key='test-key',
            model_type='gpt-4',
            prompts=['Como criar um blog profissional'],
            instances_json='[{"name": "blog1"}]'
        )
        
        assert request.api_key == 'test-key'
        assert request.model_type == 'gpt-4'
        assert len(request.prompts) == 1
        assert request.instances_json == '[{"name": "blog1"}]'
    
    def test_generation_request_without_instances(self):
        """Testa criação de GenerationRequest sem instâncias"""
        request = GenerationRequest(
            api_key='test-key',
            model_type='gpt-4',
            prompts=['Como criar um blog profissional']
        )
        
        assert request.instances_json is None


class TestGenerationResult:
    """Testes para dataclass GenerationResult"""
    
    def test_generation_result_success(self):
        """Testa criação de GenerationResult de sucesso"""
        result = GenerationResult(
            success=True,
            zip_path='/path/to/artigos.zip',
            download_url='download'
        )
        
        assert result.success is True
        assert result.zip_path == '/path/to/artigos.zip'
        assert result.download_url == 'download'
        assert result.error_message is None
    
    def test_generation_result_failure(self):
        """Testa criação de GenerationResult de falha"""
        result = GenerationResult(
            success=False,
            error_message='Erro na geração'
        )
        
        assert result.success is False
        assert result.error_message == 'Erro na geração'
        assert result.zip_path is None
        assert result.download_url is None 