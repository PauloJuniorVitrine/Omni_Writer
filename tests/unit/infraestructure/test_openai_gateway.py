"""
Testes unitários para OpenAI Gateway
Prompt: tests
Ruleset: geral_rules_melhorado.yaml
Data/Hora: 2025-01-27T18:30:00Z
Tracing ID: TEST_OPENAI_GATEWAY_001
"""
import pytest
import os
import requests
from unittest.mock import Mock, patch, MagicMock
from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from infraestructure.openai_gateway import generate_article_openai
from shared.config import OPENAI_API_URL


class TestOpenAIGateway:
    """Testes para o gateway OpenAI com cobertura completa de cenários."""

    @pytest.fixture
    def mock_config(self):
        """Fixture para configuração de teste."""
        return GenerationConfig(
            api_key="test_api_key_12345",
            model_type="openai",
            prompts=[PromptInput(text="Escreva um artigo sobre inteligência artificial", index=1)],
            temperature=0.7,
            max_tokens=4000,
            language="pt-BR"
        )

    @pytest.fixture
    def mock_prompt(self):
        """Fixture para prompt de teste."""
        return PromptInput(
            text="Escreva um artigo sobre inteligência artificial",
            index=1
        )

    @pytest.fixture
    def mock_success_response(self):
        """Fixture para resposta de sucesso da API."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'choices': [{
                'message': {
                    'content': 'Artigo gerado com sucesso sobre IA.'
                }
            }]
        }
        mock_response.raise_for_status.return_value = None
        return mock_response

    def test_generate_article_success(self, mock_config, mock_prompt, mock_success_response):
        """Testa geração de artigo com sucesso."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                result = generate_article_openai(mock_config, mock_prompt, "trace_123")

                # Verifica se a requisição foi feita corretamente
                mock_post.assert_called_once()
                call_args = mock_post.call_args
                
                # Verifica URL
                assert call_args[0][0] == OPENAI_API_URL
                
                # Verifica headers
                headers = call_args[1]['headers']
                assert headers['Authorization'] == 'Bearer test_api_key_12345'
                assert headers['Content-Type'] == 'application/json'
                
                # Verifica payload
                data = call_args[1]['json']
                assert data['model'] == 'gpt-4o'
                assert data['temperature'] == 0.7
                assert data['max_tokens'] == 4000
                assert len(data['messages']) == 2
                assert data['messages'][0]['role'] == 'system'
                assert 'pt-BR' in data['messages'][0]['content']
                assert data['messages'][1]['role'] == 'user'
                assert data['messages'][1]['content'] == mock_prompt.text

                # Verifica resultado
                assert isinstance(result, ArticleOutput)
                assert result.content == 'Artigo gerado com sucesso sobre IA.'
                assert result.filename == 'artigo_2_v1.txt'

                # Verifica log de sucesso
                mock_logger.info.assert_called_once()
                log_call = mock_logger.info.call_args
                assert log_call[1]['extra']['event'] == 'openai_generation'
                assert log_call[1]['extra']['status'] == 'success'
                assert log_call[1]['extra']['trace_id'] == 'trace_123'

    def test_generate_article_with_variation(self, mock_config, mock_prompt, mock_success_response):
        """Testa geração de artigo com variação."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                result = generate_article_openai(mock_config, mock_prompt, "trace_456", variation=2)

                # Verifica se a variação foi incluída no prompt
                call_args = mock_post.call_args
                data = call_args[1]['json']
                system_message = data['messages'][0]['content']
                assert 'Variação 3:' in system_message
                assert 'versão diferente' in system_message

                # Verifica nome do arquivo com variação
                assert result.filename == 'artigo_2_v3.txt'

    def test_generate_article_api_error(self, mock_config, mock_prompt):
        """Testa tratamento de erro da API."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("API Error")
        
        with patch('requests.post', return_value=mock_response) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.HTTPError):
                    generate_article_openai(mock_config, mock_prompt, "trace_789")

                # Verifica log de erro
                mock_logger.error.assert_called_once()
                log_call = mock_logger.error.call_args
                assert log_call[1]['extra']['event'] == 'openai_generation'
                assert log_call[1]['extra']['status'] == 'error'
                assert log_call[1]['extra']['trace_id'] == 'trace_789'

    def test_generate_article_network_error(self, mock_config, mock_prompt):
        """Testa tratamento de erro de rede."""
        with patch('requests.post', side_effect=requests.exceptions.ConnectionError("Network Error")) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.ConnectionError):
                    generate_article_openai(mock_config, mock_prompt, "trace_network")

                # Verifica log de erro
                mock_logger.error.assert_called_once()
                log_call = mock_logger.error.call_args
                assert log_call[1]['extra']['status'] == 'error'

    def test_generate_article_timeout_error(self, mock_config, mock_prompt):
        """Testa tratamento de timeout."""
        with patch('requests.post', side_effect=requests.exceptions.Timeout("Timeout Error")) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.Timeout):
                    generate_article_openai(mock_config, mock_prompt, "trace_timeout")

                # Verifica log de erro
                mock_logger.error.assert_called_once()

    def test_generate_article_invalid_response_format(self, mock_config, mock_prompt):
        """Testa tratamento de resposta inválida da API."""
        mock_response = Mock()
        mock_response.json.return_value = {'invalid': 'format'}
        mock_response.raise_for_status.return_value = None
        
        with patch('requests.post', return_value=mock_response) as mock_post:
            with patch('infraestructure.openai_gateway.logger') as mock_logger:
                with pytest.raises(KeyError):
                    generate_article_openai(mock_config, mock_prompt, "trace_invalid")

                # Verifica log de erro
                mock_logger.error.assert_called_once()

    @pytest.mark.parametrize("temperature,expected_temp", [
        (0.0, 0.0),
        (0.5, 0.5),
        (1.0, 1.0),
        (0.7, 0.7)
    ])
    def test_generate_article_temperature_variations(self, mock_prompt, mock_success_response, temperature, expected_temp):
        """Testa diferentes valores de temperatura."""
        config = GenerationConfig(
            api_key="test_key",
            model_type="openai",
            prompts=[mock_prompt],
            temperature=temperature,
            max_tokens=4000,
            language="pt-BR"
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_openai(config, mock_prompt, "trace_temp")
            
            call_args = mock_post.call_args
            data = call_args[1]['json']
            assert data['temperature'] == expected_temp

    @pytest.mark.parametrize("max_tokens,expected_tokens", [
        (1000, 1000),
        (2000, 2000),
        (4000, 4000),
        (8000, 8000)
    ])
    def test_generate_article_max_tokens_variations(self, mock_prompt, mock_success_response, max_tokens, expected_tokens):
        """Testa diferentes valores de max_tokens."""
        config = GenerationConfig(
            api_key="test_key",
            model_type="openai",
            prompts=[mock_prompt],
            temperature=0.7,
            max_tokens=max_tokens,
            language="pt-BR"
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_openai(config, mock_prompt, "trace_tokens")
            
            call_args = mock_post.call_args
            data = call_args[1]['json']
            assert data['max_tokens'] == expected_tokens

    @pytest.mark.parametrize("language,expected_lang", [
        ("pt-BR", "pt-BR"),
        ("en-US", "en-US"),
        ("es-ES", "es-ES"),
        ("fr-FR", "fr-FR")
    ])
    def test_generate_article_language_variations(self, mock_prompt, mock_success_response, language, expected_lang):
        """Testa diferentes idiomas."""
        config = GenerationConfig(
            api_key="test_key",
            model_type="openai",
            prompts=[mock_prompt],
            temperature=0.7,
            max_tokens=4000,
            language=language
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_openai(config, mock_prompt, "trace_lang")
            
            call_args = mock_post.call_args
            data = call_args[1]['json']
            system_message = data['messages'][0]['content']
            assert expected_lang in system_message

    def test_generate_article_mock_mode(self, mock_config, mock_prompt):
        """Testa modo mock para ambiente de teste."""
        original_testing = os.environ.get('TESTING', '0')
        os.environ['TESTING'] = '1'
        
        try:
            result = generate_article_openai(mock_config, mock_prompt, "trace_mock")
            
            assert isinstance(result, ArticleOutput)
            assert result.content == 'Artigo gerado de teste.'
            assert result.filename == 'artigo_2_v1.txt'
        finally:
            os.environ['TESTING'] = original_testing

    def test_generate_article_mock_mode_with_variation(self, mock_config, mock_prompt):
        """Testa modo mock com variação."""
        original_testing = os.environ.get('TESTING', '0')
        os.environ['TESTING'] = '1'
        
        try:
            result = generate_article_openai(mock_config, mock_prompt, "trace_mock_var", variation=3)
            
            assert isinstance(result, ArticleOutput)
            assert result.content == 'Artigo gerado de teste.'
            assert result.filename == 'artigo_2_v4.txt'
        finally:
            os.environ['TESTING'] = original_testing

    def test_generate_article_circuit_breaker_integration(self, mock_config, mock_prompt):
        """Testa integração com circuit breaker."""
        with patch('infraestructure.openai_gateway.circuit_breaker') as mock_cb:
            mock_cb.return_value = lambda func: func
            
            with patch('requests.post', return_value=Mock()) as mock_post:
                generate_article_openai(mock_config, mock_prompt, "trace_cb")
                
                # Verifica se circuit breaker foi chamado
                mock_cb.assert_called_once_with('ai_providers')

    def test_generate_article_empty_prompt(self, mock_config):
        """Testa comportamento com prompt vazio."""
        empty_prompt = PromptInput(text="", index=0)
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {
                'choices': [{'message': {'content': 'Artigo vazio.'}}]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            result = generate_article_openai(mock_config, empty_prompt, "trace_empty")
            
            assert result.content == 'Artigo vazio.'
            assert result.filename == 'artigo_1_v1.txt'

    def test_generate_article_special_characters_prompt(self, mock_config):
        """Testa comportamento com caracteres especiais no prompt."""
        special_prompt = PromptInput(text="Artigo com ç, ã, é, ñ, 中文, 🚀", index=5)
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {
                'choices': [{'message': {'content': 'Artigo com caracteres especiais.'}}]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            result = generate_article_openai(mock_config, special_prompt, "trace_special")
            
            assert result.content == 'Artigo com caracteres especiais.'
            assert result.filename == 'artigo_6_v1.txt' 