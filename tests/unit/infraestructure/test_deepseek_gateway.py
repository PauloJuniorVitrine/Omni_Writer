"""
Testes unitários para DeepSeek Gateway
Prompt: tests
Ruleset: geral_rules_melhorado.yaml
Data/Hora: 2025-01-27T18:35:00Z
Tracing ID: TEST_DEEPSEEK_GATEWAY_001
"""
import pytest
import requests
from unittest.mock import Mock, patch
from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from infraestructure.deepseek_gateway import generate_article_deepseek
from shared.config import DEEPSEEK_API_URL


class TestDeepSeekGateway:
    """Testes para o gateway DeepSeek com cobertura completa de cenários."""

    @pytest.fixture
    def mock_config(self):
        """Fixture para configuração de teste."""
        return GenerationConfig(
            api_key="test_deepseek_key_12345",
            model_type="deepseek",
            prompts=[PromptInput(text="Escreva um artigo sobre machine learning", index=2)],
            temperature=0.8,
            max_tokens=4000,
            language="pt-BR"
        )

    @pytest.fixture
    def mock_prompt(self):
        """Fixture para prompt de teste."""
        return PromptInput(
            text="Escreva um artigo sobre machine learning",
            index=2
        )

    @pytest.fixture
    def mock_success_response(self):
        """Fixture para resposta de sucesso da API."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'choices': [{
                'message': {
                    'content': 'Artigo sobre machine learning gerado com sucesso.'
                }
            }]
        }
        mock_response.raise_for_status.return_value = None
        return mock_response

    def test_generate_article_success(self, mock_config, mock_prompt, mock_success_response):
        """Testa geração de artigo com sucesso."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                result = generate_article_deepseek(mock_config, mock_prompt, "trace_123")

                # Verifica se a requisição foi feita corretamente
                mock_post.assert_called_once()
                call_args = mock_post.call_args
                
                # Verifica URL
                assert call_args[0][0] == DEEPSEEK_API_URL
                
                # Verifica headers
                headers = call_args[1]['headers']
                assert headers['Authorization'] == 'Bearer test_deepseek_key_12345'
                assert headers['Content-Type'] == 'application/json'
                
                # Verifica payload
                data = call_args[1]['json']
                assert data['model'] == 'deepseek-chat-v2'
                assert data['temperature'] == 0.8
                assert data['max_tokens'] == 4000
                assert len(data['messages']) == 2
                assert data['messages'][0]['role'] == 'system'
                assert 'pt-BR' in data['messages'][0]['content']
                assert data['messages'][1]['role'] == 'user'
                assert data['messages'][1]['content'] == mock_prompt.text

                # Verifica resultado
                assert isinstance(result, ArticleOutput)
                assert result.content == 'Artigo sobre machine learning gerado com sucesso.'
                assert result.filename == 'artigo_3_v1.txt'

                # Verifica log de sucesso
                mock_logger.info.assert_called_once()
                log_call = mock_logger.info.call_args
                assert log_call[1]['extra']['event'] == 'deepseek_generation'
                assert log_call[1]['extra']['status'] == 'success'
                assert log_call[1]['extra']['source'] == 'deepseek_gateway'
                assert log_call[1]['extra']['trace_id'] == 'trace_123'

    def test_generate_article_with_variation(self, mock_config, mock_prompt, mock_success_response):
        """Testa geração de artigo com variação."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                result = generate_article_deepseek(mock_config, mock_prompt, "trace_456", variation=3)

                # Verifica se a variação foi incluída no prompt
                call_args = mock_post.call_args
                data = call_args[1]['json']
                system_message = data['messages'][0]['content']
                assert 'Variação 4:' in system_message
                assert 'versão diferente' in system_message

                # Verifica nome do arquivo com variação
                assert result.filename == 'artigo_3_v4.txt'

    def test_generate_article_api_error(self, mock_config, mock_prompt):
        """Testa tratamento de erro da API."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("DeepSeek API Error")
        
        with patch('requests.post', return_value=mock_response) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.HTTPError):
                    generate_article_deepseek(mock_config, mock_prompt, "trace_789")

                # Verifica log de erro
                mock_logger.error.assert_called_once()
                log_call = mock_logger.error.call_args
                assert log_call[1]['extra']['event'] == 'deepseek_generation'
                assert log_call[1]['extra']['status'] == 'error'
                assert log_call[1]['extra']['source'] == 'deepseek_gateway'
                assert log_call[1]['extra']['trace_id'] == 'trace_789'

    def test_generate_article_network_error(self, mock_config, mock_prompt):
        """Testa tratamento de erro de rede."""
        with patch('requests.post', side_effect=requests.exceptions.ConnectionError("Network Error")) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.ConnectionError):
                    generate_article_deepseek(mock_config, mock_prompt, "trace_network")

                # Verifica log de erro
                mock_logger.error.assert_called_once()
                log_call = mock_logger.error.call_args
                assert log_call[1]['extra']['status'] == 'error'

    def test_generate_article_timeout_error(self, mock_config, mock_prompt):
        """Testa tratamento de timeout."""
        with patch('requests.post', side_effect=requests.exceptions.Timeout("Timeout Error")) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                with pytest.raises(requests.exceptions.Timeout):
                    generate_article_deepseek(mock_config, mock_prompt, "trace_timeout")

                # Verifica log de erro
                mock_logger.error.assert_called_once()

    def test_generate_article_invalid_response_format(self, mock_config, mock_prompt):
        """Testa tratamento de resposta inválida da API."""
        mock_response = Mock()
        mock_response.json.return_value = {'invalid': 'format'}
        mock_response.raise_for_status.return_value = None
        
        with patch('requests.post', return_value=mock_response) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                with pytest.raises(KeyError):
                    generate_article_deepseek(mock_config, mock_prompt, "trace_invalid")

                # Verifica log de erro
                mock_logger.error.assert_called_once()

    @pytest.mark.parametrize("temperature,expected_temp", [
        (0.0, 0.0),
        (0.3, 0.3),
        (0.8, 0.8),
        (1.0, 1.0)
    ])
    def test_generate_article_temperature_variations(self, mock_prompt, mock_success_response, temperature, expected_temp):
        """Testa diferentes valores de temperatura."""
        config = GenerationConfig(
            api_key="test_key",
            model_type="deepseek",
            prompts=[mock_prompt],
            temperature=temperature,
            max_tokens=4000,
            language="pt-BR"
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_deepseek(config, mock_prompt, "trace_temp")
            
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
            model_type="deepseek",
            prompts=[mock_prompt],
            temperature=0.8,
            max_tokens=max_tokens,
            language="pt-BR"
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_deepseek(config, mock_prompt, "trace_tokens")
            
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
            model_type="deepseek",
            prompts=[mock_prompt],
            temperature=0.8,
            max_tokens=4000,
            language=language
        )
        
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_deepseek(config, mock_prompt, "trace_lang")
            
            call_args = mock_post.call_args
            data = call_args[1]['json']
            system_message = data['messages'][0]['content']
            assert expected_lang in system_message

    def test_generate_article_circuit_breaker_integration(self, mock_config, mock_prompt):
        """Testa integração com circuit breaker."""
        with patch('infraestructure.deepseek_gateway.circuit_breaker') as mock_cb:
            mock_cb.return_value = lambda func: func
            
            with patch('requests.post', return_value=Mock()) as mock_post:
                generate_article_deepseek(mock_config, mock_prompt, "trace_cb")
                
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
            
            result = generate_article_deepseek(mock_config, empty_prompt, "trace_empty")
            
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
            
            result = generate_article_deepseek(mock_config, special_prompt, "trace_special")
            
            assert result.content == 'Artigo com caracteres especiais.'
            assert result.filename == 'artigo_6_v1.txt'

    def test_generate_article_no_variation_instruction(self, mock_config, mock_prompt, mock_success_response):
        """Testa que não há instrução de variação quando variation=0."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            result = generate_article_deepseek(mock_config, mock_prompt, "trace_no_var", variation=0)
            
            call_args = mock_post.call_args
            data = call_args[1]['json']
            system_message = data['messages'][0]['content']
            
            # Verifica que não há instrução de variação
            assert 'Variação' not in system_message
            assert 'versão diferente' not in system_message

    def test_generate_article_multiple_variations(self, mock_config, mock_prompt, mock_success_response):
        """Testa múltiplas variações sequenciais."""
        variations = [1, 5, 10]
        
        for variation in variations:
            with patch('requests.post', return_value=mock_success_response) as mock_post:
                result = generate_article_deepseek(mock_config, mock_prompt, f"trace_var_{variation}", variation=variation)
                
                call_args = mock_post.call_args
                data = call_args[1]['json']
                system_message = data['messages'][0]['content']
                
                # Verifica instrução de variação correta
                expected_var = variation + 1
                assert f'Variação {expected_var}:' in system_message
                assert result.filename == f'artigo_3_v{expected_var}.txt'

    def test_generate_article_timeout_parameter(self, mock_config, mock_prompt, mock_success_response):
        """Testa que o timeout de 120 segundos é aplicado."""
        with patch('requests.post', return_value=mock_success_response) as mock_post:
            generate_article_deepseek(mock_config, mock_prompt, "trace_timeout_param")
            
            call_args = mock_post.call_args
            assert call_args[1]['timeout'] == 120

    def test_generate_article_error_logging_details(self, mock_config, mock_prompt):
        """Testa que detalhes do erro são logados corretamente."""
        test_error = Exception("Test error message")
        
        with patch('requests.post', side_effect=test_error) as mock_post:
            with patch('infraestructure.deepseek_gateway.logger') as mock_logger:
                with pytest.raises(Exception):
                    generate_article_deepseek(mock_config, mock_prompt, "trace_error_details")

                # Verifica que o erro foi logado com detalhes
                mock_logger.error.assert_called_once()
                log_call = mock_logger.error.call_args
                assert log_call[1]['extra']['details'] == "Test error message" 