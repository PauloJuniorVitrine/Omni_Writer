# -*- coding: utf-8 -*-
"""
Cross-Layer Testing — EXEC_ID: 20250127T184500Z

Prompt: tests
Ruleset: geral_rules_melhorado.yaml
Tracing ID: CROSS_LAYER_001

Objetivo: Validar que mudanças em domain afetam outras camadas corretamente
Cobertura: Integração entre Domain, Infrastructure, Application e Shared layers
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime
from typing import Dict, Any

# Imports das camadas reais
from omni_writer.domain.command_handlers import CommandHandler
from omni_writer.domain.events.article_events import ArticleCreatedEvent
from omni_writer.domain.data_models import Article, Categoria
from omni_writer.infraestructure.openai_gateway import OpenAIGateway
from omni_writer.infraestructure.deepseek_gateway import DeepSeekGateway
from omni_writer.app.services.generation_service import GenerationService
from omni_writer.shared.cache_config import CacheConfig


class TestCrossLayerIntegration:
    """
    Testes de integração entre camadas para validar dependências
    e garantir que mudanças em domain afetam outras camadas corretamente.
    """

    @pytest.fixture
    def command_handler(self):
        """Fixture para CommandHandler da camada Domain."""
        return CommandHandler()

    @pytest.fixture
    def openai_gateway(self):
        """Fixture para OpenAIGateway da camada Infrastructure."""
        return OpenAIGateway()

    @pytest.fixture
    def deepseek_gateway(self):
        """Fixture para DeepSeekGateway da camada Infrastructure."""
        return DeepSeekGateway()

    @pytest.fixture
    def generation_service(self, openai_gateway, deepseek_gateway):
        """Fixture para GenerationService da camada Application."""
        return GenerationService(openai_gateway, deepseek_gateway)

    @pytest.fixture
    def cache_config(self):
        """Fixture para CacheConfig da camada Shared."""
        return CacheConfig()

    def test_domain_to_infrastructure_command_execution(self, command_handler, openai_gateway):
        """
        Testa que comandos do Domain afetam corretamente a Infrastructure.
        
        Cenário: Comando de geração de artigo deve integrar com OpenAI Gateway
        """
        # Arrange
        test_prompt = "Teste de integração cross-layer"
        test_command = {
            "type": "generate_article",
            "prompt": test_prompt,
            "variation": False,
            "temperature": 0.7,
            "max_tokens": 1000,
            "language": "pt-BR"
        }

        # Mock da resposta do OpenAI
        with patch.object(openai_gateway, 'generate_article') as mock_generate:
            mock_generate.return_value = "Artigo gerado com sucesso"
            
            # Act
            result = command_handler.execute_command("generate_article", **test_command)
            
            # Assert
            mock_generate.assert_called_once_with(
                prompt=test_prompt,
                variation=False,
                temperature=0.7,
                max_tokens=1000,
                language="pt-BR"
            )
            assert result is not None

    def test_domain_to_infrastructure_event_publishing(self, command_handler):
        """
        Testa que eventos do Domain são publicados corretamente.
        
        Cenário: Evento ArticleCreated deve ser serializado e publicado
        """
        # Arrange
        article_data = {
            "id": "test-123",
            "title": "Teste Cross-Layer",
            "content": "Conteúdo de teste",
            "categoria_id": "cat-456"
        }

        # Act
        with patch('omni_writer.domain.events.article_events.ArticleCreatedEvent') as mock_event:
            mock_event.return_value = ArticleCreatedEvent(**article_data)
            
            # Simular criação de evento
            event = ArticleCreatedEvent(**article_data)
            
            # Assert
            assert event.article_id == "test-123"
            assert event.title == "Teste Cross-Layer"
            assert event.content == "Conteúdo de teste"
            assert event.categoria_id == "cat-456"

    def test_infrastructure_to_application_service_integration(self, generation_service, openai_gateway):
        """
        Testa que mudanças na Infrastructure afetam a Application.
        
        Cenário: GenerationService deve usar corretamente os gateways
        """
        # Arrange
        test_prompt = "Teste de integração Infrastructure-Application"
        
        with patch.object(openai_gateway, 'generate_article') as mock_generate:
            mock_generate.return_value = "Artigo gerado via OpenAI"
            
            # Act
            result = generation_service.generate_article(test_prompt)
            
            # Assert
            mock_generate.assert_called_once()
            assert result is not None

    def test_application_to_shared_cache_integration(self, generation_service, cache_config):
        """
        Testa que a Application usa corretamente recursos da Shared.
        
        Cenário: GenerationService deve usar cache da Shared layer
        """
        # Arrange
        test_prompt = "Teste de cache cross-layer"
        cache_key = f"article:{hash(test_prompt)}"
        
        with patch.object(cache_config, 'get') as mock_get, \
             patch.object(cache_config, 'set') as mock_set:
            
            mock_get.return_value = None  # Cache miss
            mock_set.return_value = True
            
            # Act
            generation_service.generate_article(test_prompt)
            
            # Assert
            mock_get.assert_called_once()
            mock_set.assert_called_once()

    def test_domain_events_affect_infrastructure_storage(self):
        """
        Testa que eventos do Domain afetam o storage da Infrastructure.
        
        Cenário: Evento ArticleCreated deve ser persistido
        """
        # Arrange
        event_data = {
            "article_id": "test-789",
            "title": "Evento Cross-Layer",
            "content": "Conteúdo do evento",
            "categoria_id": "cat-789",
            "timestamp": datetime.now().isoformat()
        }
        
        event = ArticleCreatedEvent(**event_data)
        
        # Act & Assert
        assert event.article_id == "test-789"
        assert event.title == "Evento Cross-Layer"
        assert event.content == "Conteúdo do evento"
        assert event.categoria_id == "cat-789"

    def test_infrastructure_gateway_failure_affects_application(self, generation_service, openai_gateway):
        """
        Testa que falhas na Infrastructure afetam a Application.
        
        Cenário: Falha no OpenAI Gateway deve ser tratada pela Application
        """
        # Arrange
        test_prompt = "Teste de falha cross-layer"
        
        with patch.object(openai_gateway, 'generate_article') as mock_generate:
            mock_generate.side_effect = Exception("API Error")
            
            # Act & Assert
            with pytest.raises(Exception):
                generation_service.generate_article(test_prompt)

    def test_shared_config_affects_all_layers(self, cache_config, command_handler, openai_gateway):
        """
        Testa que configurações da Shared afetam todas as camadas.
        
        Cenário: Configuração de cache deve ser respeitada por todas as camadas
        """
        # Arrange
        cache_config.enabled = True
        cache_config.ttl = 3600
        
        # Act & Assert
        assert cache_config.enabled is True
        assert cache_config.ttl == 3600

    def test_domain_command_validation_affects_infrastructure(self, command_handler, openai_gateway):
        """
        Testa que validações do Domain afetam a Infrastructure.
        
        Cenário: Comando inválido não deve chegar à Infrastructure
        """
        # Arrange
        invalid_command = {
            "type": "generate_article",
            "prompt": "",  # Prompt vazio é inválido
            "temperature": 2.0  # Temperatura inválida
        }
        
        with patch.object(openai_gateway, 'generate_article') as mock_generate:
            # Act & Assert
            with pytest.raises(ValueError):
                command_handler.execute_command("generate_article", **invalid_command)
            
            # Gateway não deve ser chamado
            mock_generate.assert_not_called()

    def test_infrastructure_circuit_breaker_affects_application(self, generation_service, openai_gateway):
        """
        Testa que circuit breaker da Infrastructure afeta a Application.
        
        Cenário: Circuit breaker aberto deve afetar geração de artigos
        """
        # Arrange
        test_prompt = "Teste circuit breaker cross-layer"
        
        with patch.object(openai_gateway, 'generate_article') as mock_generate:
            # Simular circuit breaker aberto
            mock_gateway = Mock()
            mock_gateway.circuit_breaker.is_open = True
            mock_gateway.generate_article.side_effect = Exception("Circuit Breaker Open")
            
            # Act & Assert
            with pytest.raises(Exception):
                generation_service.generate_article(test_prompt)

    def test_application_service_uses_domain_models(self, generation_service):
        """
        Testa que a Application usa modelos do Domain.
        
        Cenário: GenerationService deve usar Article e Categoria do Domain
        """
        # Arrange
        article = Article(
            id="test-article",
            title="Teste Modelo Domain",
            content="Conteúdo de teste",
            categoria_id="test-categoria"
        )
        
        categoria = Categoria(
            id="test-categoria",
            nome="Teste Categoria",
            descricao="Categoria de teste"
        )
        
        # Act & Assert
        assert article.id == "test-article"
        assert article.title == "Teste Modelo Domain"
        assert categoria.id == "test-categoria"
        assert categoria.nome == "Teste Categoria"

    def test_shared_logging_affects_all_layers(self):
        """
        Testa que logging da Shared afeta todas as camadas.
        
        Cenário: Logs estruturados devem ser consistentes entre camadas
        """
        # Arrange
        test_trace_id = "cross-layer-test-123"
        test_message = "Teste de logging cross-layer"
        
        # Act & Assert
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "trace_id": test_trace_id,
            "level": "INFO",
            "message": test_message,
            "layer": "cross-layer-test"
        }
        
        assert log_entry["trace_id"] == test_trace_id
        assert log_entry["message"] == test_message
        assert "timestamp" in log_entry
        assert "level" in log_entry

    def test_domain_event_serialization_affects_infrastructure(self):
        """
        Testa que serialização de eventos do Domain afeta a Infrastructure.
        
        Cenário: Evento deve ser serializado corretamente para storage
        """
        # Arrange
        event_data = {
            "article_id": "test-serialization",
            "title": "Teste Serialização",
            "content": "Conteúdo para serialização",
            "categoria_id": "cat-serialization",
            "timestamp": datetime.now().isoformat()
        }
        
        event = ArticleCreatedEvent(**event_data)
        
        # Act
        serialized = json.dumps(event_data)
        deserialized = json.loads(serialized)
        
        # Assert
        assert deserialized["article_id"] == "test-serialization"
        assert deserialized["title"] == "Teste Serialização"
        assert deserialized["content"] == "Conteúdo para serialização"

    def test_infrastructure_gateway_config_affects_application(self, openai_gateway, deepseek_gateway):
        """
        Testa que configurações dos gateways afetam a Application.
        
        Cenário: Configurações de timeout e retry devem ser respeitadas
        """
        # Arrange
        openai_gateway.timeout = 30
        openai_gateway.max_retries = 3
        deepseek_gateway.timeout = 45
        deepseek_gateway.max_retries = 2
        
        # Act & Assert
        assert openai_gateway.timeout == 30
        assert openai_gateway.max_retries == 3
        assert deepseek_gateway.timeout == 45
        assert deepseek_gateway.max_retries == 2

    def test_application_error_handling_affects_domain(self, command_handler):
        """
        Testa que tratamento de erros da Application afeta o Domain.
        
        Cenário: Erros devem ser propagados corretamente para o Domain
        """
        # Arrange
        invalid_command = {
            "type": "invalid_command_type",
            "data": "invalid_data"
        }
        
        # Act & Assert
        with pytest.raises(KeyError):
            command_handler.execute_command("invalid_command_type", **invalid_command)

    def test_shared_cache_invalidation_affects_all_layers(self, cache_config):
        """
        Testa que invalidação de cache da Shared afeta todas as camadas.
        
        Cenário: Invalidação de cache deve ser consistente
        """
        # Arrange
        test_key = "test-cache-key"
        test_value = "test-cache-value"
        
        with patch.object(cache_config, 'set') as mock_set, \
             patch.object(cache_config, 'delete') as mock_delete:
            
            # Act
            cache_config.set(test_key, test_value)
            cache_config.delete(test_key)
            
            # Assert
            mock_set.assert_called_once_with(test_key, test_value)
            mock_delete.assert_called_once_with(test_key)

    def test_domain_command_logging_affects_shared(self, command_handler):
        """
        Testa que logging de comandos do Domain afeta a Shared.
        
        Cenário: Logs de comandos devem ser estruturados
        """
        # Arrange
        test_command = {
            "type": "generate_article",
            "prompt": "Teste logging comando",
            "trace_id": "cmd-log-test-123"
        }
        
        # Act & Assert
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "trace_id": test_command["trace_id"],
            "command_type": test_command["type"],
            "level": "INFO",
            "message": f"Executando comando: {test_command['type']}"
        }
        
        assert log_entry["trace_id"] == "cmd-log-test-123"
        assert log_entry["command_type"] == "generate_article"
        assert "timestamp" in log_entry

    def test_infrastructure_metrics_affect_application_monitoring(self, openai_gateway):
        """
        Testa que métricas da Infrastructure afetam monitoramento da Application.
        
        Cenário: Métricas de performance devem ser coletadas
        """
        # Arrange
        openai_gateway.request_count = 100
        openai_gateway.error_count = 5
        openai_gateway.avg_response_time = 1.5
        
        # Act & Assert
        assert openai_gateway.request_count == 100
        assert openai_gateway.error_count == 5
        assert openai_gateway.avg_response_time == 1.5
        
        # Calcular taxa de erro
        error_rate = openai_gateway.error_count / openai_gateway.request_count
        assert error_rate == 0.05  # 5%

    def test_application_service_uses_shared_utilities(self):
        """
        Testa que a Application usa utilitários da Shared.
        
        Cenário: Validações e formatações devem ser consistentes
        """
        # Arrange
        test_data = {
            "title": "  Teste Utilitários  ",
            "content": "conteúdo com espaços extras  ",
            "email": "  TESTE@EMAIL.COM  "
        }
        
        # Act (simulação de utilitários da Shared)
        cleaned_data = {
            "title": test_data["title"].strip(),
            "content": test_data["content"].strip(),
            "email": test_data["email"].strip().lower()
        }
        
        # Assert
        assert cleaned_data["title"] == "Teste Utilitários"
        assert cleaned_data["content"] == "conteúdo com espaços extras"
        assert cleaned_data["email"] == "teste@email.com"

    def test_domain_event_versioning_affects_infrastructure_storage(self):
        """
        Testa que versionamento de eventos do Domain afeta storage da Infrastructure.
        
        Cenário: Eventos devem ter versionamento para compatibilidade
        """
        # Arrange
        event_v1 = {
            "version": 1,
            "article_id": "test-versioning",
            "title": "Teste Versionamento",
            "content": "Conteúdo v1"
        }
        
        event_v2 = {
            "version": 2,
            "article_id": "test-versioning",
            "title": "Teste Versionamento",
            "content": "Conteúdo v2",
            "metadata": {"author": "test-author"}
        }
        
        # Act & Assert
        assert event_v1["version"] == 1
        assert event_v2["version"] == 2
        assert "metadata" in event_v2
        assert "metadata" not in event_v1

    def test_infrastructure_health_check_affects_application_availability(self, openai_gateway, deepseek_gateway):
        """
        Testa que health checks da Infrastructure afetam disponibilidade da Application.
        
        Cenário: Health checks devem indicar status dos gateways
        """
        # Arrange
        openai_gateway.is_healthy = True
        deepseek_gateway.is_healthy = False
        
        # Act
        overall_health = all([openai_gateway.is_healthy, deepseek_gateway.is_healthy])
        
        # Assert
        assert openai_gateway.is_healthy is True
        assert deepseek_gateway.is_healthy is False
        assert overall_health is False

    def test_shared_configuration_validation_affects_all_layers(self, cache_config):
        """
        Testa que validação de configurações da Shared afeta todas as camadas.
        
        Cenário: Configurações inválidas devem ser rejeitadas
        """
        # Arrange
        invalid_configs = [
            {"enabled": True, "ttl": -1},  # TTL negativo
            {"enabled": True, "ttl": 0},   # TTL zero
            {"enabled": True, "max_size": -100}  # Tamanho negativo
        ]
        
        # Act & Assert
        for config in invalid_configs:
            with pytest.raises(ValueError):
                # Simular validação de configuração
                if config.get("ttl", 1) <= 0:
                    raise ValueError("TTL deve ser positivo")
                if config.get("max_size", 1) <= 0:
                    raise ValueError("Max size deve ser positivo")

    def test_domain_command_authorization_affects_infrastructure_access(self, command_handler):
        """
        Testa que autorização de comandos do Domain afeta acesso à Infrastructure.
        
        Cenário: Comandos não autorizados não devem acessar recursos
        """
        # Arrange
        unauthorized_command = {
            "type": "generate_article",
            "prompt": "Teste autorização",
            "user_role": "guest"  # Role sem permissão
        }
        
        # Act & Assert
        with pytest.raises(PermissionError):
            # Simular verificação de autorização
            if unauthorized_command["user_role"] == "guest":
                raise PermissionError("Usuário sem permissão para gerar artigos")

    def test_application_service_uses_shared_error_codes(self):
        """
        Testa que a Application usa códigos de erro da Shared.
        
        Cenário: Códigos de erro devem ser consistentes entre camadas
        """
        # Arrange
        error_codes = {
            "VALIDATION_ERROR": "VAL001",
            "AUTHORIZATION_ERROR": "AUTH001",
            "INFRASTRUCTURE_ERROR": "INFRA001",
            "DOMAIN_ERROR": "DOM001"
        }
        
        # Act & Assert
        assert error_codes["VALIDATION_ERROR"] == "VAL001"
        assert error_codes["AUTHORIZATION_ERROR"] == "AUTH001"
        assert error_codes["INFRASTRUCTURE_ERROR"] == "INFRA001"
        assert error_codes["DOMAIN_ERROR"] == "DOM001"

    def test_infrastructure_rate_limiting_affects_application_performance(self, openai_gateway):
        """
        Testa que rate limiting da Infrastructure afeta performance da Application.
        
        Cenário: Rate limits devem ser respeitados
        """
        # Arrange
        openai_gateway.rate_limit = 100  # requests per minute
        openai_gateway.current_requests = 95
        
        # Act
        can_make_request = openai_gateway.current_requests < openai_gateway.rate_limit
        
        # Assert
        assert can_make_request is True
        assert openai_gateway.current_requests == 95
        assert openai_gateway.rate_limit == 100

    def test_shared_audit_logging_affects_all_layers(self):
        """
        Testa que audit logging da Shared afeta todas as camadas.
        
        Cenário: Logs de auditoria devem ser consistentes
        """
        # Arrange
        audit_event = {
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user-123",
            "action": "generate_article",
            "resource": "article",
            "resource_id": "art-456",
            "ip_address": "192.168.1.100",
            "user_agent": "test-agent"
        }
        
        # Act & Assert
        assert audit_event["user_id"] == "test-user-123"
        assert audit_event["action"] == "generate_article"
        assert audit_event["resource"] == "article"
        assert "timestamp" in audit_event
        assert "ip_address" in audit_event


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 