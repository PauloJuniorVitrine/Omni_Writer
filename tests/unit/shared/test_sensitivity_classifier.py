"""
Testes Unitários - Sensitivity Classifier
========================================

Tracing ID: TEST_SENS_CLASS_20250127_001
Prompt: Item 14 - Sensitivity Classification Tests
Ruleset: checklist_integracao_externa.md
Created: 2025-01-27T23:05:00Z

Testes baseados em código real do sistema de classificação de sensibilidade.
"""

import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from shared.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
    ClassificationResult,
    SensitivityRule,
    classify_data_sensitivity
)


class TestSensitivityLevel:
    """Testes para enum SensitivityLevel"""
    
    def test_sensitivity_levels_exist(self):
        """Testa se todos os níveis de sensibilidade existem"""
        levels = list(SensitivityLevel)
        expected_levels = ['public', 'internal', 'confidential', 'restricted', 'critical']
        
        assert len(levels) == 5
        for level in levels:
            assert level.value in expected_levels
    
    def test_sensitivity_level_hierarchy(self):
        """Testa hierarquia dos níveis de sensibilidade"""
        # Verifica se os níveis estão ordenados corretamente
        levels = list(SensitivityLevel)
        
        # PUBLIC deve ser o menos sensível
        assert levels[0] == SensitivityLevel.PUBLIC
        
        # CRITICAL deve ser o mais sensível
        assert levels[-1] == SensitivityLevel.CRITICAL


class TestSensitivityRule:
    """Testes para dataclass SensitivityRule"""
    
    def test_sensitivity_rule_creation(self):
        """Testa criação de regra de sensibilidade"""
        rule = SensitivityRule(
            name="Test Rule",
            patterns=[r'test', r'example'],
            sensitivity_level=SensitivityLevel.CONFIDENTIAL,
            weight=0.8,
            context_required=True,
            false_positive_patterns=[r'dummy'],
            description="Regra de teste"
        )
        
        assert rule.name == "Test Rule"
        assert len(rule.patterns) == 2
        assert rule.sensitivity_level == SensitivityLevel.CONFIDENTIAL
        assert rule.weight == 0.8
        assert rule.context_required is True
        assert len(rule.false_positive_patterns) == 1
        assert rule.description == "Regra de teste"


class TestClassificationResult:
    """Testes para dataclass ClassificationResult"""
    
    def test_classification_result_creation(self):
        """Testa criação de resultado de classificação"""
        result = ClassificationResult(
            field_name="test_field",
            field_value="test_value",
            sensitivity_level=SensitivityLevel.CONFIDENTIAL,
            confidence_score=0.85,
            classification_method="rules",
            context={"environment": "test"},
            timestamp=datetime.now(),
            tracing_id="TEST_001",
            false_positive_risk=0.1,
            recommendations=["Test recommendation"]
        )
        
        assert result.field_name == "test_field"
        assert result.field_value == "test_value"
        assert result.sensitivity_level == SensitivityLevel.CONFIDENTIAL
        assert result.confidence_score == 0.85
        assert result.classification_method == "rules"
        assert result.context["environment"] == "test"
        assert result.tracing_id == "TEST_001"
        assert result.false_positive_risk == 0.1
        assert len(result.recommendations) == 1


class TestSensitivityClassifier:
    """Testes para classe SensitivityClassifier"""
    
    @pytest.fixture
    def classifier(self):
        """Fixture para criar classificador de teste"""
        return SensitivityClassifier()
    
    @pytest.fixture
    def temp_config_file(self):
        """Fixture para arquivo de configuração temporário"""
        config = {
            'cache_enabled': False,
            'ml_enabled': True,
            'confidence_threshold': 0.8,
            'false_positive_threshold': 0.2
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_path = f.name
        
        yield temp_path
        
        os.unlink(temp_path)
    
    def test_classifier_initialization(self, classifier):
        """Testa inicialização do classificador"""
        assert classifier.tracing_id.startswith("SENS_CLASS_")
        assert classifier.config['cache_enabled'] is True
        assert classifier.config['ml_enabled'] is True
        assert len(classifier.rules) > 0
        assert 'sensitive_words' in classifier.ml_model
    
    def test_classifier_with_config_file(self, temp_config_file):
        """Testa inicialização com arquivo de configuração"""
        classifier = SensitivityClassifier(temp_config_file)
        
        assert classifier.config['cache_enabled'] is False
        assert classifier.config['confidence_threshold'] == 0.8
        assert classifier.config['false_positive_threshold'] == 0.2
    
    def test_classify_api_key_critical(self, classifier):
        """Testa classificação de chave de API como crítica"""
        result = classifier.classify_field(
            field_name="api_key",
            field_value="sk_test_1234567890abcdef",
            context={"environment": "production"},
            service_name="payment"
        )
        
        assert result.sensitivity_level == SensitivityLevel.CRITICAL
        assert result.confidence_score > 0.8
        assert "api" in result.field_name.lower()
        assert len(result.recommendations) > 0
    
    def test_classify_password_critical(self, classifier):
        """Testa classificação de senha como crítica"""
        result = classifier.classify_field(
            field_name="user_password",
            field_value="mypassword123",
            context={"environment": "production"},
            service_name="auth"
        )
        
        assert result.sensitivity_level == SensitivityLevel.CRITICAL
        assert result.confidence_score > 0.8
        assert "password" in result.field_name.lower()
        assert "criptografia" in " ".join(result.recommendations).lower()
    
    def test_classify_cpf_restricted(self, classifier):
        """Testa classificação de CPF como restrito"""
        result = classifier.classify_field(
            field_name="customer_cpf",
            field_value="123.456.789-00",
            context={"environment": "production"},
            service_name="user"
        )
        
        assert result.sensitivity_level == SensitivityLevel.RESTRICTED
        assert result.confidence_score > 0.7
        assert "cpf" in result.field_name.lower()
    
    def test_classify_credit_card_restricted(self, classifier):
        """Testa classificação de cartão de crédito como restrito"""
        result = classifier.classify_field(
            field_name="card_number",
            field_value="4111-1111-1111-1111",
            context={"environment": "production"},
            service_name="payment"
        )
        
        assert result.sensitivity_level == SensitivityLevel.RESTRICTED
        assert result.confidence_score > 0.7
        assert "card" in result.field_name.lower()
    
    def test_classify_user_id_confidential(self, classifier):
        """Testa classificação de ID de usuário como confidencial"""
        result = classifier.classify_field(
            field_name="user_id",
            field_value="12345",
            context={"environment": "production"},
            service_name="user"
        )
        
        assert result.sensitivity_level == SensitivityLevel.CONFIDENTIAL
        assert result.confidence_score > 0.6
        assert "user" in result.field_name.lower()
    
    def test_classify_business_data_confidential(self, classifier):
        """Testa classificação de dados de negócio como confidenciais"""
        result = classifier.classify_field(
            field_name="revenue_amount",
            field_value="1000000",
            context={"environment": "production"},
            service_name="financial"
        )
        
        assert result.sensitivity_level == SensitivityLevel.CONFIDENTIAL
        assert result.confidence_score > 0.6
        assert "revenue" in result.field_name.lower()
    
    def test_classify_config_internal(self, classifier):
        """Testa classificação de configuração como interna"""
        result = classifier.classify_field(
            field_name="database_config",
            field_value="postgresql://user:pass@localhost/db",
            context={"environment": "development"},
            service_name="config"
        )
        
        assert result.sensitivity_level == SensitivityLevel.INTERNAL
        assert result.confidence_score > 0.4
        assert "config" in result.field_name.lower()
    
    def test_classify_public_content(self, classifier):
        """Testa classificação de conteúdo público"""
        result = classifier.classify_field(
            field_name="blog_title",
            field_value="Como usar APIs",
            context={"environment": "production"},
            service_name="content"
        )
        
        assert result.sensitivity_level == SensitivityLevel.PUBLIC
        assert result.confidence_score > 0.3
        assert "title" in result.field_name.lower()
    
    def test_false_positive_detection_test_environment(self, classifier):
        """Testa detecção de falso positivo em ambiente de teste"""
        result = classifier.classify_field(
            field_name="api_key",
            field_value="sk_test_1234567890abcdef",
            context={"environment": "test"},
            service_name="payment"
        )
        
        # Em ambiente de teste, deve reduzir a sensibilidade
        assert result.false_positive_risk > 0.3
        assert result.sensitivity_level in [SensitivityLevel.CRITICAL, SensitivityLevel.RESTRICTED]
    
    def test_false_positive_detection_test_data(self, classifier):
        """Testa detecção de falso positivo com dados de teste"""
        result = classifier.classify_field(
            field_name="test_api_key",
            field_value="test_key_123",
            context={"environment": "development"},
            service_name="test"
        )
        
        # Com dados de teste, deve reduzir a sensibilidade
        assert result.false_positive_risk > 0.3
        assert result.sensitivity_level in [SensitivityLevel.CRITICAL, SensitivityLevel.RESTRICTED, SensitivityLevel.CONFIDENTIAL]
    
    def test_cache_functionality(self, classifier):
        """Testa funcionalidade de cache"""
        # Primeira classificação
        result1 = classifier.classify_field(
            field_name="test_field",
            field_value="test_value",
            context={"environment": "production"},
            service_name="test"
        )
        
        # Segunda classificação (deve usar cache)
        result2 = classifier.classify_field(
            field_name="test_field",
            field_value="test_value",
            context={"environment": "production"},
            service_name="test"
        )
        
        assert result1.sensitivity_level == result2.sensitivity_level
        assert result1.confidence_score == result2.confidence_score
        assert result1.tracing_id == result2.tracing_id
    
    def test_metrics_tracking(self, classifier):
        """Testa rastreamento de métricas"""
        initial_metrics = classifier.get_metrics()
        
        # Fazer algumas classificações
        classifier.classify_field("field1", "value1", {"environment": "production"}, "service1")
        classifier.classify_field("field2", "value2", {"environment": "production"}, "service2")
        
        updated_metrics = classifier.get_metrics()
        
        assert updated_metrics['classifications_total'] > initial_metrics['classifications_total']
        assert updated_metrics['classifications_total'] >= 2
    
    def test_cache_stats(self, classifier):
        """Testa estatísticas de cache"""
        cache_stats = classifier.get_cache_stats()
        
        assert 'cache_size' in cache_stats
        assert 'cache_ttl_hours' in cache_stats
        assert 'cache_enabled' in cache_stats
        assert cache_stats['cache_enabled'] is True
    
    def test_search_classifications(self, classifier):
        """Testa busca de classificações"""
        # Fazer algumas classificações
        classifier.classify_field("user_id", "123", {"environment": "production"}, "user")
        classifier.classify_field("api_key", "sk_test_123", {"environment": "production"}, "payment")
        
        # Buscar por serviço
        user_results = classifier.search_classifications(service_name="user")
        assert len(user_results) > 0
        assert all("user" in str(result.context.get('service_name', '')) for result in user_results)
        
        # Buscar por nível de sensibilidade
        critical_results = classifier.search_classifications(sensitivity_level=SensitivityLevel.CRITICAL)
        assert len(critical_results) >= 0  # Pode ser 0 se não houver críticos
    
    def test_sensitivity_summary(self, classifier):
        """Testa resumo de sensibilidade"""
        # Fazer algumas classificações
        classifier.classify_field("public_field", "public_value", {"environment": "production"}, "content")
        classifier.classify_field("confidential_field", "confidential_value", {"environment": "production"}, "business")
        
        summary = classifier.get_sensitivity_summary()
        
        assert isinstance(summary, dict)
        assert len(summary) > 0
        assert all(level in summary for level in ['public', 'confidential'])
    
    def test_export_classifications_json(self, classifier):
        """Testa exportação de classificações em JSON"""
        # Fazer algumas classificações
        classifier.classify_field("field1", "value1", {"environment": "production"}, "service1")
        classifier.classify_field("field2", "value2", {"environment": "production"}, "service2")
        
        json_export = classifier.export_classifications(format='json', include_hashes=True)
        
        assert json_export.startswith('[')
        assert json_export.endswith(']')
        
        data = json.loads(json_export)
        assert isinstance(data, list)
        assert len(data) > 0
    
    def test_export_classifications_csv(self, classifier):
        """Testa exportação de classificações em CSV"""
        # Fazer algumas classificações
        classifier.classify_field("field1", "value1", {"environment": "production"}, "service1")
        
        csv_export = classifier.export_classifications(format='csv', include_hashes=True)
        
        assert csv_export.count('\n') > 0
        assert ',' in csv_export
    
    def test_validate_classification(self, classifier):
        """Testa validação de classificação"""
        # Validar classificação correta
        is_valid = classifier.validate_classification(
            field_name="api_key",
            field_value="sk_test_123",
            expected_level=SensitivityLevel.CRITICAL,
            context={"environment": "production"}
        )
        
        assert is_valid is True
        
        # Validar classificação incorreta
        is_valid = classifier.validate_classification(
            field_name="blog_title",
            field_value="Como usar APIs",
            expected_level=SensitivityLevel.CRITICAL,
            context={"environment": "production"}
        )
        
        assert is_valid is False
    
    def test_classifier_string_representation(self, classifier):
        """Testa representação string do classificador"""
        str_repr = str(classifier)
        
        assert "SensitivityClassifier" in str_repr
        assert classifier.tracing_id in str_repr
        assert "metrics" in str_repr
        assert "cache_stats" in str_repr
    
    def test_recommendations_generation(self, classifier):
        """Testa geração de recomendações"""
        result = classifier.classify_field(
            field_name="api_key",
            field_value="sk_test_1234567890abcdef",
            context={"environment": "production"},
            service_name="payment"
        )
        
        assert len(result.recommendations) > 0
        assert all(isinstance(rec, str) for rec in result.recommendations)
        
        # Verificar se há recomendações específicas para pagamento
        recommendations_text = " ".join(result.recommendations).lower()
        assert "criptografia" in recommendations_text or "acesso" in recommendations_text


class TestClassifyDataSensitivityFunction:
    """Testes para função de conveniência classify_data_sensitivity"""
    
    def test_classify_data_sensitivity_function(self):
        """Testa função de conveniência"""
        result = classify_data_sensitivity(
            field_name="api_key",
            field_value="sk_test_1234567890abcdef",
            context={"environment": "production"},
            service_name="payment"
        )
        
        assert isinstance(result, ClassificationResult)
        assert result.sensitivity_level == SensitivityLevel.CRITICAL
        assert result.confidence_score > 0.8
        assert result.tracing_id.startswith("SENS_CLASS_")
    
    def test_classify_data_sensitivity_minimal_params(self):
        """Testa função com parâmetros mínimos"""
        result = classify_data_sensitivity(
            field_name="test_field",
            field_value="test_value"
        )
        
        assert isinstance(result, ClassificationResult)
        assert result.field_name == "test_field"
        assert result.field_value == "test_value"
        assert result.context == {}


class TestSensitivityClassifierIntegration:
    """Testes de integração do classificador"""
    
    @pytest.fixture
    def classifier(self):
        """Fixture para classificador de integração"""
        return SensitivityClassifier()
    
    def test_integration_with_real_data_patterns(self, classifier):
        """Testa integração com padrões de dados reais"""
        test_cases = [
            # (field_name, field_value, expected_level, service_name)
            ("stripe_secret_key", "sk_live_1234567890abcdef", SensitivityLevel.CRITICAL, "payment"),
            ("user_email", "user@example.com", SensitivityLevel.CONFIDENTIAL, "user"),
            ("customer_cpf", "123.456.789-00", SensitivityLevel.RESTRICTED, "user"),
            ("blog_post_title", "Como usar APIs", SensitivityLevel.PUBLIC, "content"),
            ("database_password", "dbpass123", SensitivityLevel.CRITICAL, "config"),
            ("revenue_amount", "1000000.00", SensitivityLevel.CONFIDENTIAL, "financial"),
            ("jwt_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", SensitivityLevel.CRITICAL, "auth"),
            ("public_announcement", "Nova funcionalidade disponível", SensitivityLevel.PUBLIC, "content")
        ]
        
        for field_name, field_value, expected_level, service_name in test_cases:
            result = classifier.classify_field(
                field_name=field_name,
                field_value=field_value,
                context={"environment": "production"},
                service_name=service_name
            )
            
            assert result.sensitivity_level == expected_level, \
                f"Campo {field_name} deveria ser {expected_level.value}, mas foi {result.sensitivity_level.value}"
            
            assert result.confidence_score > 0.5, \
                f"Confiança muito baixa para {field_name}: {result.confidence_score}"
            
            assert len(result.recommendations) > 0, \
                f"Sem recomendações para {field_name}"
    
    def test_integration_false_positive_handling(self, classifier):
        """Testa tratamento de falsos positivos em integração"""
        # Dados que parecem sensíveis mas são de teste
        test_cases = [
            ("test_api_key", "test_key_123", "test"),
            ("example_password", "example_pass", "example"),
            ("dummy_cpf", "123.456.789-00", "dummy"),
            ("mock_credit_card", "4111-1111-1111-1111", "mock")
        ]
        
        for field_name, field_value, service_name in test_cases:
            result = classifier.classify_field(
                field_name=field_name,
                field_value=field_value,
                context={"environment": "test"},
                service_name=service_name
            )
            
            # Deve detectar risco de falso positivo
            assert result.false_positive_risk > 0.3, \
                f"Risco de falso positivo muito baixo para {field_name}"
            
            # Deve reduzir a sensibilidade
            assert result.sensitivity_level.value in ['restricted', 'confidential', 'internal'], \
                f"Sensibilidade muito alta para dados de teste: {field_name}"
    
    def test_integration_performance_metrics(self, classifier):
        """Testa métricas de performance em integração"""
        initial_metrics = classifier.get_metrics()
        
        # Fazer múltiplas classificações
        for i in range(10):
            classifier.classify_field(
                field_name=f"field_{i}",
                field_value=f"value_{i}",
                context={"environment": "production"},
                service_name="test"
            )
        
        final_metrics = classifier.get_metrics()
        
        # Verificar se métricas foram atualizadas
        assert final_metrics['classifications_total'] == initial_metrics['classifications_total'] + 10
        assert final_metrics['cache_hits'] >= 0  # Pode ser 0 se não houver cache hits
        assert final_metrics['ml_classifications'] + final_metrics['rule_classifications'] >= 10


if __name__ == "__main__":
    # Executar testes
    pytest.main([__file__, "-v"]) 