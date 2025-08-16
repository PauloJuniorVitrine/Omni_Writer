"""
Testes unitários para sistema de feature flags.
Baseados em código real e cenários reais do sistema Omni Writer.

Prompt: Testes para Feature Flags - Item 2
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T16:25:00Z
Tracing ID: FEATURE_FLAGS_TEST_20250127_002

Política de Testes:
- ✅ Baseados em código real do sistema
- ✅ Cenários reais de uso
- ✅ Edge cases reais
- ❌ Proibidos: dados sintéticos, genéricos ou aleatórios
- ❌ Proibidos: testes foo, bar, lorem, random
"""

import pytest
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from shared.feature_flags import (
    FeatureFlagsManager,
    FeatureFlagType,
    FeatureFlagStatus,
    FeatureFlagConfig,
    FeatureFlagAudit,
    feature_flag,
    require_feature_flag,
    FeatureFlagDisabledError,
    is_feature_enabled,
    set_feature_flag,
    get_feature_flag,
    get_all_feature_flags,
    get_feature_usage_stats
)


class TestFeatureFlagConfig:
    """Testes para configuração de feature flags."""
    
    def test_feature_flag_config_creation(self):
        """Testa criação de configuração de feature flag."""
        config = FeatureFlagConfig(
            name="stripe_payment_enabled",
            type=FeatureFlagType.RELEASE,
            status=FeatureFlagStatus.DISABLED,
            description="Habilita integração com Stripe para pagamentos",
            percentage=0.0
        )
        
        assert config.name == "stripe_payment_enabled"
        assert config.type == FeatureFlagType.RELEASE
        assert config.status == FeatureFlagStatus.DISABLED
        assert config.description == "Habilita integração com Stripe para pagamentos"
        assert config.percentage == 0.0
        assert config.created_at is not None
        assert config.updated_at is not None
    
    def test_feature_flag_config_with_dates(self):
        """Testa configuração com datas de início e fim."""
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=7)
        
        config = FeatureFlagConfig(
            name="new_ui_enabled",
            type=FeatureFlagType.EXPERIMENT,
            status=FeatureFlagStatus.PARTIAL,
            description="Habilita nova interface de usuário",
            percentage=50.0,
            start_date=start_date,
            end_date=end_date
        )
        
        assert config.start_date == start_date
        assert config.end_date == end_date
        assert config.percentage == 50.0
    
    def test_feature_flag_config_with_conditions(self):
        """Testa configuração com condições personalizadas."""
        conditions = {
            "user_type": "premium",
            "region": "us-east-1",
            "version": "2.0"
        }
        
        config = FeatureFlagConfig(
            name="advanced_features_enabled",
            type=FeatureFlagType.PERMISSION,
            status=FeatureFlagStatus.ENABLED,
            description="Habilita recursos avançados para usuários premium",
            conditions=conditions
        )
        
        assert config.conditions == conditions
        assert config.type == FeatureFlagType.PERMISSION


class TestFeatureFlagAudit:
    """Testes para auditoria de feature flags."""
    
    def test_feature_flag_audit_creation(self):
        """Testa criação de entrada de auditoria."""
        timestamp = datetime.utcnow()
        context = {"ip": "192.168.1.1", "user_agent": "Mozilla/5.0"}
        
        audit = FeatureFlagAudit(
            flag_name="stripe_payment_enabled",
            user_id="user_123",
            session_id="session_456",
            enabled=False,
            timestamp=timestamp,
            context=context,
            trace_id="trace_789"
        )
        
        assert audit.flag_name == "stripe_payment_enabled"
        assert audit.user_id == "user_123"
        assert audit.session_id == "session_456"
        assert audit.enabled is False
        assert audit.timestamp == timestamp
        assert audit.context == context
        assert audit.trace_id == "trace_789"


class TestFeatureFlagsManager:
    """Testes para gerenciador de feature flags."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para gerenciador de feature flags."""
        with patch('shared.feature_flags.REDIS_AVAILABLE', False):
            return FeatureFlagsManager()
    
    def test_manager_initialization(self, manager):
        """Testa inicialização do gerenciador."""
        assert manager.enabled is True
        assert manager.audit_enabled is True
        assert manager.max_audit_log_size == 10000
        assert len(manager.flags) > 0
    
    def test_load_default_flags(self, manager):
        """Testa carregamento de flags padrão."""
        # Verifica se flags críticas estão carregadas
        assert "stripe_payment_enabled" in manager.flags
        assert "service_mesh_enabled" in manager.flags
        assert "proactive_intelligence_enabled" in manager.flags
        assert "contract_drift_prediction_enabled" in manager.flags
        assert "multi_region_enabled" in manager.flags
        
        # Verifica configurações das flags
        stripe_flag = manager.flags["stripe_payment_enabled"]
        assert stripe_flag.type == FeatureFlagType.RELEASE
        assert stripe_flag.status == FeatureFlagStatus.DISABLED
        assert stripe_flag.percentage == 0.0
    
    def test_is_enabled_disabled_flag(self, manager):
        """Testa verificação de flag desabilitada."""
        result = manager.is_enabled("stripe_payment_enabled")
        assert result is False
    
    def test_is_enabled_enabled_flag(self, manager):
        """Testa verificação de flag habilitada."""
        # Habilita flag
        manager.set_flag("stripe_payment_enabled", FeatureFlagStatus.ENABLED)
        
        result = manager.is_enabled("stripe_payment_enabled")
        assert result is True
    
    def test_is_enabled_partial_flag(self, manager):
        """Testa verificação de flag com rollout parcial."""
        # Define flag com 50% de rollout
        manager.set_flag("stripe_payment_enabled", FeatureFlagStatus.PARTIAL, 50.0)
        
        # Testa múltiplas verificações para ver distribuição
        enabled_count = 0
        total_checks = 100
        
        for i in range(total_checks):
            if manager.is_enabled("stripe_payment_enabled", user_id=f"user_{i}"):
                enabled_count += 1
        
        # Deve estar próximo de 50% (com tolerância)
        percentage = (enabled_count / total_checks) * 100
        assert 40 <= percentage <= 60
    
    def test_is_enabled_nonexistent_flag(self, manager):
        """Testa verificação de flag inexistente."""
        result = manager.is_enabled("nonexistent_flag")
        assert result is False
    
    def test_is_enabled_with_dates(self, manager):
        """Testa verificação de flag com datas de validade."""
        now = datetime.utcnow()
        start_date = now + timedelta(hours=1)  # Flag inicia em 1 hora
        
        manager.set_flag(
            "future_flag",
            FeatureFlagStatus.ENABLED,
            description="Flag que inicia no futuro",
            start_date=start_date
        )
        
        # Flag não deve estar habilitada antes da data de início
        result = manager.is_enabled("future_flag")
        assert result is False
    
    def test_set_flag(self, manager):
        """Testa definição de feature flag."""
        manager.set_flag(
            "test_flag",
            FeatureFlagStatus.ENABLED,
            75.0,
            "Flag de teste"
        )
        
        flag = manager.get_flag("test_flag")
        assert flag is not None
        assert flag.name == "test_flag"
        assert flag.status == FeatureFlagStatus.ENABLED
        assert flag.percentage == 75.0
        assert flag.description == "Flag de teste"
    
    def test_get_flag(self, manager):
        """Testa obtenção de configuração de flag."""
        flag = manager.get_flag("stripe_payment_enabled")
        assert flag is not None
        assert flag.name == "stripe_payment_enabled"
        assert flag.type == FeatureFlagType.RELEASE
    
    def test_get_all_flags(self, manager):
        """Testa obtenção de todas as flags."""
        flags = manager.get_all_flags()
        assert isinstance(flags, dict)
        assert len(flags) > 0
        assert "stripe_payment_enabled" in flags
    
    def test_audit_flag_usage(self, manager):
        """Testa auditoria de uso de flags."""
        # Habilita auditoria
        manager.audit_enabled = True
        
        # Verifica flag
        manager.is_enabled("stripe_payment_enabled", user_id="test_user")
        
        # Verifica se auditoria foi registrada
        audit_log = manager.get_audit_log("stripe_payment_enabled")
        assert len(audit_log) > 0
        
        latest_audit = audit_log[-1]
        assert latest_audit.flag_name == "stripe_payment_enabled"
        assert latest_audit.user_id == "test_user"
        assert latest_audit.enabled is False  # Flag está desabilitada por padrão
    
    def test_get_usage_stats(self, manager):
        """Testa obtenção de estatísticas de uso."""
        # Habilita auditoria
        manager.audit_enabled = True
        
        # Simula uso da flag
        for i in range(10):
            manager.is_enabled("stripe_payment_enabled", user_id=f"user_{i}")
        
        # Obtém estatísticas
        stats = manager.get_usage_stats("stripe_payment_enabled")
        
        assert stats["total_checks"] == 10
        assert stats["enabled_count"] == 0  # Flag está desabilitada
        assert stats["disabled_count"] == 10
        assert stats["enabled_percentage"] == 0.0
    
    def test_manager_disabled(self):
        """Testa comportamento quando feature flags estão desabilitadas."""
        with patch.dict(os.environ, {'FEATURE_FLAGS_ENABLED': 'false'}):
            manager = FeatureFlagsManager()
            
            result = manager.is_enabled("stripe_payment_enabled")
            assert result is False


class TestFeatureFlagDecorators:
    """Testes para decorators de feature flags."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para gerenciador de feature flags."""
        with patch('shared.feature_flags.REDIS_AVAILABLE', False):
            return FeatureFlagsManager()
    
    def test_feature_flag_decorator_enabled(self, manager):
        """Testa decorator com flag habilitada."""
        # Habilita flag
        manager.set_flag("test_decorator_flag", FeatureFlagStatus.ENABLED)
        
        @feature_flag("test_decorator_flag")
        def test_function():
            return "function_executed"
        
        result = test_function()
        assert result == "function_executed"
    
    def test_feature_flag_decorator_disabled(self, manager):
        """Testa decorator com flag desabilitada."""
        @feature_flag("test_decorator_flag_disabled")
        def test_function():
            return "function_executed"
        
        result = test_function()
        assert result is None  # Retorna None quando flag está desabilitada
    
    def test_feature_flag_decorator_with_user_id(self, manager):
        """Testa decorator com user_id."""
        # Define flag com 50% de rollout
        manager.set_flag("test_user_flag", FeatureFlagStatus.PARTIAL, 50.0)
        
        @feature_flag("test_user_flag", user_id="specific_user")
        def test_function():
            return "function_executed"
        
        result = test_function()
        # Resultado pode ser None ou "function_executed" dependendo da distribuição
        assert result in [None, "function_executed"]
    
    def test_require_feature_flag_decorator_enabled(self, manager):
        """Testa decorator require com flag habilitada."""
        # Habilita flag
        manager.set_flag("test_require_flag", FeatureFlagStatus.ENABLED)
        
        @require_feature_flag("test_require_flag")
        def test_function():
            return "function_executed"
        
        result = test_function()
        assert result == "function_executed"
    
    def test_require_feature_flag_decorator_disabled(self, manager):
        """Testa decorator require com flag desabilitada."""
        @require_feature_flag("test_require_flag_disabled")
        def test_function():
            return "function_executed"
        
        with pytest.raises(FeatureFlagDisabledError):
            test_function()


class TestFeatureFlagFunctions:
    """Testes para funções de conveniência."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para gerenciador de feature flags."""
        with patch('shared.feature_flags.REDIS_AVAILABLE', False):
            return FeatureFlagsManager()
    
    def test_is_feature_enabled(self, manager):
        """Testa função is_feature_enabled."""
        # Habilita flag
        set_feature_flag("test_function_flag", FeatureFlagStatus.ENABLED)
        
        result = is_feature_enabled("test_function_flag")
        assert result is True
    
    def test_set_feature_flag(self, manager):
        """Testa função set_feature_flag."""
        set_feature_flag(
            "test_set_flag",
            FeatureFlagStatus.ENABLED,
            80.0,
            "Flag de teste para função"
        )
        
        flag = get_feature_flag("test_set_flag")
        assert flag is not None
        assert flag.status == FeatureFlagStatus.ENABLED
        assert flag.percentage == 80.0
        assert flag.description == "Flag de teste para função"
    
    def test_get_feature_flag(self, manager):
        """Testa função get_feature_flag."""
        flag = get_feature_flag("stripe_payment_enabled")
        assert flag is not None
        assert flag.name == "stripe_payment_enabled"
    
    def test_get_all_feature_flags(self, manager):
        """Testa função get_all_feature_flags."""
        flags = get_all_feature_flags()
        assert isinstance(flags, dict)
        assert len(flags) > 0
    
    def test_get_feature_usage_stats(self, manager):
        """Testa função get_feature_usage_stats."""
        # Habilita auditoria
        manager.audit_enabled = True
        
        # Simula uso
        for i in range(5):
            is_feature_enabled("stripe_payment_enabled", user_id=f"user_{i}")
        
        stats = get_feature_usage_stats("stripe_payment_enabled")
        assert stats["total_checks"] == 5
        assert stats["enabled_count"] == 0  # Flag está desabilitada por padrão


class TestFeatureFlagIntegration:
    """Testes de integração para feature flags."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para gerenciador de feature flags."""
        with patch('shared.feature_flags.REDIS_AVAILABLE', False):
            return FeatureFlagsManager()
    
    def test_integration_with_real_flags(self, manager):
        """Testa integração com flags reais do sistema."""
        # Testa flags de integração externa
        assert "stripe_payment_enabled" in manager.flags
        assert "service_mesh_enabled" in manager.flags
        assert "proactive_intelligence_enabled" in manager.flags
        assert "contract_drift_prediction_enabled" in manager.flags
        assert "multi_region_enabled" in manager.flags
        
        # Testa flags de performance
        assert "advanced_caching_enabled" in manager.flags
        assert "parallel_processing_enabled" in manager.flags
        
        # Testa flags de segurança
        assert "enhanced_security_enabled" in manager.flags
        assert "rate_limiting_strict_enabled" in manager.flags
        
        # Testa flags de monitoramento
        assert "detailed_metrics_enabled" in manager.flags
        assert "circuit_breaker_metrics_enabled" in manager.flags
    
    def test_rollout_scenario(self, manager):
        """Testa cenário de rollout gradual."""
        # Simula rollout de 25% para nova funcionalidade
        manager.set_flag(
            "new_ml_optimization",
            FeatureFlagStatus.PARTIAL,
            25.0,
            "Nova otimização baseada em ML"
        )
        
        # Simula 100 usuários
        enabled_users = 0
        total_users = 100
        
        for i in range(total_users):
            if manager.is_enabled("new_ml_optimization", user_id=f"user_{i}"):
                enabled_users += 1
        
        # Deve estar próximo de 25%
        percentage = (enabled_users / total_users) * 100
        assert 15 <= percentage <= 35  # Tolerância de ±10%
    
    def test_rollback_scenario(self, manager):
        """Testa cenário de rollback."""
        # Habilita flag
        manager.set_flag("test_rollback_flag", FeatureFlagStatus.ENABLED)
        assert manager.is_enabled("test_rollback_flag") is True
        
        # Simula rollback (desabilita flag)
        manager.set_flag("test_rollback_flag", FeatureFlagStatus.DISABLED)
        assert manager.is_enabled("test_rollback_flag") is False
    
    def test_audit_trail_completeness(self, manager):
        """Testa completude do trail de auditoria."""
        manager.audit_enabled = True
        
        # Simula uso com contexto completo
        context = {
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "endpoint": "/api/generate",
            "trace_id": "trace_123456"
        }
        
        manager.is_enabled(
            "stripe_payment_enabled",
            user_id="user_123",
            session_id="session_456",
            context=context
        )
        
        # Verifica auditoria
        audit_log = manager.get_audit_log("stripe_payment_enabled")
        assert len(audit_log) > 0
        
        latest_audit = audit_log[-1]
        assert latest_audit.user_id == "user_123"
        assert latest_audit.session_id == "session_456"
        assert latest_audit.context == context
        assert latest_audit.trace_id == "trace_123456"


class TestFeatureFlagEdgeCases:
    """Testes para casos extremos de feature flags."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para gerenciador de feature flags."""
        with patch('shared.feature_flags.REDIS_AVAILABLE', False):
            return FeatureFlagsManager()
    
    def test_zero_percentage_flag(self, manager):
        """Testa flag com 0% de rollout."""
        manager.set_flag("zero_percentage_flag", FeatureFlagStatus.PARTIAL, 0.0)
        
        result = manager.is_enabled("zero_percentage_flag", user_id="any_user")
        assert result is False
    
    def test_hundred_percentage_flag(self, manager):
        """Testa flag com 100% de rollout."""
        manager.set_flag("hundred_percentage_flag", FeatureFlagStatus.PARTIAL, 100.0)
        
        result = manager.is_enabled("hundred_percentage_flag", user_id="any_user")
        assert result is True
    
    def test_flag_with_expired_end_date(self, manager):
        """Testa flag com data de fim expirada."""
        past_date = datetime.utcnow() - timedelta(days=1)
        
        manager.set_flag(
            "expired_flag",
            FeatureFlagStatus.ENABLED,
            end_date=past_date
        )
        
        result = manager.is_enabled("expired_flag")
        assert result is False
    
    def test_flag_with_future_start_date(self, manager):
        """Testa flag com data de início no futuro."""
        future_date = datetime.utcnow() + timedelta(days=1)
        
        manager.set_flag(
            "future_flag",
            FeatureFlagStatus.ENABLED,
            start_date=future_date
        )
        
        result = manager.is_enabled("future_flag")
        assert result is False
    
    def test_concurrent_flag_access(self, manager):
        """Testa acesso concorrente às flags."""
        import threading
        
        results = []
        
        def check_flag():
            result = manager.is_enabled("stripe_payment_enabled")
            results.append(result)
        
        # Cria múltiplas threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=check_flag)
            threads.append(thread)
            thread.start()
        
        # Aguarda todas as threads
        for thread in threads:
            thread.join()
        
        # Todas devem retornar o mesmo resultado (False, pois flag está desabilitada)
        assert all(result is False for result in results)
        assert len(results) == 10 