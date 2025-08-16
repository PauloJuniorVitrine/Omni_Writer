"""
Testes unitários para Hash-based Audit Trail
============================================

Testes baseados em código real e cenários reais de auditoria.

Tracing ID: TEST_HASH_AUDIT_20250127_001
Prompt: checklist_integracao_externa.md - Item 13
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:25:00Z

Baseado em:
- Código real do HashAuditTrail
- Cenários reais de logs críticos
- Requisitos de compliance e auditoria
- Padrões de segurança e integridade
"""

import json
import pytest
import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from shared.hash_audit_trail import (
    HashAuditTrail,
    AuditEntry,
    ChainValidationResult,
    LogSeverity,
    HashValidationStatus
)
from shared.config import Config
from shared.feature_flags import FeatureFlags


class TestHashAuditTrail:
    """Testes para HashAuditTrail baseados em código real."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock da configuração para testes."""
        config = Mock(spec=Config)
        config.get.return_value = "development"
        return config
    
    @pytest.fixture
    def mock_feature_flags(self):
        """Mock das feature flags para testes."""
        flags = Mock(spec=FeatureFlags)
        flags.is_enabled.return_value = True
        return flags
    
    @pytest.fixture
    def audit_trail(self, mock_config, mock_feature_flags):
        """Instância do audit trail para testes."""
        with patch('shared.hash_audit_trail.Config', return_value=mock_config), \
             patch('shared.hash_audit_trail.FeatureFlags', return_value=mock_feature_flags):
            
            return HashAuditTrail()
    
    def test_initialization_with_feature_flag(self, mock_config, mock_feature_flags):
        """Testa inicialização com feature flag ativa."""
        with patch('shared.hash_audit_trail.Config', return_value=mock_config), \
             patch('shared.hash_audit_trail.FeatureFlags', return_value=mock_feature_flags), \
             patch('os.makedirs') as mock_makedirs:
            
            audit_trail = HashAuditTrail()
            
            assert audit_trail.config == mock_config
            assert audit_trail.feature_flags == mock_feature_flags
            assert len(audit_trail.audit_entries) == 0
            assert audit_trail.hash_algorithm == "sha256"
            assert audit_trail.chain_validation_interval == 300
            
            # Verificar que diretório foi criado
            mock_makedirs.assert_called_once()
    
    def test_is_critical_log_payment_service(self, audit_trail):
        """Testa detecção de log crítico em serviço de pagamento."""
        # Cenário real: Log de erro em serviço de pagamento
        is_critical = audit_trail.is_critical_log(
            service_name="stripe_payment_service",
            log_level=LogSeverity.ERROR,
            message="Payment processing failed for transaction 12345",
            context={"transaction_id": "txn_12345", "amount": 100.00}
        )
        
        assert is_critical is True
    
    def test_is_critical_log_authentication_service(self, audit_trail):
        """Testa detecção de log crítico em serviço de autenticação."""
        # Cenário real: Log de erro em autenticação
        is_critical = audit_trail.is_critical_log(
            service_name="user_authentication_service",
            log_level=LogSeverity.ERROR,
            message="Authentication failed for user admin",
            context={"user_id": "admin", "ip_address": "192.168.1.100"}
        )
        
        assert is_critical is True
    
    def test_is_critical_log_with_critical_keywords(self, audit_trail):
        """Testa detecção de log crítico por palavras-chave."""
        # Cenário real: Log com palavras-chave críticas
        is_critical = audit_trail.is_critical_log(
            service_name="general_service",
            log_level=LogSeverity.WARNING,
            message="Security violation detected in API endpoint",
            context={"endpoint": "/api/admin", "user_id": "user123"}
        )
        
        assert is_critical is True
    
    def test_is_critical_log_with_critical_context(self, audit_trail):
        """Testa detecção de log crítico por contexto."""
        # Cenário real: Log com contexto crítico
        is_critical = audit_trail.is_critical_log(
            service_name="general_service",
            log_level=LogSeverity.INFO,
            message="API request processed",
            context={"api_key": "sk_test_123", "payment_id": "pi_123"}
        )
        
        assert is_critical is True
    
    def test_is_critical_log_false_positive_development(self, audit_trail):
        """Testa detecção de falso positivo em desenvolvimento."""
        # Cenário real: Log de debug em desenvolvimento
        is_critical = audit_trail.is_critical_log(
            service_name="test_service",
            log_level=LogSeverity.DEBUG,
            message="Test debug message",
            context={"test": True}
        )
        
        assert is_critical is False
    
    def test_is_critical_log_false_positive_test_service(self, audit_trail):
        """Testa detecção de falso positivo em serviço de teste."""
        # Cenário real: Serviço de teste
        is_critical = audit_trail.is_critical_log(
            service_name="mock_payment_service",
            log_level=LogSeverity.ERROR,
            message="Mock payment error",
            context={"mock": True}
        )
        
        assert is_critical is False
    
    def test_create_audit_entry_critical_log(self, audit_trail):
        """Testa criação de entrada de auditoria para log crítico."""
        # Cenário real: Log crítico de pagamento
        entry = audit_trail.create_audit_entry(
            service_name="stripe_payment_service",
            log_level=LogSeverity.ERROR,
            message="Payment failed: insufficient funds",
            context={"transaction_id": "txn_123", "amount": 500.00},
            tracing_id="payment_error_001"
        )
        
        # Verificar que entrada foi criada
        assert entry is not None
        assert isinstance(entry, AuditEntry)
        assert entry.service_name == "stripe_payment_service"
        assert entry.log_level == LogSeverity.ERROR
        assert entry.message == "Payment failed: insufficient funds"
        assert entry.tracing_id == "payment_error_001"
        assert entry.is_critical is True
        assert entry.requires_chain_validation is True
        assert entry.validation_status == HashValidationStatus.PENDING
        
        # Verificar hashes
        assert len(entry.original_hash) == 64  # SHA-256 hex
        assert len(entry.chain_hash) == 64
        assert entry.previous_hash is not None
    
    def test_create_audit_entry_non_critical_log(self, audit_trail):
        """Testa que entrada não é criada para log não crítico."""
        # Cenário real: Log não crítico
        entry = audit_trail.create_audit_entry(
            service_name="general_service",
            log_level=LogSeverity.INFO,
            message="User logged in successfully",
            context={"user_id": "user123"},
            tracing_id="login_success_001"
        )
        
        # Verificar que entrada não foi criada
        assert entry is None
    
    def test_validate_entry_integrity_valid(self, audit_trail):
        """Testa validação de integridade de entrada válida."""
        # Criar entrada de auditoria
        entry = audit_trail.create_audit_entry(
            service_name="test_service",
            log_level=LogSeverity.ERROR,
            message="Test error message",
            context={"test": True},
            tracing_id="test_001"
        )
        
        # Validar integridade
        is_valid = audit_trail.validate_entry_integrity(entry.entry_id)
        
        assert is_valid is True
        assert entry.validation_status == HashValidationStatus.VALID
        assert entry.validation_timestamp is not None
        assert entry.validation_attempts == 1
    
    def test_validate_entry_integrity_invalid(self, audit_trail):
        """Testa validação de integridade de entrada modificada."""
        # Criar entrada de auditoria
        entry = audit_trail.create_audit_entry(
            service_name="test_service",
            log_level=LogSeverity.ERROR,
            message="Original message",
            context={"test": True},
            tracing_id="test_002"
        )
        
        # Modificar a mensagem (simulando adulteração)
        entry.message = "Modified message"
        
        # Validar integridade
        is_valid = audit_trail.validate_entry_integrity(entry.entry_id)
        
        assert is_valid is False
        assert entry.validation_status == HashValidationStatus.INVALID
        assert entry.validation_timestamp is not None
        assert entry.validation_attempts == 1
    
    def test_validate_entry_integrity_not_found(self, audit_trail):
        """Testa validação de entrada inexistente."""
        # Tentar validar entrada que não existe
        is_valid = audit_trail.validate_entry_integrity("nonexistent_entry")
        
        assert is_valid is False
    
    def test_validate_chain_integrity_valid_chain(self, audit_trail):
        """Testa validação de integridade de chain válida."""
        # Criar múltiplas entradas para formar chain
        entries = []
        for i in range(3):
            entry = audit_trail.create_audit_entry(
                service_name=f"service_{i}",
                log_level=LogSeverity.ERROR,
                message=f"Error message {i}",
                context={"index": i},
                tracing_id=f"chain_test_{i}"
            )
            entries.append(entry)
        
        # Validar chain
        result = audit_trail.validate_chain_integrity()
        
        # Verificar resultado
        assert isinstance(result, ChainValidationResult)
        assert result.total_entries == 3
        assert result.valid_entries == 3
        assert result.invalid_entries == 0
        assert len(result.broken_links) == 0
        assert result.integrity_score == 1.0
        assert result.validation_status == HashValidationStatus.VALID
        assert "íntegra" in result.recommendations[0]
    
    def test_validate_chain_integrity_broken_chain(self, audit_trail):
        """Testa validação de integridade de chain quebrada."""
        # Criar múltiplas entradas
        entries = []
        for i in range(3):
            entry = audit_trail.create_audit_entry(
                service_name=f"service_{i}",
                log_level=LogSeverity.ERROR,
                message=f"Error message {i}",
                context={"index": i},
                tracing_id=f"broken_chain_{i}"
            )
            entries.append(entry)
        
        # Modificar uma entrada (quebrar chain)
        entries[1].message = "Modified message"
        
        # Validar chain
        result = audit_trail.validate_chain_integrity()
        
        # Verificar resultado
        assert result.invalid_entries > 0
        assert result.integrity_score < 1.0
        assert len(result.broken_links) > 0
    
    def test_validate_chain_integrity_empty_chain(self, audit_trail):
        """Testa validação de chain vazia."""
        # Validar chain sem entradas
        result = audit_trail.validate_chain_integrity()
        
        # Verificar resultado
        assert result.total_entries == 0
        assert result.valid_entries == 0
        assert result.invalid_entries == 0
        assert result.integrity_score == 1.0
        assert result.validation_status == HashValidationStatus.VALID
        assert "Nenhuma entrada" in result.recommendations[0]
    
    def test_get_audit_summary_with_entries(self, audit_trail):
        """Testa resumo de auditoria com entradas."""
        # Criar entradas de teste
        for i in range(5):
            audit_trail.create_audit_entry(
                service_name=f"service_{i % 2}",  # 2 serviços diferentes
                log_level=LogSeverity.ERROR if i % 2 == 0 else LogSeverity.CRITICAL,
                message=f"Error message {i}",
                context={"index": i},
                tracing_id=f"summary_test_{i}"
            )
        
        # Obter resumo
        summary = audit_trail.get_audit_summary()
        
        # Verificar estrutura
        assert summary["total_entries"] == 5
        assert summary["valid_entries"] == 5  # Todas válidas inicialmente
        assert summary["invalid_entries"] == 0
        assert summary["integrity_score"] == 1.0
        assert "service_0" in summary["service_distribution"]
        assert "service_1" in summary["service_distribution"]
        assert "error" in summary["level_distribution"]
        assert "critical" in summary["level_distribution"]
        assert len(summary["recent_entries"]) == 5
    
    def test_get_audit_summary_filtered(self, audit_trail):
        """Testa resumo de auditoria com filtros."""
        # Criar entradas de teste
        for i in range(3):
            audit_trail.create_audit_entry(
                service_name="target_service",
                log_level=LogSeverity.ERROR,
                message=f"Error message {i}",
                context={"index": i},
                tracing_id=f"filter_test_{i}"
            )
        
        # Criar entrada de outro serviço
        audit_trail.create_audit_entry(
            service_name="other_service",
            log_level=LogSeverity.ERROR,
            message="Other error",
            context={"other": True},
            tracing_id="filter_test_other"
        )
        
        # Obter resumo filtrado
        summary = audit_trail.get_audit_summary(service_name="target_service")
        
        # Verificar filtro
        assert summary["total_entries"] == 3
        assert "target_service" in summary["service_distribution"]
        assert "other_service" not in summary["service_distribution"]
    
    def test_export_audit_data_json(self, audit_trail):
        """Testa exportação de dados em formato JSON."""
        # Criar entradas de teste
        for i in range(2):
            audit_trail.create_audit_entry(
                service_name=f"export_service_{i}",
                log_level=LogSeverity.ERROR,
                message=f"Export error {i}",
                context={"export": True, "index": i},
                tracing_id=f"export_test_{i}"
            )
        
        # Exportar dados
        json_data = audit_trail.export_audit_data("json", include_hashes=True)
        
        # Verificar formato JSON
        data = json.loads(json_data)
        assert "audit_entries" in data
        assert "export_metadata" in data
        assert len(data["audit_entries"]) == 2
        assert data["export_metadata"]["total_entries"] == 2
        assert data["export_metadata"]["include_hashes"] is True
        
        # Verificar que hashes estão incluídos
        for entry in data["audit_entries"]:
            assert "original_hash" in entry
            assert "chain_hash" in entry
            assert len(entry["original_hash"]) == 64
            assert len(entry["chain_hash"]) == 64
    
    def test_export_audit_data_json_no_hashes(self, audit_trail):
        """Testa exportação JSON sem hashes."""
        # Criar entrada de teste
        audit_trail.create_audit_entry(
            service_name="no_hash_service",
            log_level=LogSeverity.ERROR,
            message="No hash error",
            context={"no_hash": True},
            tracing_id="no_hash_test"
        )
        
        # Exportar dados sem hashes
        json_data = audit_trail.export_audit_data("json", include_hashes=False)
        
        # Verificar que hashes não estão incluídos
        data = json.loads(json_data)
        for entry in data["audit_entries"]:
            assert "original_hash" not in entry
            assert "chain_hash" not in entry
    
    def test_export_audit_data_csv(self, audit_trail):
        """Testa exportação de dados em formato CSV."""
        # Criar entrada de teste
        audit_trail.create_audit_entry(
            service_name="csv_service",
            log_level=LogSeverity.ERROR,
            message="CSV error",
            context={"csv": True},
            tracing_id="csv_test"
        )
        
        # Exportar dados em CSV
        csv_data = audit_trail.export_audit_data("csv", include_hashes=True)
        
        # Verificar formato CSV
        lines = csv_data.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row
        
        # Verificar header
        header = lines[0]
        assert "entry_id" in header
        assert "timestamp" in header
        assert "service_name" in header
        assert "original_hash" in header
        assert "chain_hash" in header
    
    def test_export_audit_data_invalid_format(self, audit_trail):
        """Testa exportação com formato inválido."""
        with pytest.raises(ValueError, match="Formato não suportado"):
            audit_trail.export_audit_data("xml")
    
    def test_cleanup_old_entries(self, audit_trail):
        """Testa limpeza de entradas antigas."""
        # Criar entrada antiga (simular)
        old_entry = audit_trail.create_audit_entry(
            service_name="old_service",
            log_level=LogSeverity.ERROR,
            message="Old error",
            context={"old": True},
            tracing_id="old_test"
        )
        
        # Modificar timestamp para ser antiga
        old_entry.timestamp = datetime.utcnow() - timedelta(days=31)
        
        # Criar entrada recente
        recent_entry = audit_trail.create_audit_entry(
            service_name="recent_service",
            log_level=LogSeverity.ERROR,
            message="Recent error",
            context={"recent": True},
            tracing_id="recent_test"
        )
        
        # Verificar entradas antes da limpeza
        assert len(audit_trail.audit_entries) == 2
        
        # Limpar entradas antigas (manter 30 dias)
        audit_trail.cleanup_old_entries(days_to_keep=30)
        
        # Verificar que apenas entrada recente permaneceu
        assert len(audit_trail.audit_entries) == 1
        assert recent_entry.entry_id in audit_trail.audit_entries
        assert old_entry.entry_id not in audit_trail.audit_entries
    
    def test_get_entry_by_id(self, audit_trail):
        """Testa obtenção de entrada por ID."""
        # Criar entrada
        entry = audit_trail.create_audit_entry(
            service_name="get_service",
            log_level=LogSeverity.ERROR,
            message="Get error",
            context={"get": True},
            tracing_id="get_test"
        )
        
        # Obter entrada por ID
        retrieved_entry = audit_trail.get_entry_by_id(entry.entry_id)
        
        # Verificar que é a mesma entrada
        assert retrieved_entry is not None
        assert retrieved_entry.entry_id == entry.entry_id
        assert retrieved_entry.service_name == entry.service_name
        assert retrieved_entry.message == entry.message
    
    def test_get_entry_by_id_not_found(self, audit_trail):
        """Testa obtenção de entrada inexistente."""
        # Tentar obter entrada que não existe
        entry = audit_trail.get_entry_by_id("nonexistent_entry")
        
        assert entry is None
    
    def test_search_entries_by_service(self, audit_trail):
        """Testa busca de entradas por serviço."""
        # Criar entradas de diferentes serviços
        for i in range(3):
            audit_trail.create_audit_entry(
                service_name="target_service",
                log_level=LogSeverity.ERROR,
                message=f"Target error {i}",
                context={"target": True, "index": i},
                tracing_id=f"search_target_{i}"
            )
        
        audit_trail.create_audit_entry(
            service_name="other_service",
            log_level=LogSeverity.ERROR,
            message="Other error",
            context={"other": True},
            tracing_id="search_other"
        )
        
        # Buscar por serviço específico
        results = audit_trail.search_entries(service_name="target_service")
        
        # Verificar resultados
        assert len(results) == 3
        for result in results:
            assert result.service_name == "target_service"
    
    def test_search_entries_by_log_level(self, audit_trail):
        """Testa busca de entradas por nível de log."""
        # Criar entradas de diferentes níveis
        audit_trail.create_audit_entry(
            service_name="level_service",
            log_level=LogSeverity.ERROR,
            message="Error message",
            context={"level": "error"},
            tracing_id="search_error"
        )
        
        audit_trail.create_audit_entry(
            service_name="level_service",
            log_level=LogSeverity.CRITICAL,
            message="Critical message",
            context={"level": "critical"},
            tracing_id="search_critical"
        )
        
        # Buscar por nível específico
        results = audit_trail.search_entries(log_level=LogSeverity.ERROR)
        
        # Verificar resultados
        assert len(results) == 1
        assert results[0].log_level == LogSeverity.ERROR
    
    def test_search_entries_by_message_pattern(self, audit_trail):
        """Testa busca de entradas por padrão de mensagem."""
        # Criar entradas com diferentes mensagens
        audit_trail.create_audit_entry(
            service_name="pattern_service",
            log_level=LogSeverity.ERROR,
            message="Payment processing failed",
            context={"pattern": "payment"},
            tracing_id="search_payment"
        )
        
        audit_trail.create_audit_entry(
            service_name="pattern_service",
            log_level=LogSeverity.ERROR,
            message="Authentication successful",
            context={"pattern": "auth"},
            tracing_id="search_auth"
        )
        
        # Buscar por padrão
        results = audit_trail.search_entries(message_pattern="payment")
        
        # Verificar resultados
        assert len(results) == 1
        assert "payment" in results[0].message.lower()
    
    def test_search_entries_by_tracing_id(self, audit_trail):
        """Testa busca de entradas por tracing ID."""
        # Criar entrada com tracing ID específico
        audit_trail.create_audit_entry(
            service_name="tracing_service",
            log_level=LogSeverity.ERROR,
            message="Tracing error",
            context={"tracing": True},
            tracing_id="specific_trace_123"
        )
        
        # Buscar por tracing ID
        results = audit_trail.search_entries(tracing_id="specific_trace_123")
        
        # Verificar resultados
        assert len(results) == 1
        assert results[0].tracing_id == "specific_trace_123"
    
    def test_search_entries_with_limit(self, audit_trail):
        """Testa busca de entradas com limite."""
        # Criar múltiplas entradas
        for i in range(10):
            audit_trail.create_audit_entry(
                service_name="limit_service",
                log_level=LogSeverity.ERROR,
                message=f"Limit error {i}",
                context={"limit": True, "index": i},
                tracing_id=f"limit_test_{i}"
            )
        
        # Buscar com limite
        results = audit_trail.search_entries(limit=5)
        
        # Verificar limite
        assert len(results) == 5
    
    def test_hash_generation_consistency(self, audit_trail):
        """Testa consistência na geração de hashes."""
        # Criar entrada
        entry = audit_trail.create_audit_entry(
            service_name="hash_service",
            log_level=LogSeverity.ERROR,
            message="Hash test message",
            context={"hash_test": True},
            tracing_id="hash_test"
        )
        
        # Reconstruir conteúdo
        content = {
            "service_name": entry.service_name,
            "log_level": entry.log_level.value,
            "message": entry.message,
            "context": entry.context,
            "timestamp": entry.timestamp.isoformat(),
            "tracing_id": entry.tracing_id
        }
        
        content_json = json.dumps(content, sort_keys=True)
        expected_hash = hashlib.sha256(content_json.encode()).hexdigest()
        
        # Verificar que hash é consistente
        assert entry.original_hash == expected_hash
    
    def test_chain_linking_consistency(self, audit_trail):
        """Testa consistência no chain linking."""
        # Criar múltiplas entradas
        entries = []
        for i in range(3):
            entry = audit_trail.create_audit_entry(
                service_name=f"chain_service_{i}",
                log_level=LogSeverity.ERROR,
                message=f"Chain message {i}",
                context={"chain": True, "index": i},
                tracing_id=f"chain_test_{i}"
            )
            entries.append(entry)
        
        # Verificar chain linking
        for i in range(1, len(entries)):
            current_entry = entries[i]
            previous_entry = entries[i - 1]
            
            # Reconstruir chain hash esperado
            expected_chain_data = f"{previous_entry.chain_hash}:{current_entry.original_hash}:{current_entry.timestamp.isoformat()}"
            expected_chain_hash = hashlib.sha256(expected_chain_data.encode()).hexdigest()
            
            # Verificar que chain hash é consistente
            assert current_entry.chain_hash == expected_chain_hash
            assert current_entry.previous_hash == previous_entry.chain_hash


class TestAuditEntryDataClass:
    """Testes para a classe AuditEntry."""
    
    def test_audit_entry_creation(self):
        """Testa criação de AuditEntry com dados reais."""
        entry = AuditEntry(
            entry_id="test_entry_123",
            timestamp=datetime.utcnow(),
            service_name="test_service",
            log_level=LogSeverity.ERROR,
            message="Test error message",
            context={"test": True, "user_id": "user123"},
            original_hash="a" * 64,  # SHA-256 hex
            chain_hash="b" * 64,
            previous_hash="c" * 64,
            tracing_id="test_trace_123",
            environment="development",
            validation_status=HashValidationStatus.PENDING,
            validation_timestamp=None,
            validation_attempts=0,
            is_critical=True,
            requires_chain_validation=True
        )
        
        # Verificar estrutura
        assert entry.entry_id == "test_entry_123"
        assert entry.service_name == "test_service"
        assert entry.log_level == LogSeverity.ERROR
        assert entry.message == "Test error message"
        assert entry.context["test"] is True
        assert entry.context["user_id"] == "user123"
        assert len(entry.original_hash) == 64
        assert len(entry.chain_hash) == 64
        assert len(entry.previous_hash) == 64
        assert entry.tracing_id == "test_trace_123"
        assert entry.environment == "development"
        assert entry.validation_status == HashValidationStatus.PENDING
        assert entry.is_critical is True
        assert entry.requires_chain_validation is True


class TestChainValidationResultDataClass:
    """Testes para a classe ChainValidationResult."""
    
    def test_chain_validation_result_creation(self):
        """Testa criação de ChainValidationResult com dados reais."""
        result = ChainValidationResult(
            chain_id="chain_20250127_001",
            start_timestamp=datetime.utcnow() - timedelta(hours=1),
            end_timestamp=datetime.utcnow(),
            total_entries=10,
            valid_entries=9,
            invalid_entries=1,
            broken_links=["entry_123", "chain_link_456"],
            integrity_score=0.9,
            validation_status=HashValidationStatus.VALID,
            recommendations=["Investigar entrada com integridade comprometida"]
        )
        
        # Verificar estrutura
        assert result.chain_id == "chain_20250127_001"
        assert result.total_entries == 10
        assert result.valid_entries == 9
        assert result.invalid_entries == 1
        assert len(result.broken_links) == 2
        assert result.integrity_score == 0.9
        assert result.validation_status == HashValidationStatus.VALID
        assert len(result.recommendations) == 1 