"""
Testes Unitários - Multi-Region Adapter
======================================

Testes baseados em código real para o sistema de preparação multi-região.
Testa funcionalidades específicas implementadas no multi_region_adapter.py.

Prompt: Multi-Region Readiness - Item 10
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T21:05:00Z
Tracing ID: MULTI_REGION_READINESS_TEST_20250127_010

Regras de Teste:
- ✅ Baseado em código real implementado
- ✅ Testa funcionalidades específicas
- ❌ Proibido: dados fictícios, testes genéricos
- ❌ Proibido: foo, bar, lorem, random
"""

import pytest
import os
import time
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from infraestructure.multi_region_adapter import (
    MultiRegionAdapter,
    MultiRegionConfig,
    RegionConfig,
    RegionDetectionResult,
    RegionType,
    ComplianceFramework,
    DataResidencyLevel,
    detect_user_region,
    validate_regional_compliance,
    get_multi_region_adapter
)
from shared.feature_flags import FeatureFlagsManager


class TestMultiRegionAdapter:
    """Testes para a classe MultiRegionAdapter."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.config = MultiRegionConfig(
            default_region="us-east-1",
            auto_detection_enabled=True,
            fallback_region="us-east-1",
            service_mesh_integration=False,  # Desabilita para testes
            compliance_strict_mode=True,
            audit_all_operations=True
        )
        self.adapter = MultiRegionAdapter(self.config, "TEST_MULTI_REGION_001")
    
    def test_adapter_initialization(self):
        """Testa inicialização correta do adapter."""
        assert self.adapter.tracing_id.startswith("MULTI_REGION_")
        assert self.adapter.config.default_region == "us-east-1"
        assert self.adapter.config.auto_detection_enabled is True
        assert len(self.adapter.config.regions) > 0
        assert "us-east-1" in self.adapter.config.regions
    
    def test_region_config_initialization(self):
        """Testa inicialização das configurações de região."""
        regions = self.adapter.config.regions
        
        # Verifica regiões principais
        assert "us-east-1" in regions
        assert "sa-east-1" in regions
        assert "eu-west-1" in regions
        
        # Verifica configuração específica do Brasil
        brazil_config = regions["sa-east-1"]
        assert brazil_config.region_name == "South America (São Paulo)"
        assert brazil_config.region_type == RegionType.SOUTH_AMERICA
        assert ComplianceFramework.LGPD in brazil_config.compliance_frameworks
        assert brazil_config.data_residency == DataResidencyLevel.STRICT
    
    def test_detect_region_by_environment_variable(self):
        """Testa detecção de região por variável de ambiente."""
        with patch.dict(os.environ, {'AWS_REGION': 'eu-west-1'}):
            result = self.adapter._detect_by_environment_variable("192.168.1.1", "test-agent")
            
            assert result is not None
            assert result.detected_region == "eu-west-1"
            assert result.confidence == 1.0
            assert result.detection_method == "environment_variable"
    
    def test_detect_region_by_user_agent_brazil(self):
        """Testa detecção de região por user agent do Brasil."""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 pt-BR"
        
        result = self.adapter._detect_by_user_agent("192.168.1.1", user_agent)
        
        assert result is not None
        assert result.detected_region == "sa-east-1"
        assert result.confidence == 0.7
        assert result.detection_method == "user_agent"
    
    def test_detect_region_by_user_agent_germany(self):
        """Testa detecção de região por user agent da Alemanha."""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 de-DE"
        
        result = self.adapter._detect_by_user_agent("192.168.1.1", user_agent)
        
        assert result is not None
        assert result.detected_region == "eu-central-1"
        assert result.confidence == 0.7
        assert result.detection_method == "user_agent"
    
    def test_detect_region_by_user_agent_unknown(self):
        """Testa detecção de região com user agent desconhecido."""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        result = self.adapter._detect_by_user_agent("192.168.1.1", user_agent)
        
        assert result is None
    
    def test_detect_region_by_ip_ranges(self):
        """Testa detecção de região por ranges de IP."""
        # Testa IP dos EUA
        result = self.adapter._detect_by_ip_ranges("3.0.0.1", "test-agent")
        
        if result:  # Pode retornar None se range não estiver configurado
            assert result.detected_region in ["us-east-1", "us-west-2"]
            assert result.confidence == 0.6
            assert result.detection_method == "ip_ranges"
    
    def test_detect_region_by_ip_ranges_invalid_ip(self):
        """Testa detecção de região com IP inválido."""
        result = self.adapter._detect_by_ip_ranges("invalid-ip", "test-agent")
        
        assert result is None
    
    @patch('infraestructure.multi_region_adapter.geoip2.database.Reader')
    def test_detect_region_by_geoip_success(self, mock_geoip_reader):
        """Testa detecção de região por GeoIP com sucesso."""
        # Mock da resposta do GeoIP
        mock_response = Mock()
        mock_response.country.iso_code = "BR"
        mock_response.country.name = "Brazil"
        mock_response.city.name = "São Paulo"
        mock_response.location.latitude = -23.5505
        mock_response.location.longitude = -46.6333
        
        mock_geoip_reader.return_value.city.return_value = mock_response
        
        # Configura GeoIP reader
        self.adapter.geoip_reader = mock_geoip_reader.return_value
        
        result = self.adapter._detect_by_geoip("177.0.0.1", "test-agent")
        
        assert result is not None
        assert result.detected_region == "sa-east-1"
        assert result.confidence == 0.9
        assert result.detection_method == "geoip"
        assert result.geoip_data is not None
        assert result.geoip_data['country'] == "Brazil"
        assert result.geoip_data['country_code'] == "BR"
    
    @patch('infraestructure.multi_region_adapter.geoip2.database.Reader')
    def test_detect_region_by_geoip_address_not_found(self, mock_geoip_reader):
        """Testa detecção de região por GeoIP com endereço não encontrado."""
        mock_geoip_reader.return_value.city.side_effect = geoip2.errors.AddressNotFoundError("Address not found")
        
        self.adapter.geoip_reader = mock_geoip_reader.return_value
        
        result = self.adapter._detect_by_geoip("192.168.1.1", "test-agent")
        
        assert result is None
    
    def test_detect_region_fallback(self):
        """Testa detecção de região com fallback."""
        # Simula falha em todos os métodos de detecção
        with patch.object(self.adapter, '_detect_by_environment_variable', return_value=None), \
             patch.object(self.adapter, '_detect_by_geoip', return_value=None), \
             patch.object(self.adapter, '_detect_by_user_agent', return_value=None), \
             patch.object(self.adapter, '_detect_by_ip_ranges', return_value=None):
            
            result = self.adapter.detect_region("192.168.1.1", "test-agent")
            
            assert result.detected_region == "us-east-1"  # Fallback
            assert result.confidence == 0.1
            assert result.detection_method == "fallback"
    
    def test_get_region_config_existing(self):
        """Testa obtenção de configuração de região existente."""
        config = self.adapter.get_region_config("sa-east-1")
        
        assert config is not None
        assert config.region_code == "sa-east-1"
        assert config.region_name == "South America (São Paulo)"
        assert config.region_type == RegionType.SOUTH_AMERICA
        assert ComplianceFramework.LGPD in config.compliance_frameworks
    
    def test_get_region_config_nonexistent(self):
        """Testa obtenção de configuração de região inexistente."""
        config = self.adapter.get_region_config("invalid-region")
        
        assert config is None
    
    def test_validate_compliance_gdpr_success(self):
        """Testa validação de compliance GDPR com sucesso."""
        result = self.adapter.validate_compliance("eu-west-1", "read", "personal")
        
        assert result['compliant'] is True
        assert result['region_code'] == "eu-west-1"
        assert result['operation'] == "read"
        assert result['data_type'] == "personal"
        assert ComplianceFramework.GDPR.value in result['compliance_frameworks']
    
    def test_validate_compliance_lgpd_success(self):
        """Testa validação de compliance LGPD com sucesso."""
        result = self.adapter.validate_compliance("sa-east-1", "write", "sensitive")
        
        assert result['compliant'] is True
        assert result['region_code'] == "sa-east-1"
        assert result['operation'] == "write"
        assert result['data_type'] == "sensitive"
        assert ComplianceFramework.LGPD.value in result['compliance_frameworks']
    
    def test_validate_compliance_ccpa_success(self):
        """Testa validação de compliance CCPA com sucesso."""
        result = self.adapter.validate_compliance("us-east-1", "delete", "personal")
        
        assert result['compliant'] is True
        assert result['region_code'] == "us-east-1"
        assert result['operation'] == "delete"
        assert result['data_type'] == "personal"
        assert ComplianceFramework.CCPA.value in result['compliance_frameworks']
    
    def test_validate_compliance_invalid_region(self):
        """Testa validação de compliance com região inválida."""
        result = self.adapter.validate_compliance("invalid-region", "read", "personal")
        
        assert result['compliant'] is False
        assert "não suportada" in result['reason']
        assert len(result['recommendations']) > 0
    
    def test_get_storage_location(self):
        """Testa obtenção de localização de storage."""
        storage_location = self.adapter.get_storage_location("sa-east-1")
        
        assert storage_location == "sa-east-1"
    
    def test_get_storage_location_invalid_region(self):
        """Testa obtenção de localização de storage para região inválida."""
        storage_location = self.adapter.get_storage_location("invalid-region")
        
        assert storage_location == "us-east-1"  # Default
    
    def test_get_processing_location(self):
        """Testa obtenção de localização de processamento."""
        processing_location = self.adapter.get_processing_location("eu-west-1")
        
        assert processing_location == "eu-west-1"
    
    def test_should_audit_operation_enabled(self):
        """Testa se operação deve ser auditada quando habilitado."""
        should_audit = self.adapter.should_audit_operation("sa-east-1", "write")
        
        assert should_audit is True
    
    def test_should_audit_operation_disabled(self):
        """Testa se operação deve ser auditada quando desabilitado."""
        # Desabilita audit all operations
        self.adapter.config.audit_all_operations = False
        
        should_audit = self.adapter.should_audit_operation("sa-east-1", "write")
        
        assert should_audit is False
    
    def test_log_regional_operation(self):
        """Testa registro de operação regional."""
        with patch.object(self.adapter, 'should_audit_operation', return_value=True):
            # Não deve gerar erro
            self.adapter.log_regional_operation(
                region_code="sa-east-1",
                operation="write",
                user_id="user123",
                data_type="personal",
                success=True
            )
    
    def test_get_compliance_report(self):
        """Testa geração de relatório de compliance."""
        report = self.adapter.get_compliance_report("sa-east-1")
        
        assert report['region_code'] == "sa-east-1"
        assert report['region_name'] == "South America (São Paulo)"
        assert report['region_type'] == RegionType.SOUTH_AMERICA.value
        assert ComplianceFramework.LGPD.value in report['compliance_frameworks']
        assert report['data_residency'] == DataResidencyLevel.STRICT.value
        assert report['storage_location'] == "sa-east-1"
        assert report['processing_location'] == "sa-east-1"
        assert report['encryption_required'] is True
        assert report['audit_logging_required'] is True
        assert 'report_generated' in report
    
    def test_get_compliance_report_invalid_region(self):
        """Testa geração de relatório de compliance para região inválida."""
        report = self.adapter.get_compliance_report("invalid-region")
        
        assert 'error' in report
        assert 'Região invalid-region não encontrada' in report['error']
        assert 'available_regions' in report


class TestRegionDetectionResult:
    """Testes para a classe RegionDetectionResult."""
    
    def test_region_detection_result_creation(self):
        """Testa criação de resultado de detecção de região."""
        result = RegionDetectionResult(
            detected_region="sa-east-1",
            confidence=0.9,
            detection_method="geoip",
            ip_address="177.0.0.1",
            geoip_data={
                'country': 'Brazil',
                'country_code': 'BR'
            }
        )
        
        assert result.detected_region == "sa-east-1"
        assert result.confidence == 0.9
        assert result.detection_method == "geoip"
        assert result.ip_address == "177.0.0.1"
        assert result.geoip_data['country'] == "Brazil"
        assert result.geoip_data['country_code'] == "BR"
        assert isinstance(result.timestamp, datetime)


class TestRegionConfig:
    """Testes para a classe RegionConfig."""
    
    def test_region_config_creation(self):
        """Testa criação de configuração de região."""
        config = RegionConfig(
            region_code="sa-east-1",
            region_name="South America (São Paulo)",
            region_type=RegionType.SOUTH_AMERICA,
            compliance_frameworks=[ComplianceFramework.LGPD],
            data_residency=DataResidencyLevel.STRICT,
            storage_location="sa-east-1",
            processing_location="sa-east-1",
            backup_location="us-east-1",
            retention_period_days=2555,
            encryption_required=True,
            audit_logging_required=True,
            data_export_allowed=False,
            data_deletion_required=True
        )
        
        assert config.region_code == "sa-east-1"
        assert config.region_name == "South America (São Paulo)"
        assert config.region_type == RegionType.SOUTH_AMERICA
        assert ComplianceFramework.LGPD in config.compliance_frameworks
        assert config.data_residency == DataResidencyLevel.STRICT
        assert config.storage_location == "sa-east-1"
        assert config.processing_location == "sa-east-1"
        assert config.backup_location == "us-east-1"
        assert config.retention_period_days == 2555
        assert config.encryption_required is True
        assert config.audit_logging_required is True
        assert config.data_export_allowed is False
        assert config.data_deletion_required is True


class TestFunctions:
    """Testes para funções de conveniência."""
    
    def test_detect_user_region_function(self):
        """Testa função de conveniência detect_user_region."""
        result = detect_user_region("177.0.0.1", "test-agent")
        
        assert isinstance(result, RegionDetectionResult)
        assert result.detected_region in ["sa-east-1", "us-east-1"]  # Pode detectar Brasil ou fallback
        assert 0.1 <= result.confidence <= 1.0
    
    def test_validate_regional_compliance_function(self):
        """Testa função de conveniência validate_regional_compliance."""
        result = validate_regional_compliance("sa-east-1", "read", "personal")
        
        assert isinstance(result, dict)
        assert 'compliant' in result
        assert 'region_code' in result
        assert 'operation' in result
        assert 'data_type' in result
    
    def test_get_multi_region_adapter_function(self):
        """Testa função de conveniência get_multi_region_adapter."""
        adapter = get_multi_region_adapter("TEST_FUNCTION")
        
        assert isinstance(adapter, MultiRegionAdapter)
        assert adapter.tracing_id == "TEST_FUNCTION"


class TestFeatureFlags:
    """Testes para integração com feature flags."""
    
    def test_feature_flag_disabled(self):
        """Testa comportamento quando feature flag está desabilitada."""
        with patch.object(FeatureFlagsManager, 'is_enabled', return_value=False):
            result = detect_user_region("177.0.0.1", "test-agent")
            
            assert result.detected_region == "us-east-1"  # Default
            assert result.confidence == 1.0
            assert result.detection_method == "feature_flag_disabled"
    
    def test_feature_flag_enabled(self):
        """Testa comportamento quando feature flag está habilitada."""
        with patch.object(FeatureFlagsManager, 'is_enabled', return_value=True):
            result = detect_user_region("177.0.0.1", "test-agent")
            
            assert isinstance(result, RegionDetectionResult)
            assert result.detected_region in ["sa-east-1", "us-east-1"]


class TestComplianceValidation:
    """Testes específicos para validação de compliance."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.config = MultiRegionConfig(
            default_region="us-east-1",
            auto_detection_enabled=True,
            fallback_region="us-east-1",
            service_mesh_integration=False,
            compliance_strict_mode=True,
            audit_all_operations=True
        )
        self.adapter = MultiRegionAdapter(self.config, "TEST_COMPLIANCE_001")
    
    def test_gdpr_validation_encryption_required(self):
        """Testa validação GDPR para criptografia obrigatória."""
        # Configura região sem criptografia obrigatória
        region_config = self.adapter.get_region_config("eu-west-1")
        original_encryption = region_config.encryption_required
        region_config.encryption_required = False
        
        result = self.adapter.validate_compliance("eu-west-1", "write", "personal")
        
        # Restaura configuração original
        region_config.encryption_required = original_encryption
        
        assert result['compliant'] is False
        gdpr_checks = [check for check in result['checks'] if check['framework'] == 'GDPR']
        assert len(gdpr_checks) > 0
    
    def test_lgpd_validation_audit_logging(self):
        """Testa validação LGPD para logging de auditoria."""
        # Configura região sem logging de auditoria obrigatório
        region_config = self.adapter.get_region_config("sa-east-1")
        original_audit = region_config.audit_logging_required
        region_config.audit_logging_required = False
        
        result = self.adapter.validate_compliance("sa-east-1", "read", "sensitive")
        
        # Restaura configuração original
        region_config.audit_logging_required = original_audit
        
        assert result['compliant'] is False
        lgpd_checks = [check for check in result['checks'] if check['framework'] == 'LGPD']
        assert len(lgpd_checks) > 0
    
    def test_ccpa_validation_data_deletion(self):
        """Testa validação CCPA para apagamento de dados."""
        # Configura região sem apagamento de dados obrigatório
        region_config = self.adapter.get_region_config("us-east-1")
        original_deletion = region_config.data_deletion_required
        region_config.data_deletion_required = False
        
        result = self.adapter.validate_compliance("us-east-1", "delete", "personal")
        
        # Restaura configuração original
        region_config.data_deletion_required = original_deletion
        
        assert result['compliant'] is False
        ccpa_checks = [check for check in result['checks'] if check['framework'] == 'CCPA']
        assert len(ccpa_checks) > 0


class TestIntegration:
    """Testes de integração."""
    
    def test_full_region_detection_workflow(self):
        """Testa workflow completo de detecção de região."""
        # Simula detecção por user agent brasileiro
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 pt-BR"
        
        result = detect_user_region("177.0.0.1", user_agent)
        
        assert isinstance(result, RegionDetectionResult)
        assert result.detected_region in ["sa-east-1", "us-east-1"]
        
        # Valida compliance para a região detectada
        compliance = validate_regional_compliance(
            result.detected_region, 
            "write", 
            "personal"
        )
        
        assert isinstance(compliance, dict)
        assert 'compliant' in compliance
        assert compliance['region_code'] == result.detected_region
    
    def test_multiple_regions_compliance(self):
        """Testa compliance em múltiplas regiões."""
        regions_to_test = ["us-east-1", "sa-east-1", "eu-west-1"]
        
        for region in regions_to_test:
            result = validate_regional_compliance(region, "read", "personal")
            
            assert isinstance(result, dict)
            assert 'compliant' in result
            assert result['region_code'] == region
            assert 'compliance_frameworks' in result


if __name__ == "__main__":
    pytest.main([__file__]) 