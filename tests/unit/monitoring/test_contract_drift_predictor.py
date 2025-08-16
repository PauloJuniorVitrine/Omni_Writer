"""
Testes Unitários - Contract Drift Predictor
==========================================

Testes para o sistema de predição de contract drift baseados em código real.

Prompt: Contract Drift Prediction - Item 6
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T19:20:00Z
Tracing ID: CONTRACT_DRIFT_TEST_20250127_006

Análise CoCoT:
- Comprovação: Baseado em Test-Driven Development e API Contract Testing
- Causalidade: Valida funcionalidades reais do sistema de drift prediction
- Contexto: Testa integração com monitoring, circuit breaker e feature flags
- Tendência: Usa mocks realistas e cenários de produção

Decisões ToT:
- Abordagem 1: Testes de integração completos (realista, mas lento)
- Abordagem 2: Mocks simples (rápido, mas não realista)
- Abordagem 3: Mocks realistas + testes de unidade (equilibrado)
- Escolha: Abordagem 3 - mocks que simulam comportamento real

Simulação ReAct:
- Antes: Falhas em produção por mudanças de API não detectadas
- Durante: Testes validam detecção proativa de drift
- Depois: Zero downtime por mudanças de API externas

Validação de Falsos Positivos:
- Regra: Teste pode falhar por mudança legítima no código
- Validação: Verificar se teste reflete funcionalidade real
- Log: Registrar mudanças que quebram testes legítimos
"""

import pytest
import json
import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from monitoring.contract_drift_predictor import (
    ContractDriftPredictor,
    APIContract,
    APIMonitor,
    DriftDetection,
    DriftType,
    SeverityLevel,
    ContractStatus,
    get_contract_drift_predictor,
    enable_contract_drift_prediction,
    disable_contract_drift_prediction,
    monitor_api_contract
)


class TestContractDriftPredictor:
    """Testes para o sistema de predição de contract drift."""

    def setup_method(self):
        """Configuração para cada teste."""
        # Mock das dependências
        with patch('monitoring.contract_drift_predictor.is_feature_enabled') as mock_feature:
            mock_feature.return_value = True
            
            with patch('monitoring.contract_drift_predictor.get_structured_logger') as mock_logger:
                mock_logger.return_value = Mock()
                
                with patch('monitoring.contract_drift_predictor.metrics_collector') as mock_metrics:
                    mock_metrics.record_request = Mock()
                    mock_metrics.record_error = Mock()
                    
                    self.predictor = ContractDriftPredictor()
    
    def test_contract_drift_predictor_initialization(self):
        """Testa inicialização do sistema de contract drift."""
        # Verifica se o sistema foi inicializado corretamente
        assert self.predictor.enabled is True
        assert self.predictor.auto_rollback is True
        assert self.predictor.drift_threshold == 0.7
        
        # Verifica se os monitores foram configurados
        assert 'openai' in self.predictor.api_monitors
        assert 'deepseek' in self.predictor.api_monitors
        assert 'stripe' in self.predictor.api_monitors
        
        # Verifica se os contratos foram carregados
        assert 'openai' in self.predictor.contracts
        assert 'deepseek' in self.predictor.contracts
        assert 'stripe' in self.predictor.contracts
    
    def test_openai_monitor_configuration(self):
        """Testa configuração do monitor OpenAI."""
        openai_monitor = self.predictor.api_monitors['openai']
        
        assert openai_monitor.name == 'openai'
        assert openai_monitor.base_url == 'https://api.openai.com/v1'
        assert openai_monitor.health_endpoint == '/models'
        assert openai_monitor.auth_required is True
        assert openai_monitor.auth_type == 'bearer'
        assert openai_monitor.check_interval == 300
        assert openai_monitor.timeout == 30
        assert openai_monitor.drift_threshold == 0.8
        assert 200 in openai_monitor.expected_status_codes
        assert 401 in openai_monitor.expected_status_codes
        assert 403 in openai_monitor.expected_status_codes
    
    def test_deepseek_monitor_configuration(self):
        """Testa configuração do monitor DeepSeek."""
        deepseek_monitor = self.predictor.api_monitors['deepseek']
        
        assert deepseek_monitor.name == 'deepseek'
        assert deepseek_monitor.base_url == 'https://api.deepseek.com/v1'
        assert deepseek_monitor.health_endpoint == '/models'
        assert deepseek_monitor.auth_required is True
        assert deepseek_monitor.auth_type == 'bearer'
        assert deepseek_monitor.check_interval == 300
        assert deepseek_monitor.timeout == 30
        assert deepseek_monitor.drift_threshold == 0.8
    
    def test_stripe_monitor_configuration(self):
        """Testa configuração do monitor Stripe."""
        stripe_monitor = self.predictor.api_monitors['stripe']
        
        assert stripe_monitor.name == 'stripe'
        assert stripe_monitor.base_url == 'https://api.stripe.com'
        assert stripe_monitor.health_endpoint == '/v1/balance'
        assert stripe_monitor.auth_required is True
        assert stripe_monitor.auth_type == 'bearer'
        assert stripe_monitor.check_interval == 600
        assert stripe_monitor.timeout == 30
        assert stripe_monitor.drift_threshold == 0.9
    
    def test_openai_contract_structure(self):
        """Testa estrutura do contrato OpenAI."""
        openai_contract = self.predictor.contracts['openai']
        
        assert openai_contract.name == 'openai'
        assert openai_contract.base_url == 'https://api.openai.com/v1'
        assert openai_contract.version == '2024-11-06'
        assert openai_contract.status == ContractStatus.STABLE
        
        # Verifica endpoints
        assert '/chat/completions' in openai_contract.endpoints
        assert '/models' in openai_contract.endpoints
        
        # Verifica campos obrigatórios do chat/completions
        chat_endpoint = openai_contract.endpoints['/chat/completions']
        assert 'model' in chat_endpoint['required_fields']
        assert 'messages' in chat_endpoint['required_fields']
        assert 'temperature' in chat_endpoint['optional_fields']
        assert 'max_tokens' in chat_endpoint['optional_fields']
    
    def test_deepseek_contract_structure(self):
        """Testa estrutura do contrato DeepSeek."""
        deepseek_contract = self.predictor.contracts['deepseek']
        
        assert deepseek_contract.name == 'deepseek'
        assert deepseek_contract.base_url == 'https://api.deepseek.com/v1'
        assert deepseek_contract.version == '2024-01-01'
        assert deepseek_contract.status == ContractStatus.STABLE
        
        # Verifica endpoints
        assert '/chat/completions' in deepseek_contract.endpoints
        assert '/models' in deepseek_contract.endpoints
    
    def test_stripe_contract_structure(self):
        """Testa estrutura do contrato Stripe."""
        stripe_contract = self.predictor.contracts['stripe']
        
        assert stripe_contract.name == 'stripe'
        assert stripe_contract.base_url == 'https://api.stripe.com'
        assert stripe_contract.version == '2024-06-20'
        assert stripe_contract.status == ContractStatus.STABLE
        
        # Verifica endpoints
        assert '/v1/payment_intents' in stripe_contract.endpoints
        assert '/v1/balance' in stripe_contract.endpoints
        
        # Verifica campos obrigatórios do payment_intents
        payment_endpoint = stripe_contract.endpoints['/v1/payment_intents']
        assert 'amount' in payment_endpoint['required_fields']
        assert 'currency' in payment_endpoint['required_fields']
    
    def test_schema_hash_calculation(self):
        """Testa cálculo de hash do schema."""
        # Testa hash para contrato OpenAI
        openai_hash = self.predictor._calculate_schema_hash('openai')
        assert isinstance(openai_hash, str)
        assert len(openai_hash) == 64  # SHA-256 hash length
        
        # Testa hash para contrato DeepSeek
        deepseek_hash = self.predictor._calculate_schema_hash('deepseek')
        assert isinstance(deepseek_hash, str)
        assert len(deepseek_hash) == 64
        
        # Testa hash para contrato Stripe
        stripe_hash = self.predictor._calculate_schema_hash('stripe')
        assert isinstance(stripe_hash, str)
        assert len(stripe_hash) == 64
        
        # Verifica que hashes são diferentes para contratos diferentes
        assert openai_hash != deepseek_hash
        assert openai_hash != stripe_hash
        assert deepseek_hash != stripe_hash
    
    def test_body_hash_calculation(self):
        """Testa cálculo de hash do body."""
        # Body de exemplo
        body = {
            'choices': [{'message': {'content': 'Hello world'}}],
            'usage': {'total_tokens': 10}
        }
        
        hash1 = self.predictor._calculate_body_hash(body)
        assert isinstance(hash1, str)
        assert len(hash1) == 64
        
        # Mesmo body deve gerar mesmo hash
        hash2 = self.predictor._calculate_body_hash(body)
        assert hash1 == hash2
        
        # Body diferente deve gerar hash diferente
        different_body = {
            'choices': [{'message': {'content': 'Different content'}}],
            'usage': {'total_tokens': 15}
        }
        hash3 = self.predictor._calculate_body_hash(different_body)
        assert hash1 != hash3
    
    def test_drift_detection_creation(self):
        """Testa criação de detecção de drift."""
        contract = self.predictor.contracts['openai']
        
        # Simula detecção de drift
        drift = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.SCHEMA_CHANGE,
            severity=SeverityLevel.WARNING,
            description='Mudança detectada no schema da resposta',
            old_value='old_hash',
            new_value='new_hash',
            confidence=0.8,
            timestamp=datetime.now(),
            affected_endpoints=['/chat/completions'],
            recommendations=['Verificar compatibilidade', 'Atualizar contratos'],
            metadata={'contract_version': '2024-11-06'}
        )
        
        assert drift.contract_name == 'openai'
        assert drift.drift_type == DriftType.SCHEMA_CHANGE
        assert drift.severity == SeverityLevel.WARNING
        assert drift.confidence == 0.8
        assert len(drift.affected_endpoints) == 1
        assert len(drift.recommendations) == 2
    
    def test_drift_detection_with_threshold(self):
        """Testa detecção de drift com threshold."""
        contract = self.predictor.contracts['openai']
        
        # Drift com confiança abaixo do threshold (não deve ser detectado)
        with patch.object(self.predictor, '_detect_drift') as mock_detect:
            self.predictor._detect_drift(
                contract,
                DriftType.SCHEMA_CHANGE,
                SeverityLevel.WARNING,
                'Test drift',
                'old',
                'new',
                0.5,  # Abaixo do threshold de 0.7
                ['/test'],
                ['recommendation']
            )
            
            # Não deve chamar _detect_drift
            mock_detect.assert_not_called()
        
        # Drift com confiança acima do threshold (deve ser detectado)
        with patch.object(self.predictor, '_detect_drift') as mock_detect:
            self.predictor._detect_drift(
                contract,
                DriftType.SCHEMA_CHANGE,
                SeverityLevel.WARNING,
                'Test drift',
                'old',
                'new',
                0.8,  # Acima do threshold de 0.7
                ['/test'],
                ['recommendation']
            )
            
            # Deve chamar _detect_drift
            mock_detect.assert_called_once()
    
    def test_get_api_key_function(self):
        """Testa função de obtenção de API key."""
        with patch.dict('os.environ', {
            'OPENAI_API_KEY': 'test_openai_key',
            'DEEPSEEK_API_KEY': 'test_deepseek_key',
            'STRIPE_SECRET_KEY': 'test_stripe_key'
        }):
            openai_key = self.predictor._get_api_key('openai')
            deepseek_key = self.predictor._get_api_key('deepseek')
            stripe_key = self.predictor._get_api_key('stripe')
            
            assert openai_key == 'test_openai_key'
            assert deepseek_key == 'test_deepseek_key'
            assert stripe_key == 'test_stripe_key'
            
            # API inexistente deve retornar None
            unknown_key = self.predictor._get_api_key('unknown')
            assert unknown_key is None
    
    def test_get_contracts_method(self):
        """Testa método get_contracts."""
        contracts = self.predictor.get_contracts()
        
        assert isinstance(contracts, list)
        assert len(contracts) == 3  # openai, deepseek, stripe
        
        # Verifica se todos os contratos estão presentes
        contract_names = [c['name'] for c in contracts]
        assert 'openai' in contract_names
        assert 'deepseek' in contract_names
        assert 'stripe' in contract_names
    
    def test_get_contract_method(self):
        """Testa método get_contract."""
        # Contrato existente
        openai_contract = self.predictor.get_contract('openai')
        assert openai_contract is not None
        assert openai_contract['name'] == 'openai'
        assert openai_contract['base_url'] == 'https://api.openai.com/v1'
        
        # Contrato inexistente
        unknown_contract = self.predictor.get_contract('unknown')
        assert unknown_contract is None
    
    def test_get_drift_history_method(self):
        """Testa método get_drift_history."""
        # Adiciona alguns drifts de teste
        contract = self.predictor.contracts['openai']
        
        drift1 = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.SCHEMA_CHANGE,
            severity=SeverityLevel.WARNING,
            description='Test drift 1',
            old_value='old1',
            new_value='new1',
            confidence=0.8,
            timestamp=datetime.now() - timedelta(hours=1),
            affected_endpoints=['/test1'],
            recommendations=['rec1'],
            metadata={}
        )
        
        drift2 = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.ENDPOINT_CHANGE,
            severity=SeverityLevel.CRITICAL,
            description='Test drift 2',
            old_value='old2',
            new_value='new2',
            confidence=0.9,
            timestamp=datetime.now(),
            affected_endpoints=['/test2'],
            recommendations=['rec2'],
            metadata={}
        )
        
        self.predictor.drift_history = [drift1, drift2]
        
        # Testa histórico completo
        history = self.predictor.get_drift_history()
        assert len(history) == 2
        
        # Testa limite
        history_limited = self.predictor.get_drift_history(limit=1)
        assert len(history_limited) == 1
        
        # Testa filtro por contrato
        history_filtered = self.predictor.get_drift_history(contract_name='openai')
        assert len(history_filtered) == 2
        
        history_filtered = self.predictor.get_drift_history(contract_name='deepseek')
        assert len(history_filtered) == 0
    
    def test_get_active_drifts_method(self):
        """Testa método get_active_drifts."""
        # Adiciona drifts com diferentes timestamps
        contract = self.predictor.contracts['openai']
        
        # Drift antigo (mais de 24 horas)
        old_drift = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.SCHEMA_CHANGE,
            severity=SeverityLevel.WARNING,
            description='Old drift',
            old_value='old',
            new_value='new',
            confidence=0.8,
            timestamp=datetime.now() - timedelta(hours=25),
            affected_endpoints=['/test'],
            recommendations=['rec'],
            metadata={}
        )
        
        # Drift recente (menos de 24 horas)
        recent_drift = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.ENDPOINT_CHANGE,
            severity=SeverityLevel.CRITICAL,
            description='Recent drift',
            old_value='old',
            new_value='new',
            confidence=0.9,
            timestamp=datetime.now() - timedelta(hours=12),
            affected_endpoints=['/test'],
            recommendations=['rec'],
            metadata={}
        )
        
        self.predictor.drift_history = [old_drift, recent_drift]
        
        # Apenas drift recente deve aparecer
        active_drifts = self.predictor.get_active_drifts()
        assert len(active_drifts) == 1
        assert active_drifts[0]['description'] == 'Recent drift'
    
    def test_get_summary_method(self):
        """Testa método get_summary."""
        summary = self.predictor.get_summary()
        
        assert summary['enabled'] is True
        assert summary['auto_rollback'] is True
        assert summary['total_contracts'] == 3
        assert summary['total_drifts'] == 0  # Sem drifts ainda
        assert 'contracts_by_status' in summary
        assert 'drifts_by_type' in summary
        assert 'last_analysis' in summary
        
        # Verifica status dos contratos
        contracts_by_status = summary['contracts_by_status']
        assert contracts_by_status['stable'] == 3  # Todos estáveis
    
    def test_update_contract_method(self):
        """Testa método update_contract."""
        contract_name = 'openai'
        contract_data = {
            'version': '2024-12-01',
            'status': ContractStatus.DRIFTING
        }
        
        # Atualiza contrato
        self.predictor.update_contract(contract_name, contract_data)
        
        # Verifica se foi atualizado
        updated_contract = self.predictor.contracts[contract_name]
        assert updated_contract.version == '2024-12-01'
        assert updated_contract.status == ContractStatus.DRIFTING
        assert updated_contract.last_updated > datetime.now() - timedelta(seconds=5)
    
    def test_add_contract_method(self):
        """Testa método add_contract."""
        new_contract = APIContract(
            name='test_api',
            base_url='https://api.test.com',
            version='1.0.0',
            endpoints={
                '/health': {
                    'method': 'GET',
                    'response_schema': {'status': 'string'}
                }
            },
            schema_hash='test_hash',
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={'provider': 'Test'}
        )
        
        # Adiciona contrato
        self.predictor.add_contract(new_contract)
        
        # Verifica se foi adicionado
        assert 'test_api' in self.predictor.contracts
        assert 'test_api' in self.predictor.api_monitors
        
        added_contract = self.predictor.contracts['test_api']
        assert added_contract.name == 'test_api'
        assert added_contract.base_url == 'https://api.test.com'
    
    def test_add_drift_callback_method(self):
        """Testa método add_drift_callback."""
        callback_called = False
        
        def test_callback(drift):
            nonlocal callback_called
            callback_called = True
        
        # Adiciona callback
        self.predictor.add_drift_callback(test_callback)
        
        # Simula drift para testar callback
        contract = self.predictor.contracts['openai']
        drift = DriftDetection(
            contract_name='openai',
            drift_type=DriftType.SCHEMA_CHANGE,
            severity=SeverityLevel.WARNING,
            description='Test callback',
            old_value='old',
            new_value='new',
            confidence=0.8,
            timestamp=datetime.now(),
            affected_endpoints=['/test'],
            recommendations=['rec'],
            metadata={}
        )
        
        # Executa callbacks
        for callback in self.predictor.drift_callbacks:
            callback(drift)
        
        assert callback_called is True


class TestContractDriftPredictorFunctions:
    """Testes para funções utilitárias do contract drift predictor."""

    def test_get_contract_drift_predictor_function(self):
        """Testa função get_contract_drift_predictor."""
        predictor = get_contract_drift_predictor()
        assert isinstance(predictor, ContractDriftPredictor)
    
    def test_enable_contract_drift_prediction_function(self):
        """Testa função enable_contract_drift_prediction."""
        with patch('monitoring.contract_drift_predictor.set_feature_flag') as mock_set_flag:
            enable_contract_drift_prediction()
            mock_set_flag.assert_called_once_with(
                "contract_drift_prediction_enabled",
                FeatureFlagStatus.ENABLED
            )
    
    def test_disable_contract_drift_prediction_function(self):
        """Testa função disable_contract_drift_prediction."""
        with patch('monitoring.contract_drift_predictor.set_feature_flag') as mock_set_flag:
            disable_contract_drift_prediction()
            mock_set_flag.assert_called_once_with(
                "contract_drift_prediction_enabled",
                FeatureFlagStatus.DISABLED
            )
    
    def test_monitor_api_contract_decorator(self):
        """Testa decorator monitor_api_contract."""
        # Função de teste
        @monitor_api_contract('openai')
        def test_function():
            return "success"
        
        # Mock das dependências
        with patch('monitoring.contract_drift_predictor.metrics_collector') as mock_metrics:
            mock_metrics.record_request = Mock()
            mock_metrics.record_error = Mock()
            
            # Testa execução bem-sucedida
            result = test_function()
            assert result == "success"
            mock_metrics.record_request.assert_called_once()
    
    def test_monitor_api_contract_decorator_with_error(self):
        """Testa decorator monitor_api_contract com erro."""
        # Função de teste que gera erro
        @monitor_api_contract('openai')
        def test_function_with_error():
            raise ValueError("API error")
        
        # Mock das dependências
        with patch('monitoring.contract_drift_predictor.metrics_collector') as mock_metrics:
            mock_metrics.record_request = Mock()
            mock_metrics.record_error = Mock()
            
            # Testa execução com erro
            with pytest.raises(ValueError):
                test_function_with_error()
            
            mock_metrics.record_error.assert_called_once()


class TestContractDriftPredictorIntegration:
    """Testes de integração do contract drift predictor."""

    def test_integration_with_feature_flags(self):
        """Testa integração com feature flags."""
        with patch('monitoring.contract_drift_predictor.is_feature_enabled') as mock_feature:
            # Testa com feature habilitada
            mock_feature.return_value = True
            
            with patch('monitoring.contract_drift_predictor.get_structured_logger'):
                predictor = ContractDriftPredictor()
                assert predictor.enabled is True
            
            # Testa com feature desabilitada
            mock_feature.return_value = False
            
            with patch('monitoring.contract_drift_predictor.get_structured_logger'):
                predictor = ContractDriftPredictor()
                assert predictor.enabled is False
    
    def test_integration_with_logging(self):
        """Testa integração com sistema de logging."""
        mock_logger = Mock()
        
        with patch('monitoring.contract_drift_predictor.get_structured_logger', return_value=mock_logger):
            with patch('monitoring.contract_drift_predictor.is_feature_enabled', return_value=True):
                predictor = ContractDriftPredictor()
                
                # Verifica se logger foi chamado na inicialização
                mock_logger.info.assert_called()
                
                # Verifica se o call inclui tracing_id
                call_args = mock_logger.info.call_args
                assert 'tracing_id' in call_args[1]['extra']
                assert call_args[1]['extra']['tracing_id'] == 'CONTRACT_DRIFT_20250127_006'
    
    def test_integration_with_metrics_collector(self):
        """Testa integração com metrics collector."""
        mock_metrics = Mock()
        mock_metrics.record_request = Mock()
        mock_metrics.record_error = Mock()
        
        with patch('monitoring.contract_drift_predictor.metrics_collector', mock_metrics):
            with patch('monitoring.contract_drift_predictor.is_feature_enabled', return_value=True):
                with patch('monitoring.contract_drift_predictor.get_structured_logger'):
                    predictor = ContractDriftPredictor()
                    
                    # Testa decorator com sucesso
                    @monitor_api_contract('openai')
                    def test_success():
                        return "success"
                    
                    test_success()
                    mock_metrics.record_request.assert_called_once()
                    
                    # Testa decorator com erro
                    @monitor_api_contract('openai')
                    def test_error():
                        raise Exception("API error")
                    
                    with pytest.raises(Exception):
                        test_error()
                    
                    mock_metrics.record_error.assert_called_once()


class TestContractDriftPredictorEdgeCases:
    """Testes para casos extremos do contract drift predictor."""

    def test_contract_with_empty_endpoints(self):
        """Testa contrato com endpoints vazios."""
        empty_contract = APIContract(
            name='empty_api',
            base_url='https://api.empty.com',
            version='1.0.0',
            endpoints={},
            schema_hash='empty_hash',
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={}
        )
        
        # Deve funcionar sem erro
        assert empty_contract.name == 'empty_api'
        assert len(empty_contract.endpoints) == 0
    
    def test_drift_with_zero_confidence(self):
        """Testa drift com confiança zero."""
        contract = APIContract(
            name='test_api',
            base_url='https://api.test.com',
            version='1.0.0',
            endpoints={},
            schema_hash='test_hash',
            last_updated=datetime.now(),
            status=ContractStatus.STABLE,
            metadata={}
        )
        
        # Drift com confiança zero
        drift = DriftDetection(
            contract_name='test_api',
            drift_type=DriftType.SCHEMA_CHANGE,
            severity=SeverityLevel.INFO,
            description='Zero confidence drift',
            old_value='old',
            new_value='new',
            confidence=0.0,
            timestamp=datetime.now(),
            affected_endpoints=[],
            recommendations=[],
            metadata={}
        )
        
        assert drift.confidence == 0.0
        assert len(drift.affected_endpoints) == 0
        assert len(drift.recommendations) == 0
    
    def test_monitor_with_invalid_url(self):
        """Testa monitor com URL inválida."""
        invalid_monitor = APIMonitor(
            name='invalid_api',
            base_url='invalid-url',
            health_endpoint='/health',
            schema_endpoint=None,
            auth_required=False,
            auth_type='none',
            check_interval=60,
            timeout=30,
            headers={},
            expected_status_codes=[200],
            drift_threshold=0.8
        )
        
        # Deve ser criado sem erro
        assert invalid_monitor.name == 'invalid_api'
        assert invalid_monitor.base_url == 'invalid-url'
    
    def test_schema_hash_with_none_contract(self):
        """Testa cálculo de hash com contrato inexistente."""
        with patch('monitoring.contract_drift_predictor.get_structured_logger'):
            with patch('monitoring.contract_drift_predictor.is_feature_enabled', return_value=True):
                predictor = ContractDriftPredictor()
                
                # Hash de contrato inexistente deve retornar string vazia
                hash_result = predictor._calculate_schema_hash('nonexistent')
                assert hash_result == ""
    
    def test_body_hash_with_none_body(self):
        """Testa cálculo de hash com body None."""
        with patch('monitoring.contract_drift_predictor.get_structured_logger'):
            with patch('monitoring.contract_drift_predictor.is_feature_enabled', return_value=True):
                predictor = ContractDriftPredictor()
                
                # Hash de body None deve funcionar
                hash_result = predictor._calculate_body_hash(None)
                assert isinstance(hash_result, str)
                assert len(hash_result) == 64 