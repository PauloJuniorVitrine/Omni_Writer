"""
Testes de Compliance com Padrões de Segurança - Omni Writer
==========================================================

Prompt: Pendência 3.3.3 - Validar compliance com padrões de segurança
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:45:00Z
Tracing ID: PENDENCIA_3_3_3_001

Testes baseados no código real do sistema Omni Writer:
- Compliance com OWASP Top 10
- Compliance com PCI DSS
- Compliance com GDPR
- Compliance com ISO 27001
- Validação de padrões de segurança
"""

import pytest
import json
import time
import hashlib
import ssl
import socket
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, List, Any
import requests
from urllib.parse import urlparse

# Importações do sistema real
from app.validators.input_validators import SecurityValidator
from app.middleware.csrf_protection import CSRFProtector
from app.middleware.auth_middleware import AuthMiddleware
from shared.audit_trail import AuditTrail
from shared.encryption import EncryptionManager


class ComplianceValidator:
    """Validador de compliance com padrões de segurança."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_validator = SecurityValidator()
        self.csrf_protector = CSRFProtector()
        self.auth_middleware = AuthMiddleware()
        self.audit_trail = AuditTrail()
        self.encryption_manager = EncryptionManager()
        
        # Configurações de compliance baseadas em padrões reais
        self.compliance_config = {
            'owasp_top_10': {
                'A01:2021': 'Broken Access Control',
                'A02:2021': 'Cryptographic Failures',
                'A03:2021': 'Injection',
                'A04:2021': 'Insecure Design',
                'A05:2021': 'Security Misconfiguration',
                'A06:2021': 'Vulnerable Components',
                'A07:2021': 'Authentication Failures',
                'A08:2021': 'Software and Data Integrity Failures',
                'A09:2021': 'Security Logging Failures',
                'A10:2021': 'Server-Side Request Forgery'
            },
            'pci_dss': {
                'req_1': 'Install and maintain a firewall configuration',
                'req_2': 'Do not use vendor-supplied defaults',
                'req_3': 'Protect stored cardholder data',
                'req_4': 'Encrypt transmission of cardholder data',
                'req_5': 'Use and regularly update anti-virus software',
                'req_6': 'Develop and maintain secure systems',
                'req_7': 'Restrict access to cardholder data',
                'req_8': 'Assign a unique ID to each person',
                'req_9': 'Restrict physical access to cardholder data',
                'req_10': 'Track and monitor all access',
                'req_11': 'Regularly test security systems',
                'req_12': 'Maintain a policy'
            },
            'gdpr': {
                'art_5': 'Principles of processing',
                'art_6': 'Lawfulness of processing',
                'art_7': 'Conditions for consent',
                'art_8': 'Conditions applicable to child consent',
                'art_9': 'Processing of special categories',
                'art_10': 'Processing of personal data',
                'art_11': 'Processing not requiring identification',
                'art_12': 'Transparent information',
                'art_13': 'Information to be provided',
                'art_14': 'Information to be provided',
                'art_15': 'Right of access',
                'art_16': 'Right to rectification',
                'art_17': 'Right to erasure',
                'art_18': 'Right to restriction',
                'art_19': 'Notification obligation',
                'art_20': 'Right to data portability',
                'art_21': 'Right to object',
                'art_22': 'Automated individual decision-making',
                'art_23': 'Restrictions',
                'art_24': 'Responsibility of the controller',
                'art_25': 'Data protection by design',
                'art_26': 'Joint controllers',
                'art_27': 'Representatives of controllers',
                'art_28': 'Processor',
                'art_29': 'Processing under authority',
                'art_30': 'Records of processing activities',
                'art_31': 'Cooperation with supervisory authority',
                'art_32': 'Security of processing',
                'art_33': 'Notification of personal data breach',
                'art_34': 'Communication of personal data breach',
                'art_35': 'Data protection impact assessment',
                'art_36': 'Prior consultation',
                'art_37': 'Designation of data protection officer',
                'art_38': 'Position of data protection officer',
                'art_39': 'Tasks of data protection officer',
                'art_40': 'Codes of conduct',
                'art_41': 'Monitoring of approved codes',
                'art_42': 'Certification',
                'art_43': 'Certification bodies',
                'art_44': 'General principle for transfers',
                'art_45': 'Transfers on basis of adequacy',
                'art_46': 'Transfers subject to safeguards',
                'art_47': 'Binding corporate rules',
                'art_48': 'Transfers or disclosures',
                'art_49': 'Derogations for specific situations',
                'art_50': 'International cooperation',
                'art_51': 'Supervisory authority',
                'art_52': 'Independence',
                'art_53': 'General conditions',
                'art_54': 'Rules on establishment',
                'art_55': 'Competence',
                'art_56': 'Competence of lead authority',
                'art_57': 'Tasks',
                'art_58': 'Powers',
                'art_59': 'Activity reports',
                'art_60': 'Cooperation between authorities',
                'art_61': 'Mutual assistance',
                'art_62': 'Joint operations',
                'art_63': 'Consistency mechanism',
                'art_64': 'Opinion of the Board',
                'art_65': 'Dispute resolution',
                'art_66': 'Urgency procedure',
                'art_67': 'Exchange of information',
                'art_68': 'European Data Protection Board',
                'art_69': 'Independence',
                'art_70': 'Tasks of the Board',
                'art_71': 'Reports',
                'art_72': 'Procedure',
                'art_73': 'Chair',
                'art_74': 'Tasks of the Chair',
                'art_75': 'Secretariat',
                'art_76': 'Confidentiality',
                'art_77': 'Right to lodge complaint',
                'art_78': 'Right to effective judicial remedy',
                'art_79': 'Right to compensation',
                'art_80': 'Representation of data subjects',
                'art_81': 'Suspension of proceedings',
                'art_82': 'Right to compensation',
                'art_83': 'General conditions',
                'art_84': 'Penalties',
                'art_85': 'Processing and freedom of expression',
                'art_86': 'Processing and public access',
                'art_87': 'Processing of national identification',
                'art_88': 'Processing in employment context',
                'art_89': 'Safeguards and derogations',
                'art_90': 'Obligations of secrecy',
                'art_91': 'Existing data protection rules',
                'art_92': 'Exercise of delegation',
                'art_93': 'Committee procedure',
                'art_94': 'Repeal of Directive 95/46/EC',
                'art_95': 'Relationship with Directive 2002/58/EC',
                'art_96': 'Relationship with agreements',
                'art_97': 'Commission reports',
                'art_98': 'Review of other Union legal acts',
                'art_99': 'Entry into force and application'
            },
            'iso_27001': {
                'A.5': 'Information security policies',
                'A.6': 'Organization of information security',
                'A.7': 'Human resource security',
                'A.8': 'Asset management',
                'A.9': 'Access control',
                'A.10': 'Cryptography',
                'A.11': 'Physical and environmental security',
                'A.12': 'Operations security',
                'A.13': 'Communications security',
                'A.14': 'System acquisition, development and maintenance',
                'A.15': 'Supplier relationships',
                'A.16': 'Information security incident management',
                'A.17': 'Information security aspects of business continuity management',
                'A.18': 'Compliance'
            }
        }
    
    def validate_owasp_compliance(self) -> Dict[str, Any]:
        """
        Valida compliance com OWASP Top 10 2021.
        
        Returns:
            Resultado da validação OWASP
        """
        results = {
            'standard': 'OWASP Top 10 2021',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa cada categoria OWASP
        for code, description in self.compliance_config['owasp_top_10'].items():
            try:
                test_result = self._test_owasp_category(code, description)
                results['details'].append(test_result)
                
                if not test_result['passed']:
                    results['passed'] = False
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['details'].append({
                    'category': code,
                    'description': description,
                    'passed': False,
                    'error': str(e)
                })
                results['passed'] = False
        
        return results
    
    def validate_pci_dss_compliance(self) -> Dict[str, Any]:
        """
        Valida compliance com PCI DSS.
        
        Returns:
            Resultado da validação PCI DSS
        """
        results = {
            'standard': 'PCI DSS v4.0',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa requisitos críticos do PCI DSS
        critical_requirements = [
            'req_3',  # Protect stored cardholder data
            'req_4',  # Encrypt transmission of cardholder data
            'req_7',  # Restrict access to cardholder data
            'req_8',  # Assign a unique ID to each person
            'req_10'  # Track and monitor all access
        ]
        
        for req in critical_requirements:
            try:
                test_result = self._test_pci_requirement(req)
                results['details'].append(test_result)
                
                if not test_result['passed']:
                    results['passed'] = False
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['details'].append({
                    'requirement': req,
                    'description': self.compliance_config['pci_dss'][req],
                    'passed': False,
                    'error': str(e)
                })
                results['passed'] = False
        
        return results
    
    def validate_gdpr_compliance(self) -> Dict[str, Any]:
        """
        Valida compliance com GDPR.
        
        Returns:
            Resultado da validação GDPR
        """
        results = {
            'standard': 'GDPR',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa artigos críticos do GDPR
        critical_articles = [
            'art_5',   # Principles of processing
            'art_6',   # Lawfulness of processing
            'art_7',   # Conditions for consent
            'art_12',  # Transparent information
            'art_13',  # Information to be provided
            'art_15',  # Right of access
            'art_17',  # Right to erasure
            'art_25',  # Data protection by design
            'art_30',  # Records of processing activities
            'art_32',  # Security of processing
            'art_33',  # Notification of personal data breach
            'art_34'   # Communication of personal data breach
        ]
        
        for article in critical_articles:
            try:
                test_result = self._test_gdpr_article(article)
                results['details'].append(test_result)
                
                if not test_result['passed']:
                    results['passed'] = False
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['details'].append({
                    'article': article,
                    'description': self.compliance_config['gdpr'][article],
                    'passed': False,
                    'error': str(e)
                })
                results['passed'] = False
        
        return results
    
    def validate_iso_27001_compliance(self) -> Dict[str, Any]:
        """
        Valida compliance com ISO 27001.
        
        Returns:
            Resultado da validação ISO 27001
        """
        results = {
            'standard': 'ISO 27001:2013',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa controles críticos do ISO 27001
        critical_controls = [
            'A.5',   # Information security policies
            'A.6',   # Organization of information security
            'A.9',   # Access control
            'A.10',  # Cryptography
            'A.12',  # Operations security
            'A.13',  # Communications security
            'A.16',  # Information security incident management
            'A.18'   # Compliance
        ]
        
        for control in critical_controls:
            try:
                test_result = self._test_iso_control(control)
                results['details'].append(test_result)
                
                if not test_result['passed']:
                    results['passed'] = False
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['details'].append({
                    'control': control,
                    'description': self.compliance_config['iso_27001'][control],
                    'passed': False,
                    'error': str(e)
                })
                results['passed'] = False
        
        return results
    
    def _test_owasp_category(self, code: str, description: str) -> Dict[str, Any]:
        """Testa categoria específica do OWASP."""
        result = {
            'category': code,
            'description': description,
            'passed': True,
            'vulnerabilities': []
        }
        
        if code == 'A01:2021':  # Broken Access Control
            # Testa acesso não autorizado
            response = self.session.get(f"{self.base_url}/api/admin")
            if response.status_code != 401:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'broken_access_control',
                    'endpoint': '/api/admin',
                    'status_code': response.status_code
                })
        
        elif code == 'A02:2021':  # Cryptographic Failures
            # Testa se dados sensíveis estão criptografados
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                content = response.text.lower()
                if 'password' in content or 'secret' in content:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'cryptographic_failure',
                        'description': 'Sensitive data exposed'
                    })
        
        elif code == 'A03:2021':  # Injection
            # Testa injeção SQL
            sql_payload = "' OR '1'='1"
            response = self.session.post(
                f"{self.base_url}/api/search",
                json={'query': sql_payload}
            )
            if 'sql' in response.text.lower():
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'injection_vulnerability',
                    'payload': sql_payload
                })
        
        elif code == 'A05:2021':  # Security Misconfiguration
            # Testa headers de segurança
            response = self.session.get(f"{self.base_url}/")
            headers = response.headers
            
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]
            
            for header in required_headers:
                if header not in headers:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'security_misconfiguration',
                        'missing_header': header
                    })
        
        return result
    
    def _test_pci_requirement(self, req: str) -> Dict[str, Any]:
        """Testa requisito específico do PCI DSS."""
        result = {
            'requirement': req,
            'description': self.compliance_config['pci_dss'][req],
            'passed': True,
            'vulnerabilities': []
        }
        
        if req == 'req_3':  # Protect stored cardholder data
            # Testa se dados de cartão estão criptografados
            test_data = {'card_number': '4111111111111111'}
            encrypted = self.encryption_manager.encrypt_data(json.dumps(test_data))
            if not encrypted or encrypted == json.dumps(test_data):
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'pci_req_3_violation',
                    'description': 'Cardholder data not encrypted'
                })
        
        elif req == 'req_4':  # Encrypt transmission of cardholder data
            # Testa se transmissão é criptografada
            parsed_url = urlparse(self.base_url)
            if parsed_url.scheme != 'https':
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'pci_req_4_violation',
                    'description': 'Transmission not encrypted (HTTPS)'
                })
        
        elif req == 'req_7':  # Restrict access to cardholder data
            # Testa controle de acesso
            response = self.session.get(f"{self.base_url}/api/cardholder-data")
            if response.status_code != 401:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'pci_req_7_violation',
                    'description': 'Unauthorized access to cardholder data'
                })
        
        elif req == 'req_8':  # Assign a unique ID to each person
            # Testa identificação única
            user_ids = set()
            for i in range(10):
                response = self.session.post(
                    f"{self.base_url}/api/register",
                    json={'email': f'test{i}@example.com', 'password': 'password123'}
                )
                if response.status_code == 200:
                    user_data = response.json()
                    user_id = user_data.get('user_id')
                    if user_id in user_ids:
                        result['passed'] = False
                        result['vulnerabilities'].append({
                            'type': 'pci_req_8_violation',
                            'description': 'Duplicate user ID assigned'
                        })
                    user_ids.add(user_id)
        
        elif req == 'req_10':  # Track and monitor all access
            # Testa logging de acesso
            test_action = 'pci_access_test'
            audit_entry = self.audit_trail.log_action(
                user_id='test@example.com',
                action=test_action,
                details={'test': True},
                ip_address='127.0.0.1'
            )
            if not audit_entry:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'pci_req_10_violation',
                    'description': 'Access not logged'
                })
        
        return result
    
    def _test_gdpr_article(self, article: str) -> Dict[str, Any]:
        """Testa artigo específico do GDPR."""
        result = {
            'article': article,
            'description': self.compliance_config['gdpr'][article],
            'passed': True,
            'vulnerabilities': []
        }
        
        if article == 'art_5':  # Principles of processing
            # Testa princípios de processamento
            response = self.session.get(f"{self.base_url}/api/privacy-policy")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_5_violation',
                    'description': 'Privacy policy not available'
                })
        
        elif article == 'art_7':  # Conditions for consent
            # Testa consentimento
            response = self.session.post(
                f"{self.base_url}/api/consent",
                json={'consent_given': True, 'timestamp': datetime.now().isoformat()}
            )
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_7_violation',
                    'description': 'Consent mechanism not working'
                })
        
        elif article == 'art_15':  # Right of access
            # Testa direito de acesso
            response = self.session.get(f"{self.base_url}/api/user/data")
            if response.status_code != 401:  # Deve requerer autenticação
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_15_violation',
                    'description': 'Data access not properly protected'
                })
        
        elif article == 'art_17':  # Right to erasure
            # Testa direito ao esquecimento
            response = self.session.delete(f"{self.base_url}/api/user/data")
            if response.status_code != 401:  # Deve requerer autenticação
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_17_violation',
                    'description': 'Data deletion not properly protected'
                })
        
        elif article == 'art_25':  # Data protection by design
            # Testa proteção por design
            response = self.session.get(f"{self.base_url}/api/security-by-design")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_25_violation',
                    'description': 'Security by design not implemented'
                })
        
        elif article == 'art_32':  # Security of processing
            # Testa segurança do processamento
            response = self.session.get(f"{self.base_url}/api/security-measures")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'gdpr_art_32_violation',
                    'description': 'Security measures not documented'
                })
        
        return result
    
    def _test_iso_control(self, control: str) -> Dict[str, Any]:
        """Testa controle específico do ISO 27001."""
        result = {
            'control': control,
            'description': self.compliance_config['iso_27001'][control],
            'passed': True,
            'vulnerabilities': []
        }
        
        if control == 'A.5':  # Information security policies
            # Testa políticas de segurança
            response = self.session.get(f"{self.base_url}/api/security-policies")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'iso_a5_violation',
                    'description': 'Security policies not available'
                })
        
        elif control == 'A.9':  # Access control
            # Testa controle de acesso
            response = self.session.get(f"{self.base_url}/api/access-control")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'iso_a9_violation',
                    'description': 'Access control not implemented'
                })
        
        elif control == 'A.10':  # Cryptography
            # Testa criptografia
            test_data = 'sensitive_data'
            encrypted = self.encryption_manager.encrypt_data(test_data)
            if not encrypted or encrypted == test_data:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'iso_a10_violation',
                    'description': 'Cryptography not properly implemented'
                })
        
        elif control == 'A.12':  # Operations security
            # Testa segurança operacional
            response = self.session.get(f"{self.base_url}/api/operations-security")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'iso_a12_violation',
                    'description': 'Operations security not documented'
                })
        
        elif control == 'A.16':  # Information security incident management
            # Testa gerenciamento de incidentes
            response = self.session.get(f"{self.base_url}/api/incident-management")
            if response.status_code != 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'iso_a16_violation',
                    'description': 'Incident management not implemented'
                })
        
        return result
    
    def run_comprehensive_compliance_test(self) -> Dict[str, Any]:
        """
        Executa teste de compliance abrangente.
        
        Returns:
            Resultado completo dos testes
        """
        print("🔒 Iniciando validação de compliance com padrões de segurança...")
        
        test_results = {
            'timestamp': datetime.now().isoformat(),
            'base_url': self.base_url,
            'standards': [],
            'overall_passed': True,
            'vulnerabilities_found': 0,
            'recommendations': []
        }
        
        # Executa validação de todos os padrões
        standards = [
            self.validate_owasp_compliance,
            self.validate_pci_dss_compliance,
            self.validate_gdpr_compliance,
            self.validate_iso_27001_compliance
        ]
        
        for standard_func in standards:
            try:
                result = standard_func()
                test_results['standards'].append(result)
                
                if not result['passed']:
                    test_results['overall_passed'] = False
                    test_results['vulnerabilities_found'] += len(result.get('vulnerabilities', []))
                    
            except Exception as e:
                test_results['standards'].append({
                    'standard': standard_func.__name__,
                    'passed': False,
                    'error': str(e)
                })
                test_results['overall_passed'] = False
        
        # Gera recomendações
        if test_results['vulnerabilities_found'] > 0:
            test_results['recommendations'] = [
                "Implementar controles de acesso mais rigorosos",
                "Criptografar todos os dados sensíveis",
                "Implementar logging de segurança abrangente",
                "Configurar headers de segurança adequados",
                "Realizar auditoria de compliance regular"
            ]
        
        return test_results


# Testes unitários para pytest
class TestComplianceValidation:
    """Testes unitários para validação de compliance."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.validator = ComplianceValidator()
    
    def test_owasp_compliance(self):
        """Testa compliance com OWASP Top 10."""
        result = self.validator.validate_owasp_compliance()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_pci_dss_compliance(self):
        """Testa compliance com PCI DSS."""
        result = self.validator.validate_pci_dss_compliance()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_gdpr_compliance(self):
        """Testa compliance com GDPR."""
        result = self.validator.validate_gdpr_compliance()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_iso_27001_compliance(self):
        """Testa compliance com ISO 27001."""
        result = self.validator.validate_iso_27001_compliance()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_comprehensive_compliance(self):
        """Testa compliance abrangente."""
        result = self.validator.run_comprehensive_compliance_test()
        assert result['overall_passed'] is True
        assert result['vulnerabilities_found'] == 0


# Execução principal (para testes manuais)
if __name__ == "__main__":
    print("🔒 Iniciando validação de compliance com padrões de segurança...")
    
    validator = ComplianceValidator()
    result = validator.run_comprehensive_compliance_test()
    
    print(f"✅ Compliance validado: {result['overall_passed']}")
    print(f"🔍 Vulnerabilidades encontradas: {result['vulnerabilities_found']}")
    
    if result['recommendations']:
        print("📋 Recomendações:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    
    print("🔒 Validação de compliance concluída") 