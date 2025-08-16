#!/usr/bin/env python3
"""
Script de Detecção de Breaking Changes - Omni Writer
Detecta automaticamente breaking changes comparando especificações OpenAPI

Tracing ID: BREAKING_CHANGES_20250127_001
"""

import os
import sys
import json
import yaml
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass

# Adiciona shared ao path
sys.path.append(str(Path(__file__).parent.parent / 'shared'))

from versioning import BreakingChangeType, add_breaking_change

@dataclass
class BreakingChangeDetection:
    """Detecção de breaking change"""
    type: BreakingChangeType
    description: str
    affected_endpoints: List[str]
    severity: str
    details: Dict[str, Any]

class BreakingChangeDetector:
    """Detector de breaking changes"""
    
    def __init__(self):
        self.detections: List[BreakingChangeDetection] = []
        
    def log(self, message: str, level: str = 'INFO'):
        """Log estruturado"""
        timestamp = datetime.utcnow().isoformat()
        print(f"[{timestamp}] [{level}] [BREAKING_CHANGES_20250127_001] {message}")
    
    def load_openapi_spec(self, file_path: str) -> Dict[str, Any]:
        """Carrega especificação OpenAPI"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except Exception as e:
            self.log(f"Erro ao carregar {file_path}: {e}", 'ERROR')
            return {}
    
    def compare_endpoints(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[BreakingChangeDetection]:
        """Compara endpoints entre especificações"""
        detections = []
        
        old_paths = old_spec.get('paths', {})
        new_paths = new_spec.get('paths', {})
        
        # Endpoints removidos
        removed_endpoints = set(old_paths.keys()) - set(new_paths.keys())
        for endpoint in removed_endpoints:
            detection = BreakingChangeDetection(
                type=BreakingChangeType.ENDPOINT_REMOVED,
                description=f"Endpoint removido: {endpoint}",
                affected_endpoints=[endpoint],
                severity="critical",
                details={
                    'endpoint': endpoint,
                    'old_methods': list(old_paths[endpoint].keys())
                }
            )
            detections.append(detection)
        
        # Métodos removidos
        for endpoint in old_paths:
            if endpoint in new_paths:
                old_methods = set(old_paths[endpoint].keys())
                new_methods = set(new_paths[endpoint].keys())
                removed_methods = old_methods - new_methods
                
                for method in removed_methods:
                    detection = BreakingChangeDetection(
                        type=BreakingChangeType.ENDPOINT_REMOVED,
                        description=f"Método {method} removido do endpoint {endpoint}",
                        affected_endpoints=[endpoint],
                        severity="critical",
                        details={
                            'endpoint': endpoint,
                            'method': method
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def compare_parameters(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[BreakingChangeDetection]:
        """Compara parâmetros entre especificações"""
        detections = []
        
        old_paths = old_spec.get('paths', {})
        new_paths = new_spec.get('paths', {})
        
        for endpoint in old_paths:
            if endpoint not in new_paths:
                continue
                
            for method in old_paths[endpoint]:
                if method not in new_paths[endpoint]:
                    continue
                
                old_params = self._extract_parameters(old_paths[endpoint][method])
                new_params = self._extract_parameters(new_paths[endpoint][method])
                
                # Parâmetros obrigatórios removidos
                old_required = {p['name'] for p in old_params if p.get('required', False)}
                new_required = {p['name'] for p in new_params if p.get('required', False)}
                removed_required = old_required - new_required
                
                for param in removed_required:
                    detection = BreakingChangeDetection(
                        type=BreakingChangeType.PARAMETER_REMOVED,
                        description=f"Parâmetro obrigatório removido: {param} em {method} {endpoint}",
                        affected_endpoints=[endpoint],
                        severity="high",
                        details={
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param,
                            'was_required': True
                        }
                    )
                    detections.append(detection)
                
                # Parâmetros opcionais removidos
                old_optional = {p['name'] for p in old_params if not p.get('required', False)}
                new_optional = {p['name'] for p in new_params if not p.get('required', False)}
                removed_optional = old_optional - new_optional
                
                for param in removed_optional:
                    detection = BreakingChangeDetection(
                        type=BreakingChangeType.PARAMETER_REMOVED,
                        description=f"Parâmetro opcional removido: {param} em {method} {endpoint}",
                        affected_endpoints=[endpoint],
                        severity="medium",
                        details={
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param,
                            'was_required': False
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def _extract_parameters(self, method_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai parâmetros de um método"""
        params = []
        
        # Parâmetros de path
        for param in method_spec.get('parameters', []):
            if param.get('in') == 'path':
                param['required'] = True  # Path params são sempre obrigatórios
            params.append(param)
        
        # Parâmetros de query
        for param in method_spec.get('parameters', []):
            if param.get('in') == 'query':
                params.append(param)
        
        return params
    
    def compare_responses(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[BreakingChangeDetection]:
        """Compara respostas entre especificações"""
        detections = []
        
        old_paths = old_spec.get('paths', {})
        new_paths = new_spec.get('paths', {})
        
        for endpoint in old_paths:
            if endpoint not in new_paths:
                continue
                
            for method in old_paths[endpoint]:
                if method not in new_paths[endpoint]:
                    continue
                
                old_responses = old_paths[endpoint][method].get('responses', {})
                new_responses = new_paths[endpoint][method].get('responses', {})
                
                # Códigos de status removidos
                removed_status_codes = set(old_responses.keys()) - set(new_responses.keys())
                for status_code in removed_status_codes:
                    detection = BreakingChangeDetection(
                        type=BreakingChangeType.RESPONSE_CHANGED,
                        description=f"Código de status removido: {status_code} em {method} {endpoint}",
                        affected_endpoints=[endpoint],
                        severity="medium",
                        details={
                            'endpoint': endpoint,
                            'method': method,
                            'status_code': status_code,
                            'change_type': 'removed'
                        }
                    )
                    detections.append(detection)
                
                # Schemas de resposta alterados
                for status_code in old_responses:
                    if status_code in new_responses:
                        old_schema = self._extract_response_schema(old_responses[status_code])
                        new_schema = self._extract_response_schema(new_responses[status_code])
                        
                        if old_schema != new_schema:
                            detection = BreakingChangeDetection(
                                type=BreakingChangeType.RESPONSE_CHANGED,
                                description=f"Schema de resposta alterado para {status_code} em {method} {endpoint}",
                                affected_endpoints=[endpoint],
                                severity="high",
                                details={
                                    'endpoint': endpoint,
                                    'method': method,
                                    'status_code': status_code,
                                    'old_schema': old_schema,
                                    'new_schema': new_schema,
                                    'change_type': 'schema_changed'
                                }
                            )
                            detections.append(detection)
        
        return detections
    
    def _extract_response_schema(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai schema de uma resposta"""
        content = response.get('content', {})
        json_content = content.get('application/json', {})
        return json_content.get('schema', {})
    
    def compare_authentication(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[BreakingChangeDetection]:
        """Compara autenticação entre especificações"""
        detections = []
        
        old_security = old_spec.get('components', {}).get('securitySchemes', {})
        new_security = new_spec.get('components', {}).get('securitySchemes', {})
        
        # Esquemas de segurança removidos
        removed_schemes = set(old_security.keys()) - set(new_security.keys())
        for scheme in removed_schemes:
            detection = BreakingChangeDetection(
                type=BreakingChangeType.AUTHENTICATION_CHANGED,
                description=f"Esquema de autenticação removido: {scheme}",
                affected_endpoints=[],  # Será preenchido depois
                severity="critical",
                details={
                    'scheme': scheme,
                    'old_scheme': old_security[scheme],
                    'change_type': 'removed'
                }
            )
            detections.append(detection)
        
        # Esquemas de segurança alterados
        for scheme in old_security:
            if scheme in new_security:
                if old_security[scheme] != new_security[scheme]:
                    detection = BreakingChangeDetection(
                        type=BreakingChangeType.AUTHENTICATION_CHANGED,
                        description=f"Esquema de autenticação alterado: {scheme}",
                        affected_endpoints=[],
                        severity="high",
                        details={
                            'scheme': scheme,
                            'old_scheme': old_security[scheme],
                            'new_scheme': new_security[scheme],
                            'change_type': 'modified'
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def compare_schemas(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[BreakingChangeDetection]:
        """Compara schemas entre especificações"""
        detections = []
        
        old_schemas = old_spec.get('components', {}).get('schemas', {})
        new_schemas = new_spec.get('components', {}).get('schemas', {})
        
        # Schemas removidos
        removed_schemas = set(old_schemas.keys()) - set(new_schemas.keys())
        for schema in removed_schemas:
            detection = BreakingChangeDetection(
                type=BreakingChangeType.SCHEMA_CHANGED,
                description=f"Schema removido: {schema}",
                affected_endpoints=[],
                severity="high",
                details={
                    'schema': schema,
                    'old_schema': old_schemas[schema],
                    'change_type': 'removed'
                }
            )
            detections.append(detection)
        
        # Schemas alterados
        for schema in old_schemas:
            if schema in new_schemas:
                old_schema = old_schemas[schema]
                new_schema = new_schemas[schema]
                
                if old_schema != new_schema:
                    # Verifica propriedades removidas
                    old_props = set(old_schema.get('properties', {}).keys())
                    new_props = set(new_schema.get('properties', {}).keys())
                    removed_props = old_props - new_props
                    
                    if removed_props:
                        detection = BreakingChangeDetection(
                            type=BreakingChangeType.SCHEMA_CHANGED,
                            description=f"Propriedades removidas do schema {schema}: {', '.join(removed_props)}",
                            affected_endpoints=[],
                            severity="high",
                            details={
                                'schema': schema,
                                'removed_properties': list(removed_props),
                                'change_type': 'properties_removed'
                            }
                        )
                        detections.append(detection)
                    
                    # Verifica propriedades obrigatórias alteradas
                    old_required = set(old_schema.get('required', []))
                    new_required = set(new_schema.get('required', []))
                    new_required_props = new_required - old_required
                    
                    if new_required_props:
                        detection = BreakingChangeDetection(
                            type=BreakingChangeType.SCHEMA_CHANGED,
                            description=f"Propriedades agora obrigatórias no schema {schema}: {', '.join(new_required_props)}",
                            affected_endpoints=[],
                            severity="medium",
                            details={
                                'schema': schema,
                                'new_required_properties': list(new_required_props),
                                'change_type': 'properties_required'
                            }
                        )
                        detections.append(detection)
        
        return detections
    
    def detect_breaking_changes(self, old_spec_file: str, new_spec_file: str) -> List[BreakingChangeDetection]:
        """Detecta breaking changes entre duas especificações"""
        self.log(f"Detectando breaking changes entre {old_spec_file} e {new_spec_file}")
        
        old_spec = self.load_openapi_spec(old_spec_file)
        new_spec = self.load_openapi_spec(new_spec_file)
        
        if not old_spec or not new_spec:
            self.log("Erro ao carregar especificações", 'ERROR')
            return []
        
        detections = []
        
        # Compara diferentes aspectos
        detections.extend(self.compare_endpoints(old_spec, new_spec))
        detections.extend(self.compare_parameters(old_spec, new_spec))
        detections.extend(self.compare_responses(old_spec, new_spec))
        detections.extend(self.compare_authentication(old_spec, new_spec))
        detections.extend(self.compare_schemas(old_spec, new_spec))
        
        self.log(f"Detectadas {len(detections)} breaking changes")
        return detections
    
    def create_report(self, detections: List[BreakingChangeDetection], output_file: str = None) -> str:
        """Cria relatório de breaking changes"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"breaking_changes_report_{timestamp}.md"
        
        report = f"# Relatório de Breaking Changes\n\n"
        report += f"**Data:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"**Total de Breaking Changes:** {len(detections)}\n\n"
        
        # Agrupa por tipo
        by_type = {}
        for detection in detections:
            if detection.type not in by_type:
                by_type[detection.type] = []
            by_type[detection.type].append(detection)
        
        for change_type, type_detections in by_type.items():
            report += f"## {change_type.value.replace('_', ' ').title()}\n\n"
            
            for detection in type_detections:
                report += f"### {detection.description}\n\n"
                report += f"- **Severidade:** {detection.severity}\n"
                report += f"- **Endpoints Afetados:** {', '.join(detection.affected_endpoints) if detection.affected_endpoints else 'N/A'}\n"
                
                if detection.details:
                    report += f"- **Detalhes:**\n"
                    for key, value in detection.details.items():
                        report += f"  - {key}: {value}\n"
                
                report += "\n"
        
        # Salva relatório
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            self.log(f"Relatório salvo: {output_file}")
        except Exception as e:
            self.log(f"Erro ao salvar relatório: {e}", 'ERROR')
        
        return report
    
    def register_breaking_changes(self, detections: List[BreakingChangeDetection]):
        """Registra breaking changes no sistema de versionamento"""
        for detection in detections:
            try:
                add_breaking_change(
                    change_type=detection.type,
                    description=detection.description,
                    affected_endpoints=detection.affected_endpoints,
                    severity=detection.severity
                )
                self.log(f"Breaking change registrada: {detection.description}")
            except Exception as e:
                self.log(f"Erro ao registrar breaking change: {e}", 'ERROR')

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Detecta breaking changes em especificações OpenAPI')
    parser.add_argument('old_spec', help='Arquivo da especificação antiga')
    parser.add_argument('new_spec', help='Arquivo da especificação nova')
    parser.add_argument('--output', '-o', help='Arquivo de saída para o relatório')
    parser.add_argument('--register', '-r', action='store_true', help='Registra breaking changes no sistema')
    
    args = parser.parse_args()
    
    print("🔍 Detecção de Breaking Changes - Omni Writer")
    print("=" * 50)
    
    detector = BreakingChangeDetector()
    
    # Detecta breaking changes
    detections = detector.detect_breaking_changes(args.old_spec, args.new_spec)
    
    if not detections:
        print("✅ Nenhuma breaking change detectada")
        return
    
    # Cria relatório
    report = detector.create_report(detections, args.output)
    print(f"📊 {len(detections)} breaking changes detectadas")
    print(report)
    
    # Registra breaking changes se solicitado
    if args.register:
        detector.register_breaking_changes(detections)
        print("✅ Breaking changes registradas no sistema")

if __name__ == '__main__':
    main() 