#!/usr/bin/env python3
"""
🔍 DOCUMENTATION VALIDATOR - Validador de Documentação de Contratos
Tracing ID: DOC_VALIDATOR_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Validar consistência e qualidade da documentação de schemas,
verificando padrões, completude e conformidade com boas práticas.
"""

import json
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import yaml
from dataclasses import dataclass, asdict
from enum import Enum

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/documentation_validator.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('documentation_validator')

class ValidationSeverity(Enum):
    """Severidades de validação."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationIssue:
    """Estrutura para problemas de validação."""
    field_path: str
    issue_type: str
    severity: ValidationSeverity
    message: str
    suggestion: Optional[str] = None
    line_number: Optional[int] = None
    
    def __post_init__(self):
        """Converte string para enum se necessário."""
        if isinstance(self.severity, str):
            self.severity = ValidationSeverity(self.severity)

@dataclass
class ValidationResult:
    """Resultado de validação de um schema."""
    schema_name: str
    file_path: str
    is_valid: bool
    issues: List[ValidationIssue]
    validation_time: datetime
    total_fields: int
    fields_with_issues: int
    
    def __post_init__(self):
        """Calcula métricas derivadas."""
        self.fields_with_issues = len(set(issue.field_path for issue in self.issues))
        self.issue_count_by_severity = {
            severity.value: len([i for i in self.issues if i.severity == severity])
            for severity in ValidationSeverity
        }

class DocumentationValidator:
    """
    Validador de documentação para schemas.
    
    Funcionalidades:
    - Valida consistência de documentação
    - Verifica padrões de nomenclatura
    - Analisa qualidade de descrições
    - Detecta campos sem documentação
    - Sugere melhorias
    """
    
    def __init__(self):
        """Inicializa o validador de documentação."""
        self.required_patterns = self._load_required_patterns()
        self.quality_rules = self._load_quality_rules()
        self.naming_conventions = self._load_naming_conventions()
        
        logger.info("DocumentationValidator inicializado")
    
    def _load_required_patterns(self) -> Dict[str, List[str]]:
        """Carrega padrões obrigatórios por tipo de campo."""
        return {
            'email': [
                r'@.*\.',
                r'email|e-mail|correio'
            ],
            'url': [
                r'http|https|url|link|uri',
                r'protocolo|endereço'
            ],
            'date': [
                r'data|date|dia',
                r'formato|iso|yyyy|mm|dd'
            ],
            'datetime': [
                r'data.*hora|datetime|timestamp',
                r'formato|iso|utc|timezone'
            ],
            'uuid': [
                r'uuid|guid|identificador.*único',
                r'formato|xxxxx|universal'
            ],
            'password': [
                r'senha|password|credencial',
                r'criptografada|hash|segura'
            ],
            'file': [
                r'arquivo|file|upload',
                r'tamanho|formato|extensão'
            ]
        }
    
    def _load_quality_rules(self) -> Dict[str, Dict[str, Any]]:
        """Carrega regras de qualidade para documentação."""
        return {
            'description_length': {
                'min': 10,
                'max': 500,
                'warning_threshold': 50
            },
            'required_fields': {
                'must_have_description': True,
                'must_have_examples': False,
                'must_have_validation': True
            },
            'complex_types': {
                'must_have_examples': True,
                'must_have_schema': True
            },
            'naming': {
                'must_be_snake_case': True,
                'must_be_descriptive': True,
                'forbidden_words': ['temp', 'tmp', 'test', 'dummy', 'fake']
            }
        }
    
    def _load_naming_conventions(self) -> Dict[str, str]:
        """Carrega convenções de nomenclatura."""
        return {
            'id_fields': r'^[a-z_]+_id$',
            'date_fields': r'^[a-z_]+_(at|date|time)$',
            'status_fields': r'^[a-z_]+_(status|state)$',
            'count_fields': r'^[a-z_]+_(count|total|number)$',
            'flag_fields': r'^is_[a-z_]+$|^has_[a-z_]+$|^can_[a-z_]+$',
            'url_fields': r'^[a-z_]+_(url|link|uri)$',
            'email_fields': r'^[a-z_]+_(email|mail)$'
        }
    
    def validate_schema(self, schema_data: Dict[str, Any], schema_name: str, file_path: str = "") -> ValidationResult:
        """
        Valida um schema completo.
        
        Args:
            schema_data: Dados do schema
            schema_name: Nome do schema
            file_path: Caminho do arquivo
            
        Returns:
            Resultado da validação
        """
        issues = []
        start_time = datetime.now()
        
        # Valida estrutura básica
        issues.extend(self._validate_schema_structure(schema_data, schema_name))
        
        # Valida propriedades
        properties = schema_data.get('properties', {})
        required_fields = schema_data.get('required', [])
        
        for field_name, field_data in properties.items():
            field_issues = self._validate_field(
                field_name, field_data, field_name in required_fields, schema_name
            )
            issues.extend(field_issues)
        
        # Valida campos obrigatórios
        issues.extend(self._validate_required_fields(properties, required_fields, schema_name))
        
        # Valida documentação geral
        issues.extend(self._validate_schema_documentation(schema_data, schema_name))
        
        # Calcula métricas
        total_fields = len(properties)
        is_valid = not any(issue.severity == ValidationSeverity.ERROR for issue in issues)
        
        return ValidationResult(
            schema_name=schema_name,
            file_path=file_path,
            is_valid=is_valid,
            issues=issues,
            validation_time=start_time,
            total_fields=total_fields,
            fields_with_issues=0  # Será calculado no __post_init__
        )
    
    def _validate_schema_structure(self, schema_data: Dict[str, Any], schema_name: str) -> List[ValidationIssue]:
        """Valida estrutura básica do schema."""
        issues = []
        
        # Verifica se tem tipo
        if 'type' not in schema_data:
            issues.append(ValidationIssue(
                field_path="root",
                issue_type="missing_type",
                severity=ValidationSeverity.ERROR,
                message="Schema deve ter propriedade 'type' definida"
            ))
        
        # Verifica se tem descrição
        if not schema_data.get('description'):
            issues.append(ValidationIssue(
                field_path="root",
                issue_type="missing_description",
                severity=ValidationSeverity.WARNING,
                message="Schema deve ter descrição",
                suggestion="Adicione uma descrição clara do propósito do schema"
            ))
        
        # Verifica se é objeto e tem propriedades
        if schema_data.get('type') == 'object' and 'properties' not in schema_data:
            issues.append(ValidationIssue(
                field_path="root",
                issue_type="missing_properties",
                severity=ValidationSeverity.ERROR,
                message="Schema do tipo 'object' deve ter propriedades definidas"
            ))
        
        return issues
    
    def _validate_field(self, field_name: str, field_data: Dict[str, Any], is_required: bool, schema_name: str) -> List[ValidationIssue]:
        """Valida um campo individual."""
        issues = []
        field_path = f"{schema_name}.{field_name}"
        
        # Valida nome do campo
        issues.extend(self._validate_field_name(field_name, field_path))
        
        # Valida tipo do campo
        field_type = field_data.get('type', 'string')
        issues.extend(self._validate_field_type(field_type, field_data, field_path))
        
        # Valida descrição
        issues.extend(self._validate_field_description(field_name, field_data, field_path))
        
        # Valida exemplos
        issues.extend(self._validate_field_examples(field_name, field_data, field_path))
        
        # Valida regras de validação
        issues.extend(self._validate_field_validation(field_name, field_data, field_path))
        
        # Valida campos obrigatórios
        if is_required:
            issues.extend(self._validate_required_field(field_name, field_data, field_path))
        
        # Valida tipos complexos
        if field_type in ['object', 'array']:
            issues.extend(self._validate_complex_field(field_name, field_data, field_path))
        
        return issues
    
    def _validate_field_name(self, field_name: str, field_path: str) -> List[ValidationIssue]:
        """Valida nome do campo."""
        issues = []
        
        # Verifica se é snake_case
        if not re.match(r'^[a-z][a-z0-9_]*$', field_name):
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="invalid_naming",
                severity=ValidationSeverity.WARNING,
                message="Nome do campo deve seguir padrão snake_case",
                suggestion=f"Renomeie '{field_name}' para snake_case (ex: {field_name.lower().replace('-', '_')})"
            ))
        
        # Verifica palavras proibidas
        forbidden_words = self.quality_rules['naming']['forbidden_words']
        for word in forbidden_words:
            if word in field_name.lower():
                issues.append(ValidationIssue(
                    field_path=field_path,
                    issue_type="forbidden_word",
                    severity=ValidationSeverity.WARNING,
                    message=f"Nome do campo contém palavra proibida: '{word}'",
                    suggestion="Use um nome mais descritivo e profissional"
                ))
        
        # Verifica se é descritivo
        if len(field_name) < 3:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="too_short",
                severity=ValidationSeverity.WARNING,
                message="Nome do campo muito curto",
                suggestion="Use um nome mais descritivo"
            ))
        
        return issues
    
    def _validate_field_type(self, field_type: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida tipo do campo."""
        issues = []
        
        # Verifica se tipo é válido
        valid_types = ['string', 'integer', 'number', 'boolean', 'array', 'object', 'null']
        if field_type not in valid_types:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="invalid_type",
                severity=ValidationSeverity.ERROR,
                message=f"Tipo inválido: '{field_type}'",
                suggestion=f"Use um dos tipos válidos: {', '.join(valid_types)}"
            ))
        
        # Verifica formato para tipos especiais
        if 'format' in field_data:
            format_value = field_data['format']
            if field_type == 'string':
                valid_formats = ['date', 'date-time', 'email', 'uri', 'uuid', 'binary']
                if format_value not in valid_formats:
                    issues.append(ValidationIssue(
                        field_path=field_path,
                        issue_type="invalid_format",
                        severity=ValidationSeverity.WARNING,
                        message=f"Formato inválido para string: '{format_value}'",
                        suggestion=f"Use um dos formatos válidos: {', '.join(valid_formats)}"
                    ))
        
        return issues
    
    def _validate_field_description(self, field_name: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida descrição do campo."""
        issues = []
        
        description = field_data.get('description', '')
        
        # Verifica se tem descrição
        if not description:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="missing_description",
                severity=ValidationSeverity.ERROR,
                message="Campo deve ter descrição",
                suggestion=f"Adicione uma descrição clara para o campo '{field_name}'"
            ))
            return issues
        
        # Verifica tamanho da descrição
        min_length = self.quality_rules['description_length']['min']
        max_length = self.quality_rules['description_length']['max']
        warning_threshold = self.quality_rules['description_length']['warning_threshold']
        
        if len(description) < min_length:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="description_too_short",
                severity=ValidationSeverity.WARNING,
                message=f"Descrição muito curta ({len(description)} caracteres)",
                suggestion=f"Descrição deve ter pelo menos {min_length} caracteres"
            ))
        
        if len(description) > max_length:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="description_too_long",
                severity=ValidationSeverity.WARNING,
                message=f"Descrição muito longa ({len(description)} caracteres)",
                suggestion=f"Descrição deve ter no máximo {max_length} caracteres"
            ))
        
        if len(description) < warning_threshold:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="description_short",
                severity=ValidationSeverity.INFO,
                message=f"Descrição pode ser mais detalhada ({len(description)} caracteres)",
                suggestion="Considere adicionar mais detalhes sobre o campo"
            ))
        
        # Verifica padrões obrigatórios baseados no tipo
        field_type = field_data.get('type', 'string')
        format_value = field_data.get('format', '')
        
        if format_value == 'email' or 'email' in field_name.lower():
            if not any(pattern in description.lower() for pattern in self.required_patterns['email']):
                issues.append(ValidationIssue(
                    field_path=field_path,
                    issue_type="missing_email_pattern",
                    severity=ValidationSeverity.WARNING,
                    message="Descrição deve mencionar que é um email",
                    suggestion="Adicione 'email' ou 'endereço de email' na descrição"
                ))
        
        elif format_value == 'uri' or 'url' in field_name.lower():
            if not any(pattern in description.lower() for pattern in self.required_patterns['url']):
                issues.append(ValidationIssue(
                    field_path=field_path,
                    issue_type="missing_url_pattern",
                    severity=ValidationSeverity.WARNING,
                    message="Descrição deve mencionar que é uma URL",
                    suggestion="Adicione 'URL' ou 'link' na descrição"
                ))
        
        return issues
    
    def _validate_field_examples(self, field_name: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida exemplos do campo."""
        issues = []
        
        field_type = field_data.get('type', 'string')
        examples = field_data.get('examples', [])
        
        # Verifica se tipos complexos têm exemplos
        if field_type in ['object', 'array'] and not examples:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="missing_examples",
                severity=ValidationSeverity.WARNING,
                message="Tipos complexos devem ter exemplos",
                suggestion="Adicione exemplos para facilitar o entendimento"
            ))
        
        # Verifica se exemplos são válidos
        for i, example in enumerate(examples):
            if not self._is_valid_example(example, field_type):
                issues.append(ValidationIssue(
                    field_path=f"{field_path}.examples[{i}]",
                    issue_type="invalid_example",
                    severity=ValidationSeverity.WARNING,
                    message=f"Exemplo inválido para tipo '{field_type}'",
                    suggestion="Verifique se o exemplo corresponde ao tipo do campo"
                ))
        
        return issues
    
    def _validate_field_validation(self, field_name: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida regras de validação do campo."""
        issues = []
        
        # Verifica se campos obrigatórios têm validação
        if field_name in ['email', 'password', 'url'] and 'pattern' not in field_data:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="missing_validation",
                severity=ValidationSeverity.WARNING,
                message="Campo sensível deve ter validação",
                suggestion="Adicione regex pattern para validação"
            ))
        
        # Verifica se tem min/max quando apropriado
        field_type = field_data.get('type', 'string')
        if field_type == 'string' and 'maxLength' not in field_data:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="missing_max_length",
                severity=ValidationSeverity.INFO,
                message="Campo string deve ter maxLength definido",
                suggestion="Adicione maxLength para prevenir payloads excessivos"
            ))
        
        return issues
    
    def _validate_required_field(self, field_name: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida campos obrigatórios."""
        issues = []
        
        # Verifica se tem descrição clara sobre obrigatoriedade
        description = field_data.get('description', '').lower()
        if 'obrigatório' not in description and 'required' not in description:
            issues.append(ValidationIssue(
                field_path=field_path,
                issue_type="missing_required_indication",
                severity=ValidationSeverity.WARNING,
                message="Campo obrigatório deve indicar isso na descrição",
                suggestion="Adicione 'obrigatório' ou 'required' na descrição"
            ))
        
        return issues
    
    def _validate_complex_field(self, field_name: str, field_data: Dict[str, Any], field_path: str) -> List[ValidationIssue]:
        """Valida campos complexos (object, array)."""
        issues = []
        
        field_type = field_data.get('type', 'string')
        
        if field_type == 'object':
            # Verifica se tem properties definidas
            if 'properties' not in field_data:
                issues.append(ValidationIssue(
                    field_path=field_path,
                    issue_type="missing_properties",
                    severity=ValidationSeverity.ERROR,
                    message="Campo object deve ter properties definidas",
                    suggestion="Defina as propriedades do objeto"
                ))
        
        elif field_type == 'array':
            # Verifica se tem items definido
            if 'items' not in field_data:
                issues.append(ValidationIssue(
                    field_path=field_path,
                    issue_type="missing_items",
                    severity=ValidationSeverity.ERROR,
                    message="Campo array deve ter items definido",
                    suggestion="Defina o tipo dos itens do array"
                ))
        
        return issues
    
    def _validate_required_fields(self, properties: Dict[str, Any], required_fields: List[str], schema_name: str) -> List[ValidationIssue]:
        """Valida campos obrigatórios do schema."""
        issues = []
        
        # Verifica se campos obrigatórios existem nas propriedades
        for required_field in required_fields:
            if required_field not in properties:
                issues.append(ValidationIssue(
                    field_path=f"{schema_name}.required",
                    issue_type="required_field_not_found",
                    severity=ValidationSeverity.ERROR,
                    message=f"Campo obrigatório '{required_field}' não encontrado nas propriedades",
                    suggestion=f"Adicione '{required_field}' às propriedades ou remova de required"
                ))
        
        return issues
    
    def _validate_schema_documentation(self, schema_data: Dict[str, Any], schema_name: str) -> List[ValidationIssue]:
        """Valida documentação geral do schema."""
        issues = []
        
        # Verifica se tem descrição
        if not schema_data.get('description'):
            issues.append(ValidationIssue(
                field_path=f"{schema_name}.description",
                issue_type="missing_schema_description",
                severity=ValidationSeverity.WARNING,
                message="Schema deve ter descrição",
                suggestion="Adicione uma descrição clara do propósito do schema"
            ))
        
        # Verifica se tem exemplos
        if not schema_data.get('examples'):
            issues.append(ValidationIssue(
                field_path=f"{schema_name}.examples",
                issue_type="missing_schema_examples",
                severity=ValidationSeverity.INFO,
                message="Schema pode ter exemplos de uso",
                suggestion="Adicione exemplos para facilitar o entendimento"
            ))
        
        return issues
    
    def _is_valid_example(self, example: Any, field_type: str) -> bool:
        """Verifica se exemplo é válido para o tipo."""
        try:
            if field_type == 'string':
                return isinstance(example, str)
            elif field_type == 'integer':
                return isinstance(example, int)
            elif field_type == 'number':
                return isinstance(example, (int, float))
            elif field_type == 'boolean':
                return isinstance(example, bool)
            elif field_type == 'array':
                return isinstance(example, list)
            elif field_type == 'object':
                return isinstance(example, dict)
            else:
                return True
        except:
            return False
    
    def validate_schema_file(self, file_path: Path) -> ValidationResult:
        """
        Valida um arquivo de schema.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Resultado da validação
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix == '.json':
                    schema_data = json.load(f)
                elif file_path.suffix in ['.yaml', '.yml']:
                    schema_data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Formato não suportado: {file_path.suffix}")
            
            schema_name = file_path.stem
            return self.validate_schema(schema_data, schema_name, str(file_path))
            
        except Exception as e:
            logger.error(f"Erro ao validar schema {file_path}: {e}")
            return ValidationResult(
                schema_name=file_path.stem,
                file_path=str(file_path),
                is_valid=False,
                issues=[
                    ValidationIssue(
                        field_path="file",
                        issue_type="file_error",
                        severity=ValidationSeverity.ERROR,
                        message=f"Erro ao processar arquivo: {str(e)}"
                    )
                ],
                validation_time=datetime.now(),
                total_fields=0,
                fields_with_issues=0
            )
    
    def generate_validation_report(self, schemas_path: str = "shared/schemas/") -> Dict[str, Any]:
        """
        Gera relatório de validação para todos os schemas.
        
        Args:
            schemas_path: Caminho para schemas
            
        Returns:
            Relatório estruturado
        """
        schemas_dir = Path(schemas_path)
        schema_files = list(schemas_dir.glob('*.json')) + list(schemas_dir.glob('*.yaml')) + list(schemas_dir.glob('*.yml'))
        
        validation_results = []
        total_issues = 0
        error_count = 0
        warning_count = 0
        info_count = 0
        
        for schema_file in schema_files:
            result = self.validate_schema_file(schema_file)
            validation_results.append(result)
            
            total_issues += len(result.issues)
            error_count += result.issue_count_by_severity.get('error', 0)
            warning_count += result.issue_count_by_severity.get('warning', 0)
            info_count += result.issue_count_by_severity.get('info', 0)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_schemas': len(validation_results),
                'valid_schemas': len([r for r in validation_results if r.is_valid]),
                'invalid_schemas': len([r for r in validation_results if not r.is_valid]),
                'total_issues': total_issues,
                'error_count': error_count,
                'warning_count': warning_count,
                'info_count': info_count,
                'validation_score': self._calculate_validation_score(validation_results)
            },
            'results': [asdict(result) for result in validation_results],
            'recommendations': self._generate_validation_recommendations(validation_results)
        }
        
        return report
    
    def _calculate_validation_score(self, results: List[ValidationResult]) -> float:
        """Calcula score de validação (0-100)."""
        if not results:
            return 0.0
        
        total_fields = sum(r.total_fields for r in results)
        fields_with_issues = sum(r.fields_with_issues for r in results)
        
        if total_fields == 0:
            return 100.0
        
        return max(0.0, 100.0 - (fields_with_issues / total_fields * 100))
    
    def _generate_validation_recommendations(self, results: List[ValidationResult]) -> List[str]:
        """Gera recomendações baseadas nos resultados de validação."""
        recommendations = []
        
        # Conta tipos de problemas
        issue_types = {}
        for result in results:
            for issue in result.issues:
                issue_types[issue.issue_type] = issue_types.get(issue.issue_type, 0) + 1
        
        # Gera recomendações baseadas nos problemas mais comuns
        if issue_types.get('missing_description', 0) > 0:
            recommendations.append(f"Adicionar descrições para {issue_types['missing_description']} campos")
        
        if issue_types.get('description_too_short', 0) > 0:
            recommendations.append(f"Melhorar {issue_types['description_too_short']} descrições muito curtas")
        
        if issue_types.get('missing_examples', 0) > 0:
            recommendations.append(f"Adicionar exemplos para {issue_types['missing_examples']} campos complexos")
        
        if issue_types.get('invalid_naming', 0) > 0:
            recommendations.append(f"Corrigir nomenclatura de {issue_types['invalid_naming']} campos")
        
        if issue_types.get('missing_validation', 0) > 0:
            recommendations.append(f"Adicionar validação para {issue_types['missing_validation']} campos sensíveis")
        
        if not recommendations:
            recommendations.append("Documentação está em excelente estado")
        
        return recommendations

# Instância global
doc_validator = DocumentationValidator()

def get_documentation_validator() -> DocumentationValidator:
    """Retorna instância global do validador de documentação."""
    return doc_validator

if __name__ == "__main__":
    # Teste do sistema
    validator = DocumentationValidator()
    
    # Testa validação de schema
    test_schema = {
        "type": "object",
        "description": "Schema de teste",
        "properties": {
            "user_id": {
                "type": "integer",
                "description": "ID do usuário"
            },
            "email": {
                "type": "string",
                "format": "email",
                "description": "Email do usuário"
            },
            "title": {
                "type": "string",
                "description": "Título"
            }
        },
        "required": ["user_id", "email"]
    }
    
    result = validator.validate_schema(test_schema, "test_schema")
    print(f"✅ Schema validado: {result.is_valid}")
    print(f"📊 Issues encontradas: {len(result.issues)}")
    
    for issue in result.issues:
        print(f"  {issue.severity.value.upper()}: {issue.message}")
    
    print("✅ DocumentationValidator testado com sucesso!") 