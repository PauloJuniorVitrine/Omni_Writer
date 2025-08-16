#!/usr/bin/env python3
"""
📚 AUTO DOCUMENTATION - Sistema de Auto-documentação de Contratos
Tracing ID: AUTO_DOC_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Gerar automaticamente documentação para campos de schemas
e validar consistência da documentação existente.
"""

import json
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import yaml
from dataclasses import dataclass, asdict

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/auto_documentation.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('auto_documentation')

@dataclass
class FieldDocumentation:
    """Estrutura para documentação de campo."""
    field_name: str
    field_type: str
    description: str
    is_required: bool
    default_value: Optional[Any] = None
    validation_rules: List[str] = None
    examples: List[str] = None
    generated: bool = False
    
    def __post_init__(self):
        """Inicializa listas se None."""
        if self.validation_rules is None:
            self.validation_rules = []
        if self.examples is None:
            self.examples = []

@dataclass
class SchemaDocumentation:
    """Estrutura para documentação de schema."""
    schema_name: str
    schema_type: str  # 'request', 'response', 'model'
    fields: List[FieldDocumentation]
    description: str
    generated_at: datetime
    validation_status: str = 'pending'  # 'valid', 'invalid', 'pending'
    issues: List[str] = None
    
    def __post_init__(self):
        """Inicializa lista de issues se None."""
        if self.issues is None:
            self.issues = []

class AutoDocumentationGenerator:
    """
    Gerador automático de documentação para schemas.
    
    Funcionalidades:
    - Gera descrições automáticas baseadas em nomes e tipos
    - Valida documentação existente
    - Sugere melhorias para campos sem descrição
    - Integra com OpenAPI/Swagger
    """
    
    def __init__(self, templates_path: str = "shared/schemas/"):
        """
        Inicializa o gerador de documentação.
        
        Args:
            templates_path: Caminho para schemas existentes
        """
        self.templates_path = Path(templates_path)
        self.field_patterns = self._load_field_patterns()
        self.type_descriptions = self._load_type_descriptions()
        self.validation_rules = self._load_validation_rules()
        
        logger.info("AutoDocumentationGenerator inicializado")
    
    def _load_field_patterns(self) -> Dict[str, str]:
        """Carrega padrões de nomes de campos para descrições."""
        return {
            # Campos de identificação
            r'id$': "Identificador único do recurso",
            r'_id$': "Identificador único relacionado",
            r'uuid$': "Identificador único universal (UUID)",
            
            # Campos de tempo
            r'created_at$': "Data e hora de criação",
            r'updated_at$': "Data e hora da última atualização",
            r'timestamp$': "Marca temporal da operação",
            r'date$': "Data no formato ISO 8601",
            r'time$': "Horário no formato HH:MM:SS",
            
            # Campos de usuário
            r'user_id$': "Identificador do usuário",
            r'username$': "Nome de usuário único",
            r'email$': "Endereço de email válido",
            r'password$': "Senha criptografada",
            
            # Campos de conteúdo
            r'title$': "Título do conteúdo",
            r'content$': "Conteúdo principal do texto",
            r'description$': "Descrição detalhada",
            r'body$': "Corpo principal do conteúdo",
            r'text$': "Texto livre",
            
            # Campos de status
            r'status$': "Status atual do recurso",
            r'state$': "Estado atual do processo",
            r'active$': "Indica se o recurso está ativo",
            r'enabled$': "Indica se a funcionalidade está habilitada",
            
            # Campos de configuração
            r'config$': "Configurações do sistema",
            r'settings$': "Configurações do usuário",
            r'options$': "Opções disponíveis",
            r'preferences$': "Preferências do usuário",
            
            # Campos de arquivo
            r'file$': "Arquivo anexado",
            r'filename$': "Nome do arquivo",
            r'path$': "Caminho do arquivo",
            r'url$': "URL do recurso",
            
            # Campos de categoria
            r'category$': "Categoria do conteúdo",
            r'tag$': "Tag para classificação",
            r'label$': "Rótulo descritivo",
            r'type$': "Tipo do recurso",
            
            # Campos de quantidade
            r'count$': "Número de itens",
            r'quantity$': "Quantidade numérica",
            r'amount$': "Valor monetário",
            r'size$': "Tamanho em bytes",
            
            # Campos de validação
            r'valid$': "Indica se o valor é válido",
            r'verified$': "Indica se foi verificado",
            r'approved$': "Indica se foi aprovado",
            
            # Campos de relacionamento
            r'parent_id$': "Identificador do item pai",
            r'child_id$': "Identificador do item filho",
            r'related_id$': "Identificador relacionado",
            
            # Campos de metadados
            r'meta$': "Metadados adicionais",
            r'data$': "Dados estruturados",
            r'info$': "Informações complementares",
            r'details$': "Detalhes específicos",
        }
    
    def _load_type_descriptions(self) -> Dict[str, str]:
        """Carrega descrições baseadas em tipos de dados."""
        return {
            'string': "Texto alfanumérico",
            'integer': "Número inteiro",
            'number': "Número decimal",
            'boolean': "Valor verdadeiro ou falso",
            'array': "Lista de valores",
            'object': "Objeto estruturado",
            'date': "Data no formato YYYY-MM-DD",
            'datetime': "Data e hora no formato ISO 8601",
            'email': "Endereço de email válido",
            'url': "URL válida",
            'uuid': "Identificador único universal",
            'file': "Arquivo binário",
        }
    
    def _load_validation_rules(self) -> Dict[str, List[str]]:
        """Carrega regras de validação por tipo."""
        return {
            'string': [
                "Deve ser uma string não vazia",
                "Máximo de 255 caracteres",
                "Não pode conter caracteres especiais"
            ],
            'integer': [
                "Deve ser um número inteiro",
                "Deve ser maior que zero",
                "Máximo de 2147483647"
            ],
            'number': [
                "Deve ser um número decimal",
                "Deve ser maior que zero",
                "Máximo de 2 casas decimais"
            ],
            'email': [
                "Deve ser um email válido",
                "Formato: usuario@dominio.com",
                "Máximo de 254 caracteres"
            ],
            'url': [
                "Deve ser uma URL válida",
                "Deve incluir protocolo (http/https)",
                "Máximo de 2048 caracteres"
            ],
            'uuid': [
                "Deve ser um UUID válido",
                "Formato: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ],
        }
    
    def generate_field_description(self, field_name: str, field_type: str) -> str:
        """
        Gera descrição automática para um campo.
        
        Args:
            field_name: Nome do campo
            field_type: Tipo do campo
            
        Returns:
            Descrição gerada automaticamente
        """
        # Tenta encontrar padrão no nome do campo
        for pattern, description in self.field_patterns.items():
            if re.search(pattern, field_name, re.IGNORECASE):
                return description
        
        # Se não encontrar padrão, usa descrição baseada no tipo
        type_desc = self.type_descriptions.get(field_type, "Campo de dados")
        
        # Adiciona contexto baseado no nome
        if 'name' in field_name.lower():
            return f"Nome do {type_desc.lower()}"
        elif 'value' in field_name.lower():
            return f"Valor do {type_desc.lower()}"
        elif 'code' in field_name.lower():
            return f"Código do {type_desc.lower()}"
        else:
            return f"{type_desc} para {field_name.replace('_', ' ')}"
    
    def generate_validation_rules(self, field_name: str, field_type: str) -> List[str]:
        """
        Gera regras de validação para um campo.
        
        Args:
            field_name: Nome do campo
            field_type: Tipo do campo
            
        Returns:
            Lista de regras de validação
        """
        rules = self.validation_rules.get(field_type, []).copy()
        
        # Adiciona regras específicas baseadas no nome
        if 'required' in field_name.lower() or field_name.endswith('_required'):
            rules.append("Campo obrigatório")
        
        if 'min' in field_name.lower():
            rules.append("Deve ter valor mínimo")
        
        if 'max' in field_name.lower():
            rules.append("Deve ter valor máximo")
        
        if 'unique' in field_name.lower():
            rules.append("Deve ser único no sistema")
        
        return rules
    
    def generate_examples(self, field_name: str, field_type: str) -> List[str]:
        """
        Gera exemplos para um campo.
        
        Args:
            field_name: Nome do campo
            field_type: Tipo do campo
            
        Returns:
            Lista de exemplos
        """
        examples = []
        
        if field_type == 'string':
            if 'email' in field_name.lower():
                examples = ["usuario@exemplo.com", "admin@empresa.com"]
            elif 'url' in field_name.lower():
                examples = ["https://exemplo.com", "https://api.empresa.com/v1"]
            elif 'name' in field_name.lower():
                examples = ["João Silva", "Maria Santos"]
            elif 'title' in field_name.lower():
                examples = ["Título do Artigo", "Nome do Blog"]
            else:
                examples = ["exemplo", "valor padrão"]
        
        elif field_type == 'integer':
            examples = ["1", "100", "1000"]
        
        elif field_type == 'number':
            examples = ["10.5", "99.99", "1000.00"]
        
        elif field_type == 'boolean':
            examples = ["true", "false"]
        
        elif field_type == 'uuid':
            examples = ["550e8400-e29b-41d4-a716-446655440000"]
        
        elif field_type == 'date':
            examples = ["2025-01-28", "2025-12-31"]
        
        elif field_type == 'datetime':
            examples = ["2025-01-28T10:45:00Z", "2025-12-31T23:59:59Z"]
        
        return examples
    
    def analyze_schema(self, schema_data: Dict[str, Any], schema_name: str) -> SchemaDocumentation:
        """
        Analisa um schema e gera documentação.
        
        Args:
            schema_data: Dados do schema
            schema_name: Nome do schema
            
        Returns:
            Documentação do schema
        """
        fields = []
        
        # Analisa propriedades do schema
        properties = schema_data.get('properties', {})
        required_fields = schema_data.get('required', [])
        
        for field_name, field_data in properties.items():
            field_type = field_data.get('type', 'string')
            is_required = field_name in required_fields
            
            # Gera descrição se não existir
            description = field_data.get('description')
            if not description:
                description = self.generate_field_description(field_name, field_type)
            
            # Gera regras de validação
            validation_rules = self.generate_validation_rules(field_name, field_type)
            
            # Gera exemplos
            examples = self.generate_examples(field_name, field_type)
            
            field_doc = FieldDocumentation(
                field_name=field_name,
                field_type=field_type,
                description=description,
                is_required=is_required,
                default_value=field_data.get('default'),
                validation_rules=validation_rules,
                examples=examples,
                generated=not field_data.get('description')
            )
            
            fields.append(field_doc)
        
        # Determina tipo do schema
        schema_type = 'model'
        if 'request' in schema_name.lower():
            schema_type = 'request'
        elif 'response' in schema_name.lower():
            schema_type = 'response'
        
        return SchemaDocumentation(
            schema_name=schema_name,
            schema_type=schema_type,
            fields=fields,
            description=schema_data.get('description', f"Schema para {schema_name}"),
            generated_at=datetime.now()
        )
    
    def validate_schema_documentation(self, schema_doc: SchemaDocumentation) -> Tuple[bool, List[str]]:
        """
        Valida documentação de um schema.
        
        Args:
            schema_doc: Documentação do schema
            
        Returns:
            (é_válido, lista_de_problemas)
        """
        issues = []
        
        # Verifica se todos os campos têm descrição
        for field in schema_doc.fields:
            if not field.description or field.description.strip() == '':
                issues.append(f"Campo '{field.field_name}' sem descrição")
            
            if len(field.description) < 10:
                issues.append(f"Descrição muito curta para '{field.field_name}'")
            
            if len(field.description) > 500:
                issues.append(f"Descrição muito longa para '{field.field_name}'")
        
        # Verifica se há campos obrigatórios sem validação
        required_fields = [f for f in schema_doc.fields if f.is_required]
        for field in required_fields:
            if not any('obrigatório' in rule.lower() for rule in field.validation_rules):
                issues.append(f"Campo obrigatório '{field.field_name}' sem regra de obrigatoriedade")
        
        # Verifica se há exemplos para campos complexos
        complex_types = ['object', 'array']
        for field in schema_doc.fields:
            if field.field_type in complex_types and not field.examples:
                issues.append(f"Campo complexo '{field.field_name}' sem exemplos")
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    def update_schema_with_documentation(self, schema_data: Dict[str, Any], schema_doc: SchemaDocumentation) -> Dict[str, Any]:
        """
        Atualiza schema com documentação gerada.
        
        Args:
            schema_data: Schema original
            schema_doc: Documentação gerada
            
        Returns:
            Schema atualizado
        """
        updated_schema = schema_data.copy()
        
        # Atualiza descrição do schema se não existir
        if not updated_schema.get('description'):
            updated_schema['description'] = schema_doc.description
        
        # Atualiza propriedades com documentação
        for field_doc in schema_doc.fields:
            if field_doc.generated:  # Apenas campos gerados automaticamente
                if 'properties' not in updated_schema:
                    updated_schema['properties'] = {}
                
                if field_doc.field_name not in updated_schema['properties']:
                    updated_schema['properties'][field_doc.field_name] = {}
                
                field_data = updated_schema['properties'][field_doc.field_name]
                field_data['description'] = field_doc.description
                
                # Adiciona exemplos se não existirem
                if not field_data.get('examples') and field_doc.examples:
                    field_data['examples'] = field_doc.examples
                
                # Adiciona validações se não existirem
                if not field_data.get('validation') and field_doc.validation_rules:
                    field_data['validation'] = field_doc.validation_rules
        
        return updated_schema
    
    def process_schema_file(self, file_path: Path) -> SchemaDocumentation:
        """
        Processa um arquivo de schema.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Documentação gerada
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix == '.json':
                    schema_data = json.load(f)
                elif file_path.suffix == '.yaml' or file_path.suffix == '.yml':
                    schema_data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Formato de arquivo não suportado: {file_path.suffix}")
            
            schema_name = file_path.stem
            schema_doc = self.analyze_schema(schema_data, schema_name)
            
            # Valida documentação
            is_valid, issues = self.validate_schema_documentation(schema_doc)
            schema_doc.validation_status = 'valid' if is_valid else 'invalid'
            schema_doc.issues = issues
            
            logger.info(f"Schema processado: {schema_name} - Status: {schema_doc.validation_status}")
            
            return schema_doc
            
        except Exception as e:
            logger.error(f"Erro ao processar schema {file_path}: {e}")
            return SchemaDocumentation(
                schema_name=file_path.stem,
                schema_type='unknown',
                fields=[],
                description=f"Erro ao processar: {str(e)}",
                generated_at=datetime.now(),
                validation_status='error',
                issues=[str(e)]
            )
    
    def generate_documentation_report(self, schemas_path: str = None) -> Dict[str, Any]:
        """
        Gera relatório de documentação para todos os schemas.
        
        Args:
            schemas_path: Caminho para schemas (usa self.templates_path se None)
            
        Returns:
            Relatório estruturado
        """
        if schemas_path is None:
            schemas_path = self.templates_path
        
        schemas_dir = Path(schemas_path)
        schema_files = list(schemas_dir.glob('*.json')) + list(schemas_dir.glob('*.yaml')) + list(schemas_dir.glob('*.yml'))
        
        schemas_doc = []
        total_fields = 0
        fields_without_description = 0
        fields_generated = 0
        
        for schema_file in schema_files:
            schema_doc = self.process_schema_file(schema_file)
            schemas_doc.append(schema_doc)
            
            total_fields += len(schema_doc.fields)
            fields_without_description += len([f for f in schema_doc.fields if not f.description])
            fields_generated += len([f for f in schema_doc.fields if f.generated])
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_schemas': len(schemas_doc),
                'total_fields': total_fields,
                'fields_without_description': fields_without_description,
                'fields_generated': fields_generated,
                'coverage_percentage': ((total_fields - fields_without_description) / total_fields * 100) if total_fields > 0 else 0
            },
            'schemas': [asdict(schema) for schema in schemas_doc],
            'recommendations': self._generate_recommendations(schemas_doc)
        }
        
        return report
    
    def _generate_recommendations(self, schemas_doc: List[SchemaDocumentation]) -> List[str]:
        """Gera recomendações baseadas na análise."""
        recommendations = []
        
        total_schemas = len(schemas_doc)
        invalid_schemas = len([s for s in schemas_doc if s.validation_status == 'invalid'])
        
        if invalid_schemas > 0:
            recommendations.append(f"Corrigir documentação em {invalid_schemas} schemas inválidos")
        
        fields_without_desc = sum(len([f for f in s.fields if not f.description]) for s in schemas_doc)
        if fields_without_desc > 0:
            recommendations.append(f"Adicionar descrições para {fields_without_desc} campos")
        
        complex_fields = sum(len([f for f in s.fields if f.field_type in ['object', 'array'] and not f.examples]) for s in schemas_doc)
        if complex_fields > 0:
            recommendations.append(f"Adicionar exemplos para {complex_fields} campos complexos")
        
        if not recommendations:
            recommendations.append("Documentação está em bom estado")
        
        return recommendations

# Instância global
auto_doc_generator = AutoDocumentationGenerator()

def get_auto_documentation_generator() -> AutoDocumentationGenerator:
    """Retorna instância global do gerador de documentação."""
    return auto_doc_generator

if __name__ == "__main__":
    # Teste do sistema
    generator = AutoDocumentationGenerator()
    
    # Testa geração de descrições
    test_fields = [
        ("user_id", "integer"),
        ("email", "string"),
        ("created_at", "datetime"),
        ("title", "string"),
        ("content", "string"),
        ("status", "string"),
        ("file_size", "integer"),
    ]
    
    print("🧪 Testando geração de descrições:")
    for field_name, field_type in test_fields:
        description = generator.generate_field_description(field_name, field_type)
        print(f"  {field_name} ({field_type}): {description}")
    
    # Testa processamento de schema
    test_schema = {
        "type": "object",
        "properties": {
            "user_id": {"type": "integer"},
            "email": {"type": "string"},
            "title": {"type": "string"},
            "content": {"type": "string"}
        },
        "required": ["user_id", "email"]
    }
    
    schema_doc = generator.analyze_schema(test_schema, "test_schema")
    print(f"\n📊 Schema processado: {len(schema_doc.fields)} campos")
    
    # Valida documentação
    is_valid, issues = generator.validate_schema_documentation(schema_doc)
    print(f"✅ Validação: {'Válido' if is_valid else 'Inválido'}")
    if issues:
        print(f"⚠️ Problemas: {len(issues)} encontrados")
    
    print("✅ AutoDocumentationGenerator testado com sucesso!") 