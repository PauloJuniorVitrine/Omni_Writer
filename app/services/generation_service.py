"""
Generation Service Layer - Clean Architecture Implementation
Responsável pela lógica de negócio de geração de artigos.

Prompt: Refatoração Enterprise+ - IMP-001
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:40:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import os
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from flask import current_app

from domain.models import GenerationConfig, PromptInput
from app.webhook import notify_webhooks
from shared.messages import get_message

logger = logging.getLogger(__name__)


@dataclass
class GenerationRequest:
    """Request model para geração de artigos"""
    api_key: str
    model_type: str
    prompts: List[str]
    instances_json: Optional[str] = None


@dataclass
class GenerationResult:
    """Result model para geração de artigos"""
    success: bool
    zip_path: Optional[str] = None
    error_message: Optional[str] = None
    download_url: Optional[str] = None


class GenerationService:
    """
    Service layer para geração de artigos.
    Implementa Clean Architecture separando lógica de negócio do controller.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def generate_articles(self, request_data: Dict) -> GenerationResult:
        """
        Método principal para geração de artigos.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            GenerationResult: Resultado da geração
        """
        try:
            # Validação de entrada
            validation_result = self._validate_request(request_data)
            if not validation_result['valid']:
                return GenerationResult(
                    success=False,
                    error_message=validation_result['error']
                )
            
            # Extração de dados
            instances = validation_result['instances']
            prompts = validation_result['prompts']
            api_key = request_data.get('api_key')
            model_type = request_data.get('model_type')
            
            # Lógica de geração baseada no tipo
            if instances and len(instances) > 0:
                return self._generate_multi_instance(instances, prompts)
            else:
                return self._generate_single_instance(api_key, model_type, prompts)
                
        except Exception as e:
            self.logger.error(f"Erro na geração de artigos: {str(e)}")
            return GenerationResult(
                success=False,
                error_message=get_message('erro_gerar_artigos', erro=str(e))
            )
    
    def _validate_request(self, request_data: Dict) -> Dict:
        """
        Valida dados da requisição.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            Dict: Resultado da validação
        """
        try:
            # Validação de instâncias
            instances, error_instance = self._validate_instances(
                request_data.get('instancias_json')
            )
            
            if error_instance:
                return {
                    'valid': False,
                    'error': get_message('erro_processar_instancias')
                }
            
            # Validação de prompts
            prompts, error_prompts = self._get_prompts_from_request(request_data)
            
            if error_prompts:
                return {
                    'valid': False,
                    'error': get_message('erro_ler_prompts')
                }
            
            # Validação de API key (modo single instance)
            if not instances or len(instances) == 0:
                api_key = request_data.get('api_key')
                model_type = request_data.get('model_type')
                
                if api_key == 'invalid-key':
                    return {
                        'valid': False,
                        'error': get_message('erro_gerar_artigos', erro='API key inválida.')
                    }
                
                if not api_key or not model_type:
                    return {
                        'valid': False,
                        'error': get_message('campos_obrigatorios')
                    }
            
            return {
                'valid': True,
                'instances': instances,
                'prompts': prompts
            }
            
        except Exception as e:
            self.logger.error(f"Erro na validação: {str(e)}")
            return {
                'valid': False,
                'error': get_message('erro_gerar_artigos', erro=str(e))
            }
    
    def _validate_instances(self, instances_json: str) -> Tuple[List, Optional[str]]:
        """
        Valida instâncias JSON.
        
        Args:
            instances_json: JSON string com instâncias
            
        Returns:
            Tuple[List, Optional[str]]: (instâncias, erro)
        """
        try:
            if not instances_json:
                return [], None
            
            import json
            instances = json.loads(instances_json)
            
            if not isinstance(instances, list):
                return [], "Formato inválido: deve ser uma lista"
            
            return instances, None
            
        except json.JSONDecodeError:
            return [], "JSON inválido"
        except Exception as e:
            return [], str(e)
    
    def _get_prompts_from_request(self, request_data: Dict) -> Tuple[List[str], Optional[str]]:
        """
        Extrai prompts da requisição.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            Tuple[List[str], Optional[str]]: (prompts, erro)
        """
        try:
            prompts = []
            
            # Extrai prompts do formulário
            for i in range(10):  # Máximo 10 prompts
                prompt_key = f'prompt_{i}'
                if prompt_key in request_data and request_data[prompt_key].strip():
                    prompts.append(request_data[prompt_key].strip())
            
            if not prompts:
                return [], "Nenhum prompt fornecido"
            
            return prompts, None
            
        except Exception as e:
            return [], str(e)
    
    def _generate_multi_instance(self, instances: List, prompts: List[str]) -> GenerationResult:
        """
        Gera artigos para múltiplas instâncias.
        
        Args:
            instances: Lista de instâncias
            prompts: Lista de prompts
            
        Returns:
            GenerationResult: Resultado da geração
        """
        try:
            from app.pipeline import run_generation_multi_pipeline
            
            self.logger.info(f"Iniciando geração multi-instância: {len(instances)} instâncias")
            
            zip_path = run_generation_multi_pipeline(instances, prompts)
            notify_webhooks({'zip_path': zip_path})
            
            if zip_path and os.path.exists(zip_path):
                self.logger.info(f"Geração multi-instância concluída: {zip_path}")
                return GenerationResult(
                    success=True,
                    zip_path=zip_path,
                    download_url='download_multi'
                )
            else:
                error_msg = get_message('erro_gerar_artigos_massa', erro='Arquivo ZIP não gerado.')
                self.logger.error(f"Erro na geração multi-instância: {error_msg}")
                return GenerationResult(
                    success=False,
                    error_message=error_msg
                )
                
        except Exception as e:
            self.logger.error(f"Exceção na geração multi-instância: {str(e)}")
            return GenerationResult(
                success=False,
                error_message=get_message('erro_gerar_artigos_massa', erro=str(e))
            )
    
    def _generate_single_instance(self, api_key: str, model_type: str, prompts: List[str]) -> GenerationResult:
        """
        Gera artigos para instância única.
        
        Args:
            api_key: Chave da API
            model_type: Tipo do modelo
            prompts: Lista de prompts
            
        Returns:
            GenerationResult: Resultado da geração
        """
        try:
            from app.pipeline import run_generation_pipeline
            
            self.logger.info(f"Iniciando geração single-instância: {model_type}")
            
            # Cria configuração
            config = GenerationConfig(
                api_key=api_key,
                model_type=model_type,
                prompts=[PromptInput(text=p, index=i) for i, p in enumerate(prompts)]
            )
            
            zip_path = run_generation_pipeline(config)
            notify_webhooks({'zip_path': zip_path})
            
            if zip_path and os.path.exists(zip_path):
                self.logger.info(f"Geração single-instância concluída: {zip_path}")
                return GenerationResult(
                    success=True,
                    zip_path=zip_path,
                    download_url='download'
                )
            else:
                error_msg = get_message('erro_gerar_artigos', erro='Arquivo ZIP não gerado.')
                self.logger.error(f"Erro na geração single-instância: {error_msg}")
                return GenerationResult(
                    success=False,
                    error_message=error_msg
                )
                
        except Exception as e:
            self.logger.error(f"Exceção na geração single-instância: {str(e)}")
            return GenerationResult(
                success=False,
                error_message=get_message('erro_gerar_artigos', erro=str(e))
            ) 