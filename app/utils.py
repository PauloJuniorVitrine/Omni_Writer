"""
Utility functions for validation, prompt extraction, and auxiliary data handling.
"""
from typing import Tuple, Any
from flask import Request
import json

def validate_instances(instances_json: str) -> Tuple[Any, Any]:
    """
    Validates and processes the JSON of instances received from the form.
    Returns a tuple (instances, error).
    """
    if not instances_json:
        return None, 'JSON de instâncias vazio.'
    try:
        instances = json.loads(instances_json)
        if not isinstance(instances, list):
            return None, 'Formato inválido: esperado uma lista.'
        return instances, None
    except Exception as e:
        return None, str(e)

def get_prompts(request: Request) -> Tuple[Any, Any]:
    """
    Extracts and validates prompts from the received request.
    Returns a tuple (prompts, error).
    """
    try:
        prompts = []
        if 'prompts[]' in request.form:
            prompts = request.form.getlist('prompts[]')
        elif 'prompts' in request.form:
            prompts = [request.form.get('prompts')]
        elif request.files.get('prompts_file'):
            file = request.files['prompts_file']
            
            # Validação de segurança do upload
            try:
                from shared.upload_security import validate_upload
                client_ip = request.remote_addr
                is_valid, error, metadata = validate_upload(file, client_ip)
                
                if not is_valid:
                    return None, f'Erro de segurança no upload: {error}'
                
                # Lê conteúdo sanitizado
                file.seek(0)
                content = file.read().decode('utf-8')
                prompts = [line.strip() for line in content.splitlines() if line.strip()]
                
            except ImportError:
                # Fallback para validação básica se módulo não disponível
                prompts = [line.strip() for line in file.read().decode('utf-8').splitlines() if line.strip()]
        
        if not prompts or all(p == '' for p in prompts):
            return None, 'Nenhum prompt fornecido.'
        return prompts, None
    except Exception as e:
        return None, str(e) 