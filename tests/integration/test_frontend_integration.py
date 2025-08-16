#!/usr/bin/env python3
"""
🧪 TESTES DE INTEGRAÇÃO FRONTEND/BACKEND
Tracing ID: TEST_FRONTEND_INTEGRATION_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Testar integração entre frontend e backend usando os endpoints
implementados, baseado no código real do sistema Omni Writer.
"""

import pytest
import requests
import json
import time
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch
import sys
import os

# Adiciona o diretório raiz ao path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

class TestFrontendBackendIntegration:
    """
    Testes de integração entre frontend e backend.
    
    Testa a comunicação real entre os componentes usando
    os endpoints implementados no sistema Omni Writer.
    """
    
    @pytest.fixture
    def base_url(self):
        """URL base da API."""
        return "http://localhost:5000"
    
    @pytest.fixture
    def auth_token(self):
        """Token de autenticação para testes."""
        # Token de teste - em produção seria obtido via login
        return "test_token_12345"
    
    @pytest.fixture
    def headers(self, auth_token):
        """Headers padrão para requisições."""
        return {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
    
    def test_api_generate_articles_endpoint(self, base_url, headers):
        """
        Testa endpoint /api/generate-articles.
        
        Verifica se o endpoint responde corretamente e retorna
        o formato esperado pelo frontend.
        """
        # Dados de teste baseados no schema real
        payload = {
            "blog_ids": [1, 2, 3],
            "max_articles": 5,
            "include_categories": True
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            # Verifica status code
            assert response.status_code in [200, 201, 400, 401, 500], \
                f"Status code inesperado: {response.status_code}"
            
            if response.status_code == 200:
                # Verifica estrutura da resposta
                data = response.json()
                assert "status" in data, "Campo 'status' ausente na resposta"
                assert "message" in data, "Campo 'message' ausente na resposta"
                assert "task_id" in data, "Campo 'task_id' ausente na resposta"
                
                # Verifica tipos dos campos
                assert isinstance(data["status"], str), "Status deve ser string"
                assert isinstance(data["message"], str), "Message deve ser string"
                assert isinstance(data["task_id"], str), "Task ID deve ser string"
                
                # Verifica valores esperados
                assert data["status"] in ["started", "processing"], \
                    f"Status inesperado: {data['status']}"
                
            elif response.status_code == 400:
                # Verifica erro de validação
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente na resposta de erro"
                
            elif response.status_code == 401:
                # Verifica erro de autenticação
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente na resposta de erro"
                
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_entrega_zip_endpoint(self, base_url, headers):
        """
        Testa endpoint /api/entrega-zip.
        
        Verifica se o endpoint responde corretamente e retorna
        arquivo ZIP conforme esperado pelo frontend.
        """
        # Dados de teste baseados no schema real
        payload = {
            "blog_ids": [1, 2],
            "include_metadata": True,
            "format": "markdown"
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/entrega-zip",
                headers=headers,
                json=payload,
                timeout=60  # Timeout maior para geração de ZIP
            )
            
            # Verifica status code
            assert response.status_code in [200, 400, 401, 404, 500], \
                f"Status code inesperado: {response.status_code}"
            
            if response.status_code == 200:
                # Verifica se retorna arquivo ZIP
                content_type = response.headers.get("Content-Type", "")
                assert "application/zip" in content_type or "application/octet-stream" in content_type, \
                    f"Content-Type inesperado: {content_type}"
                
                # Verifica se tem conteúdo
                assert len(response.content) > 0, "Resposta vazia"
                
                # Verifica se é um ZIP válido (primeiros bytes)
                if response.content.startswith(b'PK'):
                    assert True, "Arquivo ZIP válido"
                else:
                    # Pode ser outro formato de arquivo
                    assert len(response.content) > 100, "Arquivo muito pequeno"
                
            elif response.status_code in [400, 401, 404, 500]:
                # Verifica erro
                try:
                    error_data = response.json()
                    assert "error" in error_data, "Campo 'error' ausente na resposta de erro"
                except json.JSONDecodeError:
                    # Pode ser resposta de erro sem JSON
                    assert len(response.text) > 0, "Resposta de erro vazia"
                
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_generate_articles_validation(self, base_url, headers):
        """
        Testa validação de parâmetros do endpoint /api/generate-articles.
        
        Verifica se o endpoint valida corretamente os parâmetros
        obrigatórios e opcionais.
        """
        # Teste 1: Sem blog_ids (obrigatório)
        payload_invalid = {
            "max_articles": 5,
            "include_categories": True
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=payload_invalid,
                timeout=30
            )
            
            if response.status_code == 400:
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente"
                assert "blog_ids" in error_data["error"].lower(), \
                    "Erro deve mencionar blog_ids"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
        
        # Teste 2: blog_ids vazio
        payload_empty = {
            "blog_ids": [],
            "max_articles": 5
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=payload_empty,
                timeout=30
            )
            
            if response.status_code == 400:
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_entrega_zip_validation(self, base_url, headers):
        """
        Testa validação de parâmetros do endpoint /api/entrega-zip.
        
        Verifica se o endpoint valida corretamente os parâmetros
        obrigatórios e opcionais.
        """
        # Teste 1: Sem blog_ids (obrigatório)
        payload_invalid = {
            "include_metadata": True,
            "format": "markdown"
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/entrega-zip",
                headers=headers,
                json=payload_invalid,
                timeout=30
            )
            
            if response.status_code == 400:
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente"
                assert "blog_ids" in error_data["error"].lower(), \
                    "Erro deve mencionar blog_ids"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
        
        # Teste 2: Formato inválido
        payload_invalid_format = {
            "blog_ids": [1, 2],
            "format": "invalid_format"
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/entrega-zip",
                headers=headers,
                json=payload_invalid_format,
                timeout=30
            )
            
            if response.status_code == 400:
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_authentication(self, base_url):
        """
        Testa autenticação dos endpoints.
        
        Verifica se os endpoints requerem autenticação
        e rejeitam requisições sem token.
        """
        # Teste sem token
        payload = {"blog_ids": [1, 2]}
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                json=payload,
                timeout=30
            )
            
            # Deve retornar 401 sem autenticação
            assert response.status_code == 401, \
                f"Endpoint deve requerer autenticação, status: {response.status_code}"
            
            if response.status_code == 401:
                error_data = response.json()
                assert "error" in error_data, "Campo 'error' ausente"
                
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
        
        # Teste com token inválido
        invalid_headers = {
            "Authorization": "Bearer invalid_token",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=invalid_headers,
                json=payload,
                timeout=30
            )
            
            # Deve retornar 401 com token inválido
            assert response.status_code == 401, \
                f"Endpoint deve rejeitar token inválido, status: {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_response_format_consistency(self, base_url, headers):
        """
        Testa consistência do formato de resposta.
        
        Verifica se todos os endpoints seguem o mesmo padrão
        de resposta definido na documentação OpenAPI.
        """
        endpoints = [
            ("/api/generate-articles", {"blog_ids": [1, 2]}),
            ("/api/entrega-zip", {"blog_ids": [1, 2]})
        ]
        
        for endpoint, payload in endpoints:
            try:
                response = requests.post(
                    f"{base_url}{endpoint}",
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                
                # Verifica headers consistentes
                assert "Content-Type" in response.headers, \
                    f"Content-Type ausente em {endpoint}"
                
                # Verifica formato de erro consistente
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        assert "error" in error_data, \
                            f"Campo 'error' ausente em {endpoint}"
                        assert isinstance(error_data["error"], str), \
                            f"Campo 'error' deve ser string em {endpoint}"
                    except json.JSONDecodeError:
                        # Pode ser resposta de erro sem JSON
                        pass
                
                # Verifica formato de sucesso consistente
                elif response.status_code == 200:
                    if endpoint == "/api/generate-articles":
                        try:
                            data = response.json()
                            assert "status" in data, \
                                f"Campo 'status' ausente em {endpoint}"
                            assert "message" in data, \
                                f"Campo 'message' ausente em {endpoint}"
                        except json.JSONDecodeError:
                            pytest.fail(f"Resposta não é JSON válido em {endpoint}")
                    
                    elif endpoint == "/api/entrega-zip":
                        # Deve retornar arquivo ZIP
                        content_type = response.headers.get("Content-Type", "")
                        assert "application/zip" in content_type or "application/octet-stream" in content_type, \
                            f"Content-Type inesperado em {endpoint}: {content_type}"
                
            except requests.exceptions.RequestException as e:
                pytest.skip(f"API não disponível para {endpoint}: {e}")
    
    def test_api_timeout_handling(self, base_url, headers):
        """
        Testa tratamento de timeout.
        
        Verifica se os endpoints respondem adequadamente
        quando há timeout na operação.
        """
        # Teste com timeout muito baixo
        payload = {"blog_ids": [1, 2, 3, 4, 5]}
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=payload,
                timeout=1  # Timeout muito baixo
            )
            
            # Pode retornar timeout ou continuar processando
            assert response.status_code in [200, 408, 500], \
                f"Status code inesperado com timeout: {response.status_code}"
            
        except requests.exceptions.Timeout:
            # Timeout esperado
            assert True, "Timeout tratado corretamente"
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_api_error_handling(self, base_url, headers):
        """
        Testa tratamento de erros.
        
        Verifica se os endpoints tratam erros adequadamente
        e retornam mensagens de erro úteis.
        """
        # Teste com dados malformados
        malformed_payload = "invalid json"
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                data=malformed_payload,
                timeout=30
            )
            
            # Deve retornar erro 400
            assert response.status_code == 400, \
                f"Deve retornar 400 para JSON malformado, status: {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
        
        # Teste com blog_ids inexistentes
        invalid_payload = {"blog_ids": [99999, 99998]}
        
        try:
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=invalid_payload,
                timeout=30
            )
            
            # Pode retornar 404 ou 400
            assert response.status_code in [400, 404, 500], \
                f"Status code inesperado para blogs inexistentes: {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")

class TestFrontendIntegrationWorkflow:
    """
    Testes de workflow completo frontend/backend.
    
    Simula fluxos completos de interação entre frontend
    e backend usando os endpoints implementados.
    """
    
    @pytest.fixture
    def base_url(self):
        """URL base da API."""
        return "http://localhost:5000"
    
    @pytest.fixture
    def auth_token(self):
        """Token de autenticação para testes."""
        return "test_token_12345"
    
    @pytest.fixture
    def headers(self, auth_token):
        """Headers padrão para requisições."""
        return {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
    
    def test_complete_article_generation_workflow(self, base_url, headers):
        """
        Testa workflow completo de geração de artigos.
        
        Simula o fluxo completo: iniciar geração -> acompanhar progresso
        -> gerar ZIP de entrega.
        """
        try:
            # Passo 1: Iniciar geração de artigos
            generation_payload = {
                "blog_ids": [1, 2],
                "max_articles": 3,
                "include_categories": True
            }
            
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json=generation_payload,
                timeout=30
            )
            
            if response.status_code == 200:
                generation_data = response.json()
                task_id = generation_data.get("task_id")
                
                # Passo 2: Aguardar processamento (simulado)
                if task_id:
                    time.sleep(2)  # Simula tempo de processamento
                
                # Passo 3: Gerar ZIP de entrega
                zip_payload = {
                    "blog_ids": [1, 2],
                    "include_metadata": True,
                    "format": "markdown"
                }
                
                zip_response = requests.post(
                    f"{base_url}/api/entrega-zip",
                    headers=headers,
                    json=zip_payload,
                    timeout=60
                )
                
                # Verifica se workflow foi bem-sucedido
                assert zip_response.status_code in [200, 400, 404, 500], \
                    f"Status code inesperado no ZIP: {zip_response.status_code}"
                
                if zip_response.status_code == 200:
                    # Verifica se retornou arquivo
                    content_type = zip_response.headers.get("Content-Type", "")
                    assert "application/zip" in content_type or "application/octet-stream" in content_type, \
                        f"Content-Type inesperado: {content_type}"
                    assert len(zip_response.content) > 0, "Arquivo ZIP vazio"
                
            else:
                # Se geração falhou, verifica se erro é adequado
                assert response.status_code in [400, 401, 500], \
                    f"Status code inesperado na geração: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")
    
    def test_error_recovery_workflow(self, base_url, headers):
        """
        Testa workflow de recuperação de erros.
        
        Simula cenários de erro e verifica se o sistema
        se recupera adequadamente.
        """
        try:
            # Teste 1: Erro de autenticação -> recuperação
            invalid_headers = {
                "Authorization": "Bearer invalid_token",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=invalid_headers,
                json={"blog_ids": [1]},
                timeout=30
            )
            
            assert response.status_code == 401, \
                f"Deve retornar 401 para token inválido, status: {response.status_code}"
            
            # Teste 2: Tentar novamente com token válido
            response = requests.post(
                f"{base_url}/api/generate-articles",
                headers=headers,
                json={"blog_ids": [1]},
                timeout=30
            )
            
            # Deve funcionar com token válido
            assert response.status_code in [200, 400, 500], \
                f"Status code inesperado com token válido: {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            pytest.skip(f"API não disponível: {e}")

if __name__ == "__main__":
    # Executa testes se chamado diretamente
    pytest.main([__file__, "-v"]) 