#!/usr/bin/env python3
"""
Script de Configuração - Sistemas Críticos Omni Writer
=======================================================

Configura e valida os sistemas críticos implementados:
- Paralelismo controlado na geração
- Cache inteligente avançado
- Sistema de retry inteligente
- Validação de prompts avançada

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import os
import sys
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Any

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

from omni_writer.domain.parallel_generator import ParallelArticleGenerator
from omni_writer.domain.intelligent_cache import IntelligentCache
from omni_writer.domain.smart_retry import SmartRetry
from omni_writer.domain.prompt_validator import PromptValidator
from omni_writer.domain.integrated_generator import IntegratedArticleGenerator

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/critical_systems_setup.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class CriticalSystemsSetup:
    """
    Configurador dos sistemas críticos
    """
    
    def __init__(self, config_path: str = "config/critical_systems.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.setup_results = {}
        
        # Cria diretórios necessários
        self._create_directories()
    
    def _load_config(self) -> Dict[str, Any]:
        """Carrega configuração dos sistemas críticos"""
        default_config = {
            "parallel_generation": {
                "max_workers": 5,
                "rate_limits": {
                    "openai": {"requests_per_minute": 60, "max_concurrent": 10},
                    "deepseek": {"requests_per_minute": 60, "max_concurrent": 8},
                    "gemini": {"requests_per_minute": 60, "max_concurrent": 5},
                    "claude": {"requests_per_minute": 50, "max_concurrent": 3}
                }
            },
            "intelligent_cache": {
                "max_size_mb": 100,
                "cache_dir": "cache",
                "default_ttl": 3600,
                "max_entries": 1000
            },
            "smart_retry": {
                "max_retries": 3,
                "base_delay": 1.0,
                "max_delay": 60.0,
                "backoff_multiplier": 2.0,
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "recovery_timeout": 60.0
                }
            },
            "prompt_validation": {
                "min_prompt_length": 10,
                "max_prompt_length": 4000,
                "similarity_threshold": 0.85
            },
            "output": {
                "base_dir": "output",
                "cache_dir": "cache",
                "logs_dir": "logs"
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # Merge com configuração padrão
                    self._merge_configs(default_config, user_config)
            except Exception as e:
                logger.warning(f"Erro ao carregar configuração: {e}. Usando padrão.")
        
        return default_config
    
    def _merge_configs(self, default: Dict, user: Dict):
        """Mescla configuração do usuário com padrão"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_configs(default[key], value)
            else:
                default[key] = value
    
    def _create_directories(self):
        """Cria diretórios necessários"""
        directories = [
            self.config["output"]["base_dir"],
            self.config["output"]["cache_dir"],
            self.config["output"]["logs_dir"],
            "cache",
            "logs"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.info(f"Diretório criado/verificado: {directory}")
    
    def setup_parallel_generation(self) -> bool:
        """Configura sistema de paralelismo"""
        try:
            logger.info("Configurando sistema de paralelismo...")
            
            # Testa criação do gerador paralelo
            mock_session = self._create_mock_session()
            generator = ParallelArticleGenerator(
                session=mock_session,
                output_dir=self.config["output"]["base_dir"],
                max_workers=self.config["parallel_generation"]["max_workers"]
            )
            
            # Testa rate limiter
            rate_limiter = generator.rate_limiter
            assert rate_limiter.can_proceed('openai') is True
            
            # Testa configurações
            openai_config = rate_limiter.configs['openai']
            expected_requests = self.config["parallel_generation"]["rate_limits"]["openai"]["requests_per_minute"]
            assert openai_config.requests_per_minute == expected_requests
            
            generator.shutdown()
            
            self.setup_results["parallel_generation"] = {
                "status": "success",
                "max_workers": self.config["parallel_generation"]["max_workers"],
                "rate_limits_configured": len(self.config["parallel_generation"]["rate_limits"])
            }
            
            logger.info("✅ Sistema de paralelismo configurado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar paralelismo: {e}")
            self.setup_results["parallel_generation"] = {
                "status": "error",
                "error": str(e)
            }
            return False
    
    def setup_intelligent_cache(self) -> bool:
        """Configura cache inteligente"""
        try:
            logger.info("Configurando cache inteligente...")
            
            cache = IntelligentCache(
                max_size_mb=self.config["intelligent_cache"]["max_size_mb"],
                cache_dir=self.config["intelligent_cache"]["cache_dir"]
            )
            
            # Testa operações básicas
            test_prompt = "Teste de prompt para validação do cache"
            test_content = "Conteúdo de teste gerado"
            
            # Testa set/get
            cache.set(test_prompt, test_content, "openai", "gpt-4o")
            retrieved_content = cache.get(test_prompt, "openai", "gpt-4o")
            
            assert retrieved_content == test_content
            
            # Testa métricas
            metrics = cache.get_metrics()
            assert metrics["total_requests"] > 0
            assert metrics["cache_hits"] > 0
            
            cache.clear()
            
            self.setup_results["intelligent_cache"] = {
                "status": "success",
                "max_size_mb": self.config["intelligent_cache"]["max_size_mb"],
                "cache_dir": self.config["intelligent_cache"]["cache_dir"]
            }
            
            logger.info("✅ Cache inteligente configurado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar cache: {e}")
            self.setup_results["intelligent_cache"] = {
                "status": "error",
                "error": str(e)
            }
            return False
    
    def setup_smart_retry(self) -> bool:
        """Configura sistema de retry inteligente"""
        try:
            logger.info("Configurando sistema de retry inteligente...")
            
            retry_system = SmartRetry()
            
            # Testa configurações de retry
            openai_config = retry_system.retry_configs['openai']
            expected_retries = self.config["smart_retry"]["max_retries"]
            assert openai_config.max_retries == expected_retries
            
            # Testa circuit breaker
            circuit_breaker = retry_system.circuit_breakers['openai']
            assert circuit_breaker.can_execute() is True
            
            # Testa operação simples
            def test_operation():
                return "success"
            
            result = retry_system.execute_with_retry(test_operation, "openai")
            assert result == "success"
            
            # Testa métricas
            metrics = retry_system.get_metrics()
            assert "providers" in metrics
            assert "circuit_breakers" in metrics
            
            self.setup_results["smart_retry"] = {
                "status": "success",
                "max_retries": self.config["smart_retry"]["max_retries"],
                "providers_configured": len(retry_system.retry_configs)
            }
            
            logger.info("✅ Sistema de retry inteligente configurado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar retry: {e}")
            self.setup_results["smart_retry"] = {
                "status": "error",
                "error": str(e)
            }
            return False
    
    def setup_prompt_validation(self) -> bool:
        """Configura validação de prompts"""
        try:
            logger.info("Configurando validação de prompts...")
            
            validator = PromptValidator()
            
            # Testa validação de prompt válido
            valid_prompt = "Escreva um artigo sobre tecnologia com 500 palavras"
            result = validator.validate_prompt(valid_prompt, "gpt-4o")
            
            assert result.is_valid is True
            assert result.confidence_score > 0.5
            assert result.token_estimate is not None
            
            # Testa validação de prompt inválido
            invalid_prompt = ""
            result = validator.validate_prompt(invalid_prompt, "gpt-4o")
            
            assert result.is_valid is False
            assert len(result.issues) > 0
            
            # Testa identificação de tipo de prompt
            article_prompt = "Crie um artigo sobre marketing digital"
            result = validator.validate_prompt(article_prompt, "gpt-4o")
            
            assert result.prompt_type.value in ["article", "blog_post", "unknown"]
            
            self.setup_results["prompt_validation"] = {
                "status": "success",
                "min_prompt_length": validator.min_prompt_length,
                "max_prompt_length": validator.max_prompt_length
            }
            
            logger.info("✅ Validação de prompts configurada com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar validação: {e}")
            self.setup_results["prompt_validation"] = {
                "status": "error",
                "error": str(e)
            }
            return False
    
    def setup_integrated_generator(self) -> bool:
        """Configura gerador integrado"""
        try:
            logger.info("Configurando gerador integrado...")
            
            mock_session = self._create_mock_session()
            generator = IntegratedArticleGenerator(
                session=mock_session,
                output_dir=self.config["output"]["base_dir"],
                max_workers=self.config["parallel_generation"]["max_workers"],
                cache_size_mb=self.config["intelligent_cache"]["max_size_mb"]
            )
            
            # Testa componentes integrados
            assert generator.parallel_generator is not None
            assert generator.cache is not None
            assert generator.retry_system is not None
            assert generator.validator is not None
            
            # Testa métricas integradas
            metrics = generator.get_integrated_metrics()
            assert "integrated" in metrics
            assert "parallel" in metrics
            assert "cache" in metrics
            assert "retry" in metrics
            
            # Testa resumo de performance
            performance = generator.get_performance_summary()
            assert "cache_performance" in performance
            assert "retry_performance" in performance
            assert "parallel_performance" in performance
            assert "efficiency_metrics" in performance
            
            generator.shutdown()
            
            self.setup_results["integrated_generator"] = {
                "status": "success",
                "components": ["parallel", "cache", "retry", "validator"],
                "metrics_available": True
            }
            
            logger.info("✅ Gerador integrado configurado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar gerador integrado: {e}")
            self.setup_results["integrated_generator"] = {
                "status": "error",
                "error": str(e)
            }
            return False
    
    def _create_mock_session(self):
        """Cria sessão mock para testes"""
        from unittest.mock import Mock
        
        session = Mock()
        
        # Mock da categoria
        categoria = Mock()
        categoria.id = 1
        categoria.prompt_path = "/test/prompt.txt"
        categoria.ia_provider = "openai"
        categoria.clusters = "test_clusters"
        
        # Mock do blog
        blog = Mock()
        blog.nome = "test_blog"
        categoria.blog = blog
        
        session.query.return_value.get.return_value = categoria
        return session
    
    def run_full_setup(self) -> bool:
        """Executa configuração completa dos sistemas críticos"""
        logger.info("🚀 Iniciando configuração dos sistemas críticos...")
        
        start_time = time.time()
        
        # Configura cada sistema
        systems = [
            ("Paralelismo", self.setup_parallel_generation),
            ("Cache Inteligente", self.setup_intelligent_cache),
            ("Retry Inteligente", self.setup_smart_retry),
            ("Validação de Prompts", self.setup_prompt_validation),
            ("Gerador Integrado", self.setup_integrated_generator)
        ]
        
        success_count = 0
        total_systems = len(systems)
        
        for system_name, setup_func in systems:
            logger.info(f"\n📋 Configurando {system_name}...")
            if setup_func():
                success_count += 1
            else:
                logger.error(f"❌ Falha na configuração de {system_name}")
        
        # Salva resultados
        self._save_setup_results()
        
        # Relatório final
        setup_time = time.time() - start_time
        success_rate = (success_count / total_systems) * 100
        
        logger.info(f"\n{'='*60}")
        logger.info(f"📊 RELATÓRIO DE CONFIGURAÇÃO")
        logger.info(f"{'='*60}")
        logger.info(f"✅ Sistemas configurados com sucesso: {success_count}/{total_systems}")
        logger.info(f"📈 Taxa de sucesso: {success_rate:.1f}%")
        logger.info(f"⏱️  Tempo total: {setup_time:.2f} segundos")
        logger.info(f"📁 Resultados salvos em: logs/critical_systems_setup.log")
        
        if success_count == total_systems:
            logger.info(f"\n🎉 TODOS OS SISTEMAS CRÍTICOS CONFIGURADOS COM SUCESSO!")
            logger.info(f"🚀 Omni Writer está pronto para uso com performance otimizada!")
        else:
            logger.warning(f"\n⚠️  {total_systems - success_count} sistema(s) com problemas")
            logger.info(f"📋 Verifique os logs para detalhes")
        
        return success_count == total_systems
    
    def _save_setup_results(self):
        """Salva resultados da configuração"""
        results_file = "logs/critical_systems_results.json"
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.setup_results, f, indent=2, default=str)
        
        logger.info(f"📄 Resultados salvos em: {results_file}")


def main():
    """Função principal"""
    print("🚀 Omni Writer - Configuração dos Sistemas Críticos")
    print("=" * 60)
    
    # Verifica se está no diretório correto
    if not os.path.exists("omni_writer"):
        print("❌ Erro: Execute este script no diretório raiz do projeto")
        sys.exit(1)
    
    # Executa configuração
    setup = CriticalSystemsSetup()
    success = setup.run_full_setup()
    
    if success:
        print("\n✅ Configuração concluída com sucesso!")
        sys.exit(0)
    else:
        print("\n❌ Configuração com problemas. Verifique os logs.")
        sys.exit(1)


if __name__ == "__main__":
    main() 