#!/usr/bin/env python3
"""
Exemplo de Configuração do Sistema de Cache - Omni Writer

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import os
from shared.cache_config import CacheType, CacheConfig, CacheStrategy, get_cache_config
from shared.cache_manager import get_cache_manager


def demonstrate_cache_configuration():
    """
    Demonstra como configurar o sistema de cache.
    """
    print("=== Configuração do Sistema de Cache ===")
    
    # 1. Configurações padrão
    print("\n1. Configurações Padrão:")
    
    for cache_type in CacheType:
        config = get_cache_config(cache_type)
        print(f"{cache_type.value}:")
        print(f"  - TTL: {config.ttl} segundos ({config.ttl/3600:.1f} horas)")
        print(f"  - Estratégia: {config.strategy.value.upper()}")
        print(f"  - Tamanho máximo: {config.max_size}MB")
        print(f"  - Compressão: {'Sim' if config.compression else 'Não'}")
        print(f"  - Criptografia: {'Sim' if config.encryption else 'Não'}")
        print(f"  - Distribuído: {'Sim' if config.distributed else 'Não'}")
        print()


def demonstrate_environment_configuration():
    """
    Demonstra configuração via variáveis de ambiente.
    """
    print("2. Configuração via Variáveis de Ambiente:")
    
    # Simula configuração de ambiente
    env_vars = {
        'REDIS_URL': 'redis://localhost:6379/0',
        'REDIS_MAX_CONNECTIONS': '20',
        'REDIS_SOCKET_TIMEOUT': '10',
        'CACHE_GENERATION_STATUS_TTL': '7200',  # 2 horas
        'CACHE_EXPORT_CACHE_STRATEGY': 'lfu',
        'CACHE_USER_PREFERENCES_MAX_SIZE': '100',
        'CACHE_ENABLE_METRICS': 'true',
        'CACHE_HIT_RATE_THRESHOLD': '0.85'
    }
    
    print("Variáveis de ambiente configuradas:")
    for key, value in env_vars.items():
        print(f"  {key}={value}")
    
    print("\nPara aplicar essas configurações, defina as variáveis de ambiente:")
    for key, value in env_vars.items():
        print(f"export {key}={value}")


def demonstrate_programmatic_configuration():
    """
    Demonstra configuração programática.
    """
    print("\n3. Configuração Programática:")
    
    from shared.cache_config import cache_config
    
    # Cria nova configuração
    custom_config = CacheConfig(
        ttl=7200,  # 2 horas
        strategy=CacheStrategy.LFU,
        max_size=500,  # 500MB
        compression=True,
        encryption=False,
        distributed=True
    )
    
    # Aplica configuração personalizada
    cache_config.update_config(CacheType.EXPORT_CACHE, custom_config)
    
    print("Configuração personalizada aplicada ao EXPORT_CACHE:")
    updated_config = get_cache_config(CacheType.EXPORT_CACHE)
    print(f"  - TTL: {updated_config.ttl} segundos")
    print(f"  - Estratégia: {updated_config.strategy.value.upper()}")
    print(f"  - Tamanho máximo: {updated_config.max_size}MB")
    print(f"  - Compressão: {'Sim' if updated_config.compression else 'Não'}")


def demonstrate_cache_manager_configuration():
    """
    Demonstra configuração do CacheManager.
    """
    print("\n4. Configuração do CacheManager:")
    
    # Cria CacheManager com configurações personalizadas
    from shared.cache_manager import CacheManager
    
    # Com métricas habilitadas e compressão
    cache_manager_1 = CacheManager(
        enable_metrics=True,
        enable_compression=True
    )
    print("CacheManager criado com:")
    print("  - Métricas: Habilitadas")
    print("  - Compressão: Habilitada")
    
    # Sem métricas e sem compressão
    cache_manager_2 = CacheManager(
        enable_metrics=False,
        enable_compression=False
    )
    print("CacheManager criado com:")
    print("  - Métricas: Desabilitadas")
    print("  - Compressão: Desabilitada")


def demonstrate_redis_configuration():
    """
    Demonstra configuração do Redis.
    """
    print("\n5. Configuração do Redis:")
    
    from shared.cache_config import get_redis_config
    
    redis_config = get_redis_config()
    
    print("Configuração do Redis:")
    for key, value in redis_config.items():
        print(f"  - {key}: {value}")


def demonstrate_stats_configuration():
    """
    Demonstra configuração de estatísticas.
    """
    print("\n6. Configuração de Estatísticas:")
    
    from shared.cache_config import get_cache_stats_config
    
    stats_config = get_cache_stats_config()
    
    print("Configuração de Estatísticas:")
    for key, value in stats_config.items():
        print(f"  - {key}: {value}")


def demonstrate_custom_cache_types():
    """
    Demonstra como criar tipos de cache personalizados.
    """
    print("\n7. Tipos de Cache Personalizados:")
    
    # Exemplo de como estender o sistema
    print("Para adicionar novos tipos de cache:")
    print("1. Adicione ao enum CacheType:")
    print("   CUSTOM_CACHE = 'custom_cache'")
    print()
    print("2. Configure no CacheConfiguration:")
    print("   CacheType.CUSTOM_CACHE: CacheConfig(...)")
    print()
    print("3. Use no código:")
    print("   cache_manager.set(CacheType.CUSTOM_CACHE, 'key', 'value')")


def demonstrate_best_practices():
    """
    Demonstra melhores práticas de configuração.
    """
    print("\n8. Melhores Práticas:")
    
    best_practices = [
        "Use TTL para dados temporários (status, métricas)",
        "Use LRU para dados com acesso variável (artigos, exportações)",
        "Use LFU para dados com acesso consistente (prompts)",
        "Use FIFO para dados temporários (logs, métricas)",
        "Habilite compressão para dados grandes (>1KB)",
        "Habilite criptografia para dados sensíveis",
        "Configure TTL baseado na frequência de mudança dos dados",
        "Monitore métricas de hit rate e latência",
        "Use cache warming para dados frequentemente acessados",
        "Configure limpeza automática de entradas expiradas"
    ]
    
    for i, practice in enumerate(best_practices, 1):
        print(f"{i}. {practice}")


def demonstrate_configuration_examples():
    """
    Demonstra exemplos de configuração para diferentes cenários.
    """
    print("\n9. Exemplos de Configuração por Cenário:")
    
    scenarios = {
        "Desenvolvimento": {
            "REDIS_URL": "redis://localhost:6379/0",
            "CACHE_ENABLE_METRICS": "true",
            "CACHE_GENERATION_STATUS_TTL": "1800",  # 30 min
            "CACHE_EXPORT_CACHE_MAX_SIZE": "100"    # 100MB
        },
        "Teste": {
            "REDIS_URL": "redis://test-redis:6379/0",
            "CACHE_ENABLE_METRICS": "true",
            "CACHE_GENERATION_STATUS_TTL": "300",   # 5 min
            "CACHE_EXPORT_CACHE_MAX_SIZE": "50"     # 50MB
        },
        "Produção": {
            "REDIS_URL": "redis://prod-redis-cluster:6379/0",
            "REDIS_MAX_CONNECTIONS": "50",
            "CACHE_ENABLE_METRICS": "true",
            "CACHE_HIT_RATE_THRESHOLD": "0.85",
            "CACHE_ALERT_ON_LOW_HIT_RATE": "true"
        },
        "Alta Performance": {
            "REDIS_URL": "redis://high-perf-redis:6379/0",
            "REDIS_MAX_CONNECTIONS": "100",
            "CACHE_ENABLE_METRICS": "true",
            "CACHE_GENERATION_STATUS_TTL": "7200",  # 2h
            "CACHE_EXPORT_CACHE_MAX_SIZE": "1000",  # 1GB
            "CACHE_ARTICLE_CONTENT_MAX_SIZE": "2000" # 2GB
        }
    }
    
    for scenario, config in scenarios.items():
        print(f"\n{scenario}:")
        for key, value in config.items():
            print(f"  {key}={value}")


def demonstrate_monitoring_configuration():
    """
    Demonstra configuração de monitoramento.
    """
    print("\n10. Configuração de Monitoramento:")
    
    monitoring_config = {
        "Alertas": {
            "Hit rate baixo": "CACHE_HIT_RATE_THRESHOLD=0.8",
            "Erros frequentes": "Monitorar métricas de erro",
            "Cache cheio": "Monitorar utilização > 90%",
            "Latência alta": "Monitorar duração > 100ms"
        },
        "Métricas": {
            "Prometheus": "Expor métricas em /metrics",
            "Grafana": "Dashboard para visualização",
            "Logs": "Log estruturado com metadados"
        },
        "Health Checks": {
            "Redis": "Verificar conectividade",
            "Cache": "Verificar operações básicas",
            "Estratégias": "Verificar funcionamento"
        }
    }
    
    for category, items in monitoring_config.items():
        print(f"\n{category}:")
        for name, description in items.items():
            print(f"  - {name}: {description}")


if __name__ == "__main__":
    """
    Executa demonstração de configuração do sistema de cache.
    """
    try:
        demonstrate_cache_configuration()
        demonstrate_environment_configuration()
        demonstrate_programmatic_configuration()
        demonstrate_cache_manager_configuration()
        demonstrate_redis_configuration()
        demonstrate_stats_configuration()
        demonstrate_custom_cache_types()
        demonstrate_best_practices()
        demonstrate_configuration_examples()
        demonstrate_monitoring_configuration()
        
        print("\n=== Demonstração de Configuração Concluída ===")
        print("O sistema de cache está configurado corretamente!")
        
    except Exception as e:
        print(f"Erro durante demonstração de configuração: {e}")
        raise 