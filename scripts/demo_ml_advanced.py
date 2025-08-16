#!/usr/bin/env python3
"""
Demonstração Interativa do Sistema ML Avançado.
Mostra as funcionalidades em tempo real com interface amigável.
"""

import sys
import os
import time
import json
from pathlib import Path
from datetime import datetime

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

def print_header():
    """Imprime cabeçalho da demonstração."""
    print("=" * 80)
    print("🧠 DEMONSTRAÇÃO INTERATIVA - SISTEMA ML AVANÇADO")
    print("=" * 80)
    print("📋 Resolve: 1) Não repetição, 2) Humanização, 3) Aprendizado contínuo")
    print("=" * 80)
    print()

def print_menu():
    """Imprime menu de opções."""
    print("\n🎯 ESCOLHA UMA OPÇÃO:")
    print("1. 🚀 Demo Rápida - Otimização de Conteúdo")
    print("2. 🎨 Demo Rápida - Geração Inteligente")
    print("3. 🔧 Demo Completa - Sistema Integrado")
    print("4. 📊 Estatísticas e Relatórios")
    print("5. ⚙️ Configurações do Sistema")
    print("6. 🧪 Testes de Performance")
    print("7. 📚 Documentação e Ajuda")
    print("0. ❌ Sair")
    print()

def demo_quick_optimization():
    """Demonstração rápida de otimização."""
    print("\n" + "=" * 60)
    print("🚀 DEMO RÁPIDA - OTIMIZAÇÃO DE CONTEÚDO")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import quick_optimize
        
        # Conteúdo de exemplo
        original_content = """
        Artificial intelligence is a technology that enables machines to learn and make decisions. 
        The technology has many applications in various industries. Companies are implementing AI 
        solutions to improve efficiency and productivity. The future of AI looks promising with 
        continued advancements in machine learning algorithms.
        """
        
        print("📝 CONTEÚDO ORIGINAL:")
        print("-" * 40)
        print(original_content.strip())
        print()
        
        print("🔄 OTIMIZANDO CONTEÚDO...")
        start_time = time.time()
        
        optimized_content, metrics = quick_optimize(original_content)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"✅ Otimização concluída em {processing_time:.2f}s")
        print()
        
        print("📊 MÉTRICAS DE QUALIDADE:")
        print("-" * 40)
        print(f"🔒 Unicidade:     {metrics['uniqueness']:.2f}")
        print(f"👤 Humanização:   {metrics['humanization']:.2f}")
        print(f"📖 Legibilidade:  {metrics['readability']:.2f}")
        print(f"🔗 Coerência:     {metrics['coherence']:.2f}")
        print(f"💡 Criatividade:  {metrics['creativity']:.2f}")
        print(f"📈 Score Geral:   {metrics['overall']:.2f}")
        print()
        
        print("📝 CONTEÚDO OTIMIZADO:")
        print("-" * 40)
        print(optimized_content.strip())
        print()
        
        # Comparação
        print("📊 COMPARAÇÃO:")
        print("-" * 40)
        print(f"Palavras originais: {len(original_content.split())}")
        print(f"Palavras otimizadas: {len(optimized_content.split())}")
        print(f"Melhoria no score: {metrics['overall'] - 0.5:.2f}")
        
    except Exception as e:
        print(f"❌ Erro na demonstração: {e}")
        print("💡 Certifique-se de que as dependências ML estão instaladas")

def demo_quick_generation():
    """Demonstração rápida de geração."""
    print("\n" + "=" * 60)
    print("🎨 DEMO RÁPIDA - GERAÇÃO INTELIGENTE")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import quick_generate
        
        topics = [
            "machine learning applications",
            "digital transformation",
            "sustainable technology",
            "innovation in business"
        ]
        
        styles = ["casual", "formal", "technical", "storytelling"]
        
        print("🎯 TÓPICOS DISPONÍVEIS:")
        for i, topic in enumerate(topics, 1):
            print(f"   {i}. {topic}")
        
        print("\n🎨 ESTILOS DISPONÍVEIS:")
        for i, style in enumerate(styles, 1):
            print(f"   {i}. {style}")
        
        print()
        
        # Gera conteúdo para cada estilo
        for style in styles:
            print(f"🎨 Gerando conteúdo em estilo: {style.upper()}")
            print("-" * 50)
            
            start_time = time.time()
            content = quick_generate(
                topic="artificial intelligence",
                length=200,
                style=style
            )
            end_time = time.time()
            
            print(f"⏱️ Tempo: {end_time - start_time:.2f}s")
            print(f"📝 Conteúdo:")
            print(content.strip())
            print()
            
            time.sleep(1)  # Pausa entre gerações
        
    except Exception as e:
        print(f"❌ Erro na demonstração: {e}")
        print("💡 Certifique-se de que as dependências ML estão instaladas")

def demo_complete_system():
    """Demonstração completa do sistema integrado."""
    print("\n" + "=" * 60)
    print("🔧 DEMO COMPLETA - SISTEMA INTEGRADO")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import MLIntegration, MLArticleRequest
        
        print("🚀 Inicializando sistema ML completo...")
        ml_system = MLIntegration()
        print("✅ Sistema inicializado")
        print()
        
        # Requisições de exemplo
        requests = [
            MLArticleRequest(
                topic="artificial intelligence in healthcare",
                target_length=400,
                style="casual",
                language="en",
                enable_optimization=True,
                enable_learning=True
            ),
            MLArticleRequest(
                topic="blockchain technology applications",
                target_length=300,
                style="technical",
                language="en",
                enable_optimization=True,
                enable_learning=True
            ),
            MLArticleRequest(
                topic="sustainable business practices",
                target_length=350,
                style="storytelling",
                language="en",
                enable_optimization=True,
                enable_learning=True
            )
        ]
        
        for i, request in enumerate(requests, 1):
            print(f"📝 GERANDO ARTIGO {i}: {request.topic}")
            print("-" * 50)
            
            start_time = time.time()
            response = ml_system.generate_article_with_ml(request)
            end_time = time.time()
            
            if response:
                print(f"✅ Artigo gerado com sucesso!")
                print(f"⏱️ Tempo: {response.generation_time:.2f}s")
                print(f"📊 Score: {response.quality_metrics['overall_score']:.2f}")
                print(f"🔒 Unicidade: {response.quality_metrics['uniqueness_score']:.2f}")
                print(f"👤 Humanização: {response.quality_metrics['humanization_score']:.2f}")
                print(f"🔄 Otimização: {'Sim' if response.optimization_applied else 'Não'}")
                print(f"🧠 Aprendizado: {'Sim' if response.learning_applied else 'Não'}")
                
                print(f"\n📄 PREVIEW DO CONTEÚDO:")
                preview = response.content[:300] + "..." if len(response.content) > 300 else response.content
                print(preview.strip())
                
                if response.suggestions:
                    print(f"\n💡 SUGESTÕES DE MELHORIA:")
                    for suggestion in response.suggestions[:2]:
                        print(f"   - {suggestion}")
            else:
                print("❌ Falha na geração do artigo")
            
            print()
            time.sleep(2)  # Pausa entre artigos
        
        # Estatísticas finais
        print("📊 ESTATÍSTICAS DA SESSÃO:")
        print("-" * 50)
        stats = ml_system.get_integration_stats(days=1)
        
        if "total_articles" in stats:
            print(f"📝 Artigos gerados: {stats['total_articles']}")
            print(f"📊 Score médio: {stats.get('avg_quality_score', 0):.2f}")
            print(f"🔄 Taxa de otimização: {stats.get('optimization_rate', 0):.2f}")
            print(f"🧠 Taxa de aprendizado: {stats.get('learning_rate', 0):.2f}")
            print(f"⏱️ Tempo médio: {stats.get('avg_generation_time', 0):.2f}s")
        
    except Exception as e:
        print(f"❌ Erro na demonstração: {e}")
        print("💡 Certifique-se de que as dependências ML estão instaladas")

def show_statistics():
    """Mostra estatísticas e relatórios."""
    print("\n" + "=" * 60)
    print("📊 ESTATÍSTICAS E RELATÓRIOS")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import MLIntegration, ContentOptimizer
        
        print("📈 CARREGANDO ESTATÍSTICAS...")
        
        # Estatísticas de integração
        ml_system = MLIntegration()
        integration_stats = ml_system.get_integration_stats(days=30)
        
        print("\n🔧 ESTATÍSTICAS DE INTEGRAÇÃO:")
        print("-" * 40)
        if "total_articles" in integration_stats:
            print(f"📝 Total de artigos: {integration_stats['total_articles']}")
            print(f"📊 Score médio: {integration_stats.get('avg_quality_score', 0):.2f}")
            print(f"🔄 Taxa de otimização: {integration_stats.get('optimization_rate', 0):.2f}")
            print(f"🧠 Taxa de aprendizado: {integration_stats.get('learning_rate', 0):.2f}")
            print(f"⏱️ Tempo médio: {integration_stats.get('avg_generation_time', 0):.2f}s")
            
            if "top_topics" in integration_stats:
                print(f"\n🎯 TÓPICOS MAIS POPULARES:")
                for topic in integration_stats["top_topics"][:3]:
                    print(f"   - {topic['topic']}: {topic['count']} artigos (score: {topic['avg_score']:.2f})")
            
            if "style_performance" in integration_stats:
                print(f"\n🎨 PERFORMANCE POR ESTILO:")
                for style, score in integration_stats["style_performance"].items():
                    print(f"   - {style}: {score:.2f}")
        else:
            print("📊 Nenhum dado disponível ainda")
        
        # Relatório do otimizador
        print("\n📊 RELATÓRIO DO OTIMIZADOR:")
        print("-" * 40)
        optimizer = ContentOptimizer()
        report = optimizer.generate_report(days=30)
        print(report)
        
    except Exception as e:
        print(f"❌ Erro ao carregar estatísticas: {e}")

def show_configuration():
    """Mostra e permite editar configurações."""
    print("\n" + "=" * 60)
    print("⚙️ CONFIGURAÇÕES DO SISTEMA")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import MLIntegration
        
        ml_system = MLIntegration()
        
        print("📋 CONFIGURAÇÕES ATUAIS:")
        print("-" * 40)
        
        config = ml_system.config
        for key, value in config.items():
            if isinstance(value, dict):
                print(f"🔧 {key}:")
                for sub_key, sub_value in value.items():
                    print(f"   - {sub_key}: {sub_value}")
            else:
                print(f"🔧 {key}: {value}")
        
        print("\n💡 CONFIGURAÇÕES IMPORTANTES:")
        print("-" * 40)
        print("• min_quality_score: Score mínimo para aceitar conteúdo")
        print("• similarity_threshold: Limite para detectar repetição")
        print("• max_iterations: Máximo de tentativas de otimização")
        print("• learning_enabled: Habilita aprendizado contínuo")
        
        print("\n📝 Para editar configurações, modifique o arquivo:")
        print("   omni_writer/ml_advanced/config.json")
        
    except Exception as e:
        print(f"❌ Erro ao carregar configurações: {e}")

def run_performance_tests():
    """Executa testes de performance."""
    print("\n" + "=" * 60)
    print("🧪 TESTES DE PERFORMANCE")
    print("=" * 60)
    
    try:
        from omni_writer.ml_advanced import quick_optimize, quick_generate
        import time
        
        print("⚡ TESTE 1: Performance de Otimização")
        print("-" * 40)
        
        test_content = "This is a test content for performance evaluation. " * 10
        
        times = []
        for i in range(5):
            start_time = time.time()
            optimized, metrics = quick_optimize(test_content)
            end_time = time.time()
            times.append(end_time - start_time)
            print(f"   Execução {i+1}: {times[-1]:.3f}s")
        
        avg_time = sum(times) / len(times)
        print(f"   ⏱️ Tempo médio: {avg_time:.3f}s")
        print(f"   📊 Melhor tempo: {min(times):.3f}s")
        print(f"   📊 Pior tempo: {max(times):.3f}s")
        
        print("\n⚡ TESTE 2: Performance de Geração")
        print("-" * 40)
        
        generation_times = []
        for i in range(3):
            start_time = time.time()
            content = quick_generate(f"topic {i}", 200, "casual")
            end_time = time.time()
            generation_times.append(end_time - start_time)
            print(f"   Geração {i+1}: {generation_times[-1]:.3f}s")
        
        avg_gen_time = sum(generation_times) / len(generation_times)
        print(f"   ⏱️ Tempo médio: {avg_gen_time:.3f}s")
        
        print("\n📊 RESUMO DE PERFORMANCE:")
        print("-" * 40)
        print(f"✅ Otimização: {avg_time:.3f}s (médio)")
        print(f"✅ Geração: {avg_gen_time:.3f}s (médio)")
        
        if avg_time < 2.0 and avg_gen_time < 5.0:
            print("🎉 Performance EXCELENTE!")
        elif avg_time < 5.0 and avg_gen_time < 10.0:
            print("👍 Performance BOA!")
        else:
            print("⚠️ Performance pode ser melhorada")
        
    except Exception as e:
        print(f"❌ Erro nos testes de performance: {e}")

def show_help():
    """Mostra ajuda e documentação."""
    print("\n" + "=" * 60)
    print("📚 DOCUMENTAÇÃO E AJUDA")
    print("=" * 60)
    
    print("🔧 COMO USAR O SISTEMA ML:")
    print("-" * 40)
    print("1. Instale as dependências:")
    print("   pip install -r requirements_ml.txt")
    print()
    print("2. Execute o setup:")
    print("   python scripts/setup_ml_advanced.py")
    print()
    print("3. Use as funções rápidas:")
    print("   from omni_writer.ml_advanced import quick_optimize, quick_generate")
    print()
    print("4. Ou use o sistema completo:")
    print("   from omni_writer.ml_advanced import MLIntegration")
    print()
    
    print("🎯 FUNCIONALIDADES PRINCIPAIS:")
    print("-" * 40)
    print("🔒 Não Repetição: Evita conteúdo duplicado")
    print("👤 Humanização: Cria conteúdo natural")
    print("🧠 Aprendizado: Melhora continuamente")
    print("📊 Análise: Métricas de qualidade")
    print("⚡ Otimização: Melhora automática")
    print()
    
    print("📁 ARQUIVOS IMPORTANTES:")
    print("-" * 40)
    print("• omni_writer/ml_advanced/ - Módulo principal")
    print("• omni_writer/ml_advanced/README.md - Documentação completa")
    print("• omni_writer/ml_advanced/config.json - Configurações")
    print("• scripts/test_ml_advanced.py - Testes")
    print("• requirements_ml.txt - Dependências")
    print()
    
    print("🆘 SOLUÇÃO DE PROBLEMAS:")
    print("-" * 40)
    print("❌ Erro de importação: Instale as dependências ML")
    print("❌ Modelo não carrega: Verifique conexão com internet")
    print("❌ Performance lenta: Reduza max_iterations")
    print("❌ Qualidade baixa: Ajuste min_quality_score")
    print()
    
    print("📞 SUPORTE:")
    print("-" * 40)
    print("• Documentação: omni_writer/ml_advanced/README.md")
    print("• Testes: python scripts/test_ml_advanced.py")
    print("• Logs: logs/ml_advanced.log")

def main():
    """Função principal da demonstração."""
    print_header()
    
    while True:
        print_menu()
        
        try:
            choice = input("🎯 Escolha uma opção (0-7): ").strip()
            
            if choice == "0":
                print("\n👋 Obrigado por usar o Sistema ML Avançado!")
                print("🚀 Continue explorando as funcionalidades!")
                break
            elif choice == "1":
                demo_quick_optimization()
            elif choice == "2":
                demo_quick_generation()
            elif choice == "3":
                demo_complete_system()
            elif choice == "4":
                show_statistics()
            elif choice == "5":
                show_configuration()
            elif choice == "6":
                run_performance_tests()
            elif choice == "7":
                show_help()
            else:
                print("❌ Opção inválida. Escolha de 0 a 7.")
            
            input("\n⏸️ Pressione ENTER para continuar...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Demonstração interrompida pelo usuário.")
            break
        except Exception as e:
            print(f"\n❌ Erro inesperado: {e}")
            input("⏸️ Pressione ENTER para continuar...")

if __name__ == "__main__":
    main() 