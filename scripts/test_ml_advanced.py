#!/usr/bin/env python3
"""
Script de Teste do Sistema ML Avançado.
Demonstra as funcionalidades de otimização e geração inteligente.
"""

import sys
import os
import json
import time
from pathlib import Path

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

from omni_writer.ml_advanced import (
    ContentOptimizer,
    IntelligentGenerator,
    MLIntegration,
    quick_optimize,
    quick_generate
)

def test_content_optimizer():
    """Testa o otimizador de conteúdo."""
    print("🧪 Testando ContentOptimizer...")
    
    # Conteúdo de teste
    test_content = """
    Artificial intelligence is a technology that enables machines to learn and make decisions. 
    The technology has many applications in various industries. Companies are implementing AI 
    solutions to improve efficiency and productivity. The future of AI looks promising with 
    continued advancements in machine learning algorithms.
    """
    
    try:
        # Inicializa otimizador
        optimizer = ContentOptimizer()
        
        # Analisa conteúdo
        print("📊 Analisando conteúdo...")
        analysis = optimizer.analyze_content(test_content)
        
        if analysis:
            print(f"✅ Análise concluída:")
            print(f"   📈 Score Geral: {analysis.metrics.overall_score:.2f}")
            print(f"   🔒 Unicidade: {analysis.metrics.uniqueness_score:.2f}")
            print(f"   👤 Humanização: {analysis.metrics.humanization_score:.2f}")
            print(f"   📖 Legibilidade: {analysis.metrics.readability_score:.2f}")
            print(f"   🔗 Coerência: {analysis.metrics.coherence_score:.2f}")
            print(f"   💡 Criatividade: {analysis.metrics.creativity_score:.2f}")
        
        # Otimiza conteúdo
        print("\n🚀 Otimizando conteúdo...")
        optimized_content, final_analysis = optimizer.optimize_content(test_content)
        
        if final_analysis:
            print(f"✅ Otimização concluída:")
            print(f"   📈 Score Final: {final_analysis.metrics.overall_score:.2f}")
            print(f"   🔒 Unicidade: {final_analysis.metrics.uniqueness_score:.2f}")
            print(f"   👤 Humanização: {final_analysis.metrics.humanization_score:.2f}")
        
        # Gera sugestões
        suggestions = optimizer.get_optimization_suggestions(optimized_content)
        if suggestions:
            print(f"\n💡 Sugestões de melhoria:")
            for suggestion in suggestions:
                print(f"   - {suggestion}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste do otimizador: {e}")
        return False

def test_intelligent_generator():
    """Testa o gerador inteligente."""
    print("\n🧪 Testando IntelligentGenerator...")
    
    try:
        # Inicializa gerador
        generator = IntelligentGenerator()
        
        # Testa diferentes estilos
        styles = ["casual", "formal", "technical", "storytelling"]
        topics = ["machine learning", "digital transformation", "sustainability", "innovation"]
        
        for style in styles:
            print(f"\n🎨 Testando estilo: {style}")
            
            for topic in topics[:1]:  # Testa apenas um tópico por estilo
                print(f"   📝 Gerando conteúdo sobre: {topic}")
                
                start_time = time.time()
                result = generator.generate_content(
                    topic=topic,
                    content_type="article",
                    target_length=300,
                    style=style,
                    language="en"
                )
                generation_time = time.time() - start_time
                
                if result:
                    print(f"   ✅ Gerado em {generation_time:.2f}s")
                    print(f"   📊 Score: {result.analysis.metrics.overall_score:.2f}")
                    print(f"   🔒 Unicidade: {result.uniqueness_score:.2f}")
                    print(f"   👤 Humanização: {result.humanization_score:.2f}")
                    print(f"   🔄 Iterações: {result.iterations}")
                    
                    # Mostra parte do conteúdo
                    preview = result.content[:200] + "..." if len(result.content) > 200 else result.content
                    print(f"   📄 Preview: {preview}")
                else:
                    print(f"   ❌ Falha na geração")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste do gerador: {e}")
        return False

def test_ml_integration():
    """Testa a integração ML."""
    print("\n🧪 Testando MLIntegration...")
    
    try:
        # Inicializa integração
        integration = MLIntegration()
        
        # Testa geração com ML
        print("🚀 Testando geração com ML...")
        
        from omni_writer.ml_advanced.ml_integration import MLArticleRequest
        
        request = MLArticleRequest(
            topic="artificial intelligence in healthcare",
            target_length=400,
            style="casual",
            language="en",
            enable_optimization=True,
            enable_learning=True
        )
        
        start_time = time.time()
        response = integration.generate_article_with_ml(request)
        generation_time = time.time() - start_time
        
        if response:
            print(f"✅ Artigo gerado com ML:")
            print(f"   ⏱️ Tempo: {generation_time:.2f}s")
            print(f"   📊 Score: {response.quality_metrics.get('overall_score', 0):.2f}")
            print(f"   🔒 Unicidade: {response.quality_metrics.get('uniqueness_score', 0):.2f}")
            print(f"   👤 Humanização: {response.quality_metrics.get('humanization_score', 0):.2f}")
            print(f"   🔄 Otimização: {'Sim' if response.optimization_applied else 'Não'}")
            print(f"   🧠 Aprendizado: {'Sim' if response.learning_applied else 'Não'}")
            
            # Mostra parte do conteúdo
            preview = response.content[:300] + "..." if len(response.content) > 300 else response.content
            print(f"   📄 Preview: {preview}")
            
            if response.suggestions:
                print(f"   💡 Sugestões:")
                for suggestion in response.suggestions[:2]:  # Mostra apenas 2
                    print(f"      - {suggestion}")
        else:
            print("❌ Falha na geração com ML")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste de integração: {e}")
        return False

def test_quick_functions():
    """Testa as funções rápidas."""
    print("\n🧪 Testando funções rápidas...")
    
    try:
        # Testa otimização rápida
        print("⚡ Testando otimização rápida...")
        test_content = "Machine learning is a subset of artificial intelligence that focuses on algorithms."
        
        optimized, metrics = quick_optimize(test_content)
        print(f"✅ Otimização rápida:")
        print(f"   📊 Score: {metrics.get('overall', 0):.2f}")
        print(f"   🔒 Unicidade: {metrics.get('uniqueness', 0):.2f}")
        print(f"   👤 Humanização: {metrics.get('humanization', 0):.2f}")
        
        # Testa geração rápida
        print("\n⚡ Testando geração rápida...")
        generated_content = quick_generate("blockchain technology", 200, "casual")
        print(f"✅ Geração rápida:")
        print(f"   📄 Conteúdo: {generated_content[:150]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro nas funções rápidas: {e}")
        return False

def test_performance():
    """Testa performance do sistema."""
    print("\n🧪 Testando performance...")
    
    try:
        # Testa velocidade de otimização
        print("⚡ Testando velocidade de otimização...")
        test_content = "This is a test content for performance evaluation."
        
        start_time = time.time()
        for i in range(5):
            optimized, metrics = quick_optimize(test_content)
        optimization_time = time.time() - start_time
        
        print(f"✅ Tempo médio de otimização: {optimization_time/5:.3f}s")
        
        # Testa velocidade de geração
        print("\n⚡ Testando velocidade de geração...")
        start_time = time.time()
        for i in range(3):
            content = quick_generate(f"topic {i}", 100, "casual")
        generation_time = time.time() - start_time
        
        print(f"✅ Tempo médio de geração: {generation_time/3:.3f}s")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste de performance: {e}")
        return False

def generate_demo_report():
    """Gera relatório de demonstração."""
    print("\n📊 Gerando relatório de demonstração...")
    
    try:
        integration = MLIntegration()
        
        # Gera alguns artigos de exemplo
        topics = [
            "machine learning applications",
            "digital transformation strategies", 
            "sustainable technology solutions",
            "innovation in business"
        ]
        
        results = []
        for topic in topics:
            request = MLArticleRequest(
                topic=topic,
                target_length=300,
                style="casual",
                language="en"
            )
            
            response = integration.generate_article_with_ml(request)
            if response:
                results.append({
                    "topic": topic,
                    "score": response.quality_metrics.get('overall_score', 0),
                    "uniqueness": response.quality_metrics.get('uniqueness_score', 0),
                    "humanization": response.quality_metrics.get('humanization_score', 0),
                    "time": response.generation_time
                })
        
        # Calcula estatísticas
        if results:
            avg_score = sum(r['score'] for r in results) / len(results)
            avg_uniqueness = sum(r['uniqueness'] for r in results) / len(results)
            avg_humanization = sum(r['humanization'] for r in results) / len(results)
            avg_time = sum(r['time'] for r in results) / len(results)
            
            print(f"📈 Estatísticas da demonstração:")
            print(f"   📊 Score médio: {avg_score:.2f}")
            print(f"   🔒 Unicidade média: {avg_uniqueness:.2f}")
            print(f"   👤 Humanização média: {avg_humanization:.2f}")
            print(f"   ⏱️ Tempo médio: {avg_time:.2f}s")
            print(f"   📝 Artigos gerados: {len(results)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao gerar relatório: {e}")
        return False

def main():
    """Função principal."""
    print("🚀 Iniciando Testes do Sistema ML Avançado")
    print("=" * 50)
    
    tests = [
        ("ContentOptimizer", test_content_optimizer),
        ("IntelligentGenerator", test_intelligent_generator),
        ("MLIntegration", test_ml_integration),
        ("Quick Functions", test_quick_functions),
        ("Performance", test_performance),
        ("Demo Report", generate_demo_report)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results[test_name] = "✅ PASSOU" if success else "❌ FALHOU"
        except Exception as e:
            results[test_name] = f"❌ ERRO: {e}"
    
    # Relatório final
    print("\n" + "=" * 50)
    print("📋 RELATÓRIO FINAL DOS TESTES")
    print("=" * 50)
    
    for test_name, result in results.items():
        print(f"{test_name:20} : {result}")
    
    passed = sum(1 for result in results.values() if "✅" in result)
    total = len(results)
    
    print(f"\n📊 Resultado: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 Todos os testes passaram! Sistema ML funcionando perfeitamente.")
    elif passed >= total * 0.8:
        print("👍 Maioria dos testes passou. Sistema ML funcionando bem.")
    else:
        print("⚠️ Muitos testes falharam. Verifique as dependências ML.")

if __name__ == "__main__":
    main() 