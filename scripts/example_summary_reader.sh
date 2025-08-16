#!/bin/bash
# =============================================================================
# 🚀 Example Summary Reader Script (Shell)
# 📅 Criado: 2025-01-27
# 🔧 Tracing ID: AUTO_HEALING_CONFIG_001_20250127
# 📝 Demonstra como adicionar guardas para o arquivo summary.json
# =============================================================================

set -euo pipefail

# =============================================================================
# 🔧 CONFIGURAÇÕES
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SUMMARY_FILE="$PROJECT_ROOT/.ci/config/summary.json"

# =============================================================================
# 🛟 FUNÇÃO: Garantir que o arquivo summary.json existe
# =============================================================================
ensure_summary_file_exists() {
    echo "🛟 Verificando arquivo summary.json..."
    
    # Criar diretório se não existir
    mkdir -p "$(dirname "$SUMMARY_FILE")"
    
    # Se o arquivo não existir, criar com valores padrão
    if [[ ! -f "$SUMMARY_FILE" ]]; then
        echo "📝 Criando arquivo summary.json padrão..."
        
        cat > "$SUMMARY_FILE" << 'EOF'
{
  "version": "3.0.0",
  "environment": "production",
  "tracing_id": "AUTO_HEALING_CONFIG_001_20250127",
  "repository": "${GITHUB_REPOSITORY:-unknown}",
  "run_id": "${GITHUB_RUN_ID:-unknown}",
  "sha": "${GITHUB_SHA:-unknown}",
  "branch": "${GITHUB_REF_NAME:-unknown}",
  "jobs_completed": {},
  "totals": {
    "healing_attempts": 0,
    "patches_created": 0,
    "tests_passed": 0,
    "tests_failed": 0
  },
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
        
        echo "✅ Arquivo summary.json criado em: $SUMMARY_FILE"
    else
        echo "✅ Arquivo summary.json já existe: $SUMMARY_FILE"
    fi
}

# =============================================================================
# 📖 FUNÇÃO: Ler arquivo summary.json
# =============================================================================
read_summary_file() {
    ensure_summary_file_exists
    
    if [[ -f "$SUMMARY_FILE" ]]; then
        echo "📖 Lendo arquivo summary.json..."
        
        # Verificar se é um JSON válido
        if jq empty "$SUMMARY_FILE" 2>/dev/null; then
            echo "✅ Arquivo summary.json é um JSON válido"
            
            # Extrair informações básicas
            VERSION=$(jq -r '.version' "$SUMMARY_FILE")
            ENVIRONMENT=$(jq -r '.environment' "$SUMMARY_FILE")
            TRACING_ID=$(jq -r '.tracing_id' "$SUMMARY_FILE")
            
            echo "📊 Versão: $VERSION"
            echo "🌍 Ambiente: $ENVIRONMENT"
            echo "🔧 Tracing ID: $TRACING_ID"
            
            return 0
        else
            echo "⚠️ Arquivo summary.json não é um JSON válido"
            return 1
        fi
    else
        echo "❌ Arquivo summary.json não encontrado"
        return 1
    fi
}

# =============================================================================
# 📝 FUNÇÃO: Atualizar totais no arquivo summary.json
# =============================================================================
update_summary_totals() {
    local healing_attempts="${1:-0}"
    local patches_created="${2:-0}"
    local tests_passed="${3:-0}"
    local tests_failed="${4:-0}"
    
    ensure_summary_file_exists
    
    if [[ -f "$SUMMARY_FILE" ]]; then
        echo "📝 Atualizando totais no summary.json..."
        
        # Atualizar totais usando jq
        jq --argjson ha "$healing_attempts" \
           --argjson pc "$patches_created" \
           --argjson tp "$tests_passed" \
           --argjson tf "$tests_failed" \
           '.totals.healing_attempts += $ha | .totals.patches_created += $pc | .totals.tests_passed += $tp | .totals.tests_failed += $tf' \
           "$SUMMARY_FILE" > "$SUMMARY_FILE.tmp" && mv "$SUMMARY_FILE.tmp" "$SUMMARY_FILE"
        
        echo "✅ Totais atualizados:"
        echo "   - Healing attempts: $(jq -r '.totals.healing_attempts' "$SUMMARY_FILE")"
        echo "   - Patches created: $(jq -r '.totals.patches_created' "$SUMMARY_FILE")"
        echo "   - Tests passed: $(jq -r '.totals.tests_passed' "$SUMMARY_FILE")"
        echo "   - Tests failed: $(jq -r '.totals.tests_failed' "$SUMMARY_FILE")"
    else
        echo "❌ Não foi possível atualizar summary.json"
        return 1
    fi
}

# =============================================================================
# 🔍 FUNÇÃO: Verificar status dos jobs
# =============================================================================
check_jobs_status() {
    ensure_summary_file_exists
    
    if [[ -f "$SUMMARY_FILE" ]]; then
        echo "🔍 Verificando status dos jobs..."
        
        # Contar jobs completados
        local total_jobs=$(jq '.jobs_completed | length' "$SUMMARY_FILE")
        echo "📊 Total de jobs: $total_jobs"
        
        # Listar jobs e seus status
        if [[ "$total_jobs" -gt 0 ]]; then
            echo "📋 Status dos jobs:"
            jq -r '.jobs_completed | to_entries[] | "  - \(.key): \(.value)"' "$SUMMARY_FILE"
        else
            echo "📋 Nenhum job registrado ainda"
        fi
    fi
}

# =============================================================================
# 🚀 FUNÇÃO PRINCIPAL
# =============================================================================
main() {
    echo "🚀 Example Summary Reader Script (Shell)"
    echo "=================================================="
    
    # Verificar dependências
    if ! command -v jq &> /dev/null; then
        echo "❌ Erro: jq não está instalado"
        echo "💡 Instale com: sudo apt-get install jq (Ubuntu/Debian) ou brew install jq (macOS)"
        exit 1
    fi
    
    # Garantir que o arquivo existe
    ensure_summary_file_exists
    echo "📁 Caminho do arquivo: $SUMMARY_FILE"
    
    # Ler dados do arquivo
    if read_summary_file; then
        echo "✅ Arquivo lido com sucesso"
    else
        echo "⚠️ Problemas ao ler arquivo, mas continuando..."
    fi
    
    # Exemplo de atualização de totais
    echo ""
    echo "📝 Atualizando totais..."
    update_summary_totals 1 1 10 0
    
    # Verificar status dos jobs
    echo ""
    check_jobs_status
    
    echo ""
    echo "✅ Script executado com sucesso!"
}

# =============================================================================
# 🔧 EXECUÇÃO
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
