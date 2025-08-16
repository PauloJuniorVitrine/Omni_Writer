# 🛟 Script para Aplicar Summary Fallback em Workflows
# 📅 Criado: 2025-01-27
# 🔧 Tracing ID: APPLY_SUMMARY_FALLBACK_001_20250127

param(
    [string]$WorkflowsPath = ".github/workflows",
    [switch]$DryRun,
    [switch]$Verbose
)

Write-Host "🚀 Aplicando Summary Fallback em Workflows" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

# Função para aplicar fallback em um workflow
function Apply-SummaryFallback {
    param(
        [string]$FilePath
    )
    
    Write-Host "📝 Processando: $FilePath" -ForegroundColor Yellow
    
    try {
        $content = Get-Content -Path $FilePath -Raw -Encoding UTF8
        
        # Verificar se já tem os steps necessários
        if ($content -match "Download ci-summary" -and $content -match "Ensure.*summary\.json") {
            Write-Host "  ✅ Já possui fallback configurado" -ForegroundColor Green
            return $false
        }
        
        # Verificar se é um workflow válido
        if ($content -notmatch "name:" -or $content -notmatch "jobs:") {
            Write-Host "  ⚠️ Não parece ser um workflow válido, pulando..." -ForegroundColor Yellow
            return $false
        }
        
        # Aplicar mudanças
        $modified = $false
        
        # Adicionar step de download antes do primeiro step que usa summary.json
        if ($content -match "Ensure.*summary\.json" -and $content -notmatch "Download ci-summary") {
            $downloadStep = @"

      - name: "📥 Download ci-summary (optional)"
        uses: actions/download-artifact@v4
        with:
          name: ci-summary
          path: .ci/config
        continue-on-error: true
      
"@
            
            # Inserir antes do primeiro step ensure
            $pattern = '(\s+-\s+name:\s*[🛟🛡️].*summary\.json.*\n)'
            if ($content -match $pattern) {
                $content = $content -replace $pattern, "$downloadStep`n`$1"
                $modified = $true
                Write-Host "  ➕ Adicionado step de download" -ForegroundColor Cyan
            }
        }
        
        # Adicionar step de upload no final dos jobs
        if ($content -match "Ensure.*summary\.json" -and $content -notmatch "Upload summary\.json") {
            $uploadStep = @"

      - name: "📦 Upload summary.json"
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ci-summary
          path: .ci/config/summary.json
          if-no-files-found: warn
"@
            
            # Inserir antes do fechamento do job
            $pattern = '(\n\s+[#]\s*[=]+.*\n)'
            if ($content -match $pattern) {
                $content = $content -replace $pattern, "$uploadStep`n`$1"
                $modified = $true
                Write-Host "  ➕ Adicionado step de upload" -ForegroundColor Cyan
            }
        }
        
        if ($modified) {
            if (-not $DryRun) {
                Set-Content -Path $FilePath -Value $content -Encoding UTF8
                Write-Host "  💾 Arquivo atualizado" -ForegroundColor Green
            } else {
                Write-Host "  🔍 Modificações simuladas (Dry Run)" -ForegroundColor Magenta
            }
            return $true
        } else {
            Write-Host "  ℹ️ Nenhuma modificação necessária" -ForegroundColor Blue
            return $false
        }
        
    } catch {
        Write-Host "  ❌ Erro ao processar arquivo: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Função para aplicar guardas em scripts
function Apply-ScriptGuards {
    param(
        [string]$FilePath
    )
    
    Write-Host "📝 Processando script: $FilePath" -ForegroundColor Yellow
    
    try {
        $content = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $modified = $false
        
        # Verificar se é um script shell
        if ($FilePath -match "\.sh$" -and $content -match "summary\.json") {
            if ($content -notmatch "SUMMARY_FILE.*summary\.json") {
                $guard = @"
# 🛟 Garantir que o arquivo summary.json existe
SUMMARY_FILE=".ci/config/summary.json"
[ -f "$SUMMARY_FILE" ] || { mkdir -p .ci/config; echo '{}' > "$SUMMARY_FILE"; }

"@
                # Inserir no início do script, após o shebang
                if ($content -match "^#!/") {
                    $content = $content -replace "^#!/", "$0`n`n$guard"
                    $modified = $true
                    Write-Host "  ➕ Adicionado guarda shell" -ForegroundColor Cyan
                }
            }
        }
        
        # Verificar se é um script Python
        if ($FilePath -match "\.py$" -and $content -match "summary\.json") {
            if ($content -notmatch "Path.*summary\.json") {
                $guard = @"
# 🛟 Garantir que o arquivo summary.json existe
from pathlib import Path
summary_path = Path(".ci/config/summary.json")
summary_path.parent.mkdir(parents=True, exist_ok=True)
if not summary_path.exists():
    summary_path.write_text("{}", encoding="utf-8")

"@
                # Inserir após imports
                if ($content -match "^import|^from") {
                    $lastImport = [regex]::Matches($content, "^import|^from") | Select-Object -Last 1
                    if ($lastImport) {
                        $insertPos = $lastImport.Index + $lastImport.Length
                        $content = $content.Substring(0, $insertPos) + "`n" + $guard + $content.Substring($insertPos)
                        $modified = $true
                        Write-Host "  ➕ Adicionado guarda Python" -ForegroundColor Cyan
                    }
                }
            }
        }
        
        if ($modified) {
            if (-not $DryRun) {
                Set-Content -Path $FilePath -Value $content -Encoding UTF8
                Write-Host "  💾 Script atualizado" -ForegroundColor Green
            } else {
                Write-Host "  🔍 Modificações simuladas (Dry Run)" -ForegroundColor Magenta
            }
            return $true
        } else {
            Write-Host "  ℹ️ Nenhuma modificação necessária" -ForegroundColor Blue
            return $false
        }
        
    } catch {
        Write-Host "  ❌ Erro ao processar script: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Processar workflows
Write-Host "`n🔧 Processando Workflows..." -ForegroundColor Cyan
$workflowFiles = Get-ChildItem -Path $WorkflowsPath -Filter "*.yml" -Recurse
$workflowFiles += Get-ChildItem -Path $WorkflowsPath -Filter "*.yaml" -Recurse

$workflowsModified = 0
foreach ($file in $workflowFiles) {
    if (Apply-SummaryFallback -FilePath $file.FullName) {
        $workflowsModified++
    }
}

# Processar scripts
Write-Host "`n🔧 Processando Scripts..." -ForegroundColor Cyan
$scriptFiles = Get-ChildItem -Path "scripts" -Filter "*.sh" -Recurse
$scriptFiles += Get-ChildItem -Path "scripts" -Filter "*.py" -Recurse

$scriptsModified = 0
foreach ($file in $scriptFiles) {
    if (Apply-ScriptGuards -FilePath $file.FullName) {
        $scriptsModified++
    }
}

# Resumo
Write-Host "`n📊 Resumo das Modificações" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host "Workflows processados: $($workflowFiles.Count)" -ForegroundColor White
Write-Host "Workflows modificados: $workflowsModified" -ForegroundColor Cyan
Write-Host "Scripts processados: $($scriptFiles.Count)" -ForegroundColor White
Write-Host "Scripts modificados: $scriptsModified" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "`n🔍 Modo Dry Run - Nenhuma alteração foi salva" -ForegroundColor Magenta
} else {
    Write-Host "`n✅ Todas as modificações foram aplicadas!" -ForegroundColor Green
}

Write-Host "`n🎯 Próximos passos:" -ForegroundColor Yellow
Write-Host "1. Verificar se os workflows estão funcionando" -ForegroundColor White
Write-Host "2. Testar em commits antigos" -ForegroundColor White
Write-Host "3. Validar que não há falhas por ausência do summary.json" -ForegroundColor White
