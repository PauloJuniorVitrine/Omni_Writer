# 🛟 Script para Verificar Status do Summary Fallback
# 📅 Criado: 2025-01-27

Write-Host "🚀 Verificando Status do Summary Fallback" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green

# Verificar arquivo baseline
$summaryPath = ".ci/config/summary.json"
if (Test-Path $summaryPath) {
    Write-Host "✅ Arquivo baseline existe: $summaryPath" -ForegroundColor Green
} else {
    Write-Host "❌ Arquivo baseline não encontrado: $summaryPath" -ForegroundColor Red
}

# Verificar workflows
Write-Host "`n🔧 Verificando workflows..." -ForegroundColor Cyan
$workflowFiles = Get-ChildItem -Path ".github/workflows" -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
$workflowFiles += Get-ChildItem -Path ".github/workflows" -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue

Write-Host "📁 Workflows encontrados: $($workflowFiles.Count)" -ForegroundColor White

foreach ($file in $workflowFiles) {
    Write-Host "  📝 $($file.Name)" -ForegroundColor Yellow
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
        
        if ($content -match "Download ci-summary" -and $content -match "Ensure.*summary\.json") {
            Write-Host "    ✅ Já possui fallback" -ForegroundColor Green
        } else {
            Write-Host "    ⚠️ Precisa de fallback" -ForegroundColor Red
        }
        
        if ($content -match "Upload summary\.json") {
            Write-Host "    ✅ Já possui upload" -ForegroundColor Green
        } else {
            Write-Host "    ⚠️ Precisa de upload" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "    ❌ Erro ao ler arquivo" -ForegroundColor Red
    }
}

# Verificar scripts
Write-Host "`n🔧 Verificando scripts..." -ForegroundColor Cyan
$scriptFiles = Get-ChildItem -Path "scripts" -Filter "*.sh" -Recurse -ErrorAction SilentlyContinue
$scriptFiles += Get-ChildItem -Path "scripts" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue

Write-Host "📁 Scripts encontrados: $($scriptFiles.Count)" -ForegroundColor White

foreach ($file in $scriptFiles) {
    Write-Host "  📝 $($file.Name)" -ForegroundColor Yellow
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
        
        if ($content -match "summary\.json") {
            if ($file.Name -match "\.sh$" -and $content -match "SUMMARY_FILE") {
                Write-Host "    ✅ Já possui guarda shell" -ForegroundColor Green
            } elseif ($file.Name -match "\.py$" -and $content -match "Path.*summary\.json") {
                Write-Host "    ✅ Já possui guarda Python" -ForegroundColor Green
            } else {
                Write-Host "    ⚠️ Precisa de guarda" -ForegroundColor Red
            }
        } else {
            Write-Host "    ℹ️ Não usa summary.json" -ForegroundColor Blue
        }
        
    } catch {
        Write-Host "    ❌ Erro ao ler arquivo" -ForegroundColor Red
    }
}

Write-Host "`n📊 Resumo da Verificação" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "✅ Verificação concluída" -ForegroundColor Green

Write-Host "`n🎯 Próximos passos:" -ForegroundColor Yellow
Write-Host "1. Aplicar fallback nos workflows que precisam" -ForegroundColor White
Write-Host "2. Adicionar guardas nos scripts que precisam" -ForegroundColor White
Write-Host "3. Testar em commits antigos" -ForegroundColor White
