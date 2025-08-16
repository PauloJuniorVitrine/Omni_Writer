# Script final para corrigir o workflow
Write-Host "🔧 Corrigindo workflow final..." -ForegroundColor Yellow

# Fazer backup
Copy-Item '.github/workflows/config.yaml' '.github/workflows/config.yaml.backup'
Write-Host "💾 Backup criado" -ForegroundColor Green

# Ler o arquivo
$content = Get-Content '.github/workflows/config.yaml' -Raw

# Contar quantos steps precisam ser corrigidos
$oldSteps = [regex]::Matches($content, '🛟 Ensure \.ci/config/summary\.json \(fallback\)')
Write-Host "📊 Steps encontrados: $($oldSteps.Count)" -ForegroundColor Cyan

# Substituir o step de fallback
$oldStep = '🛟 Ensure \.ci/config/summary\.json \(fallback\)'
$newStep = '🛟 Ensure summary.json exists'

$content = $content -replace $oldStep, $newStep

# Remover id: ensure_summary
$content = $content -replace 'id: ensure_summary\r?\n        ', ''

# Substituir o conteúdo do run
$oldRun = 'run: \|\r?\n          mkdir -p \.ci/config\r?\n          cat > \.ci/config/summary\.json << ''EOF''\r?\n          \{\r?\n            "version": "3\.0\.0",\r?\n            "environment": "production",\r?\n            "tracing_id": "AUTO_HEALING_CONFIG_001_20250127",\r?\n            "repository": "\$\{\{ github\.repository \}\}",\r?\n            "run_id": "\$\{\{ github\.run_id \}\}",\r?\n            "sha": "\$\{\{ github\.sha \}\}",\r?\n            "branch": "\$\{\{ github\.ref_name \}\}",\r?\n            "jobs_completed": \{\},\r?\n            "totals": \{\r?\n              "healing_attempts": 0,\r?\n              "patches_created": 0,\r?\n              "tests_passed": 0,\r?\n              "tests_failed": 0\r?\n            \},\r?\n            "timestamp": "\$\(date -u \+%Y-%m-%dT%H:%M:%SZ\)"\r?\n          \}\r?\n          EOF\r?\n          echo "path=\.ci/config/summary\.json" >> \$GITHUB_OUTPUT'

$newRun = 'run: |`n          mkdir -p .ci/config`n          [ -f .ci/config/summary.json ] || echo ''{}'' > .ci/config/summary.json'

$content = $content -replace $oldRun, $newRun

# Adicionar shell: bash
$content = $content -replace 'name: "🛟 Ensure summary\.json exists"', 'name: "🛟 Ensure summary.json exists"`n        shell: bash'

# Salvar
$content | Set-Content '.github/workflows/config.yaml' -Encoding UTF8

Write-Host "✅ Workflow corrigido!" -ForegroundColor Green
