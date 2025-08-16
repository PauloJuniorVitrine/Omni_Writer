# scripts/dev_setup.ps1
# Setup Automático do Ambiente de Desenvolvimento E2E
# 
# 📐 CoCoT: Baseado em boas práticas de automação de setup
# 🌲 ToT: Múltiplas estratégias de configuração implementadas
# ♻️ ReAct: Simulado para diferentes cenários de ambiente
#
# **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
# **Data/Hora:** 2025-01-28T12:00:00Z
# **Tracing ID:** DEV_SETUP_PS1_md1ppfhs
# **Origem:** Necessidade de automação de setup para desenvolvedores

param(
    [string]$Environment = "dev",
    [switch]$Force,
    [switch]$SkipValidation,
    [switch]$Verbose
)

# Configurações
$Config = @{
    ProjectName = "Omni Writer E2E"
    NodeVersion = "18"
    PythonVersion = "3.11"
    BaseUrl = "http://localhost:5000"
    TestDir = "tests/e2e"
    LogDir = "logs/e2e"
    ResultsDir = "test-results"
    CacheDir = ".e2e-cache"
}

# Cores para output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    Magenta = "Magenta"
    Cyan = "Cyan"
    White = "White"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$Bold
    )
    
    $prefix = if ($Bold) { "**" } else { "" }
    Write-Host "$prefix$Message$prefix" -ForegroundColor $Colors[$Color]
}

function Test-Command {
    param([string]$Command)
    
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-NodeVersion {
    try {
        $nodeVersion = node --version
        $majorVersion = ($nodeVersion -replace 'v', '').Split('.')[0]
        return [int]$majorVersion -ge 18
    }
    catch {
        return $false
    }
}

function Test-PythonVersion {
    try {
        $pythonVersion = python --version
        $majorVersion = ($pythonVersion -replace 'Python ', '').Split('.')[0]
        $minorVersion = ($pythonVersion -replace 'Python ', '').Split('.')[1]
        return [int]$majorVersion -ge 3 -and [int]$minorVersion -ge 11
    }
    catch {
        return $false
    }
}

function Install-NodeDependencies {
    Write-ColorOutput "📦 Instalando dependências Node.js..." -Color Cyan
    
    if (Test-Path "package.json") {
        if ($Force -or -not (Test-Path "node_modules")) {
            Write-ColorOutput "  Executando npm ci..." -Color Yellow
            npm ci
            if ($LASTEXITCODE -ne 0) {
                Write-ColorOutput "❌ Falha na instalação de dependências Node.js" -Color Red
                return $false
            }
        } else {
            Write-ColorOutput "  node_modules já existe, pulando..." -Color Yellow
        }
    } else {
        Write-ColorOutput "⚠️ package.json não encontrado" -Color Yellow
    }
    
    return $true
}

function Install-PythonDependencies {
    Write-ColorOutput "🐍 Instalando dependências Python..." -Color Cyan
    
    if (Test-Path "requirements.txt") {
        Write-ColorOutput "  Executando pip install..." -Color Yellow
        pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "❌ Falha na instalação de dependências Python" -Color Red
            return $false
        }
    } else {
        Write-ColorOutput "⚠️ requirements.txt não encontrado" -Color Yellow
    }
    
    return $true
}

function Install-Playwright {
    Write-ColorOutput "🎭 Instalando Playwright..." -Color Cyan
    
    Write-ColorOutput "  Instalando Playwright e browsers..." -Color Yellow
    npx playwright install --with-deps
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "❌ Falha na instalação do Playwright" -Color Red
        return $false
    }
    
    return $true
}

function New-Directories {
    Write-ColorOutput "📁 Criando diretórios necessários..." -Color Cyan
    
    $directories = @(
        $Config.TestDir,
        $Config.LogDir,
        $Config.ResultsDir,
        $Config.CacheDir,
        "$($Config.TestDir)/snapshots",
        "$($Config.TestDir)/snapshots/generate_content",
        "$($Config.TestDir)/snapshots/webhook",
        "$($Config.LogDir)/exec_trace"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-ColorOutput "  ✅ Criado: $dir" -Color Green
        } else {
            Write-ColorOutput "  ℹ️ Já existe: $dir" -Color Yellow
        }
    }
}

function Set-EnvironmentVariables {
    Write-ColorOutput "🔧 Configurando variáveis de ambiente..." -Color Cyan
    
    $envVars = @{
        "E2E_ENV" = $Environment
        "E2E_BASE_URL" = $Config.BaseUrl
        "NODE_ENV" = "development"
        "PLAYWRIGHT_BROWSERS_PATH" = "0"
    }
    
    foreach ($key in $envVars.Keys) {
        [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        Write-ColorOutput "  ✅ $key = $($envVars[$key])" -Color Green
    }
}

function Test-ApplicationHealth {
    Write-ColorOutput "🏥 Verificando saúde da aplicação..." -Color Cyan
    
    try {
        $response = Invoke-WebRequest -Uri $Config.BaseUrl -TimeoutSec 10 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-ColorOutput "  ✅ Aplicação respondendo em $($Config.BaseUrl)" -Color Green
            return $true
        }
    }
    catch {
        Write-ColorOutput "  ⚠️ Aplicação não está rodando em $($Config.BaseUrl)" -Color Yellow
        Write-ColorOutput "  💡 Execute: npm run start:dev" -Color Cyan
        return $false
    }
}

function Test-SetupValidation {
    Write-ColorOutput "🔍 Validando setup..." -Color Cyan
    
    $validationResults = @{
        Node = Test-NodeVersion
        Python = Test-PythonVersion
        Playwright = Test-Command "npx playwright"
        Dependencies = Test-Path "node_modules"
        Directories = Test-Path $Config.TestDir
    }
    
    $allValid = $true
    foreach ($test in $validationResults.Keys) {
        $status = if ($validationResults[$test]) { "✅" } else { "❌" }
        $color = if ($validationResults[$test]) { "Green" } else { "Red" }
        Write-ColorOutput "  $status $test" -Color $color
        
        if (-not $validationResults[$test]) {
            $allValid = $false
        }
    }
    
    return $allValid
}

function Show-SetupSummary {
    Write-ColorOutput "`n📊 RESUMO DO SETUP" -Color Magenta -Bold
    Write-ColorOutput "==================" -Color Magenta
    
    Write-ColorOutput "🎯 Projeto: $($Config.ProjectName)" -Color White
    Write-ColorOutput "🌍 Ambiente: $Environment" -Color White
    Write-ColorOutput "🌐 Base URL: $($Config.BaseUrl)" -Color White
    Write-ColorOutput "📁 Test Dir: $($Config.TestDir)" -Color White
    Write-ColorOutput "📊 Results Dir: $($Config.ResultsDir)" -Color White
    
    Write-ColorOutput "`n🚀 COMANDOS DISPONÍVEIS:" -Color Cyan -Bold
    Write-ColorOutput "  npm run test:e2e:quick    - Testes de smoke" -Color White
    Write-ColorOutput "  npm run test:e2e:smoke    - Testes de smoke" -Color White
    Write-ColorOutput "  npm run test:e2e:critical - Testes críticos" -Color White
    Write-ColorOutput "  npm run test:e2e:watch    - Watch mode" -Color White
    Write-ColorOutput "  npm run test:e2e:debug    - Modo debug" -Color White
    Write-ColorOutput "  npm run test:e2e:ui       - Interface UI" -Color White
    Write-ColorOutput "  npm run test:e2e:report   - Abrir relatórios" -Color White
    
    Write-ColorOutput "`n📚 DOCUMENTAÇÃO:" -Color Cyan -Bold
    Write-ColorOutput "  tests/e2e/MAINTENANCE_GUIDE.md - Guia de manutenção" -Color White
    Write-ColorOutput "  docs/e2e_troubleshooting.md   - Troubleshooting" -Color White
}

function Show-TroubleshootingTips {
    Write-ColorOutput "`n🔧 DICAS DE TROUBLESHOOTING:" -Color Yellow -Bold
    Write-ColorOutput "=================================" -Color Yellow
    
    Write-ColorOutput "❓ Problema: Aplicação não inicia" -Color White
    Write-ColorOutput "   💡 Solução: npm run start:dev" -Color Cyan
    
    Write-ColorOutput "❓ Problema: Testes falham por timeout" -Color White
    Write-ColorOutput "   💡 Solução: Aumentar timeout em e2e.config.ts" -Color Cyan
    
    Write-ColorOutput "❓ Problema: Browsers não instalam" -Color White
    Write-ColorOutput "   💡 Solução: npx playwright install --with-deps" -Color Cyan
    
    Write-ColorOutput "❓ Problema: Cache corrompido" -Color White
    Write-ColorOutput "   💡 Solução: npm run test:e2e:clean" -Color Cyan
    
    Write-ColorOutput "❓ Problema: Dependências desatualizadas" -Color White
    Write-ColorOutput "   💡 Solução: npm run test:e2e:reset" -Color Cyan
}

# Função principal
function Main {
    Write-ColorOutput "🚀 SETUP AUTOMÁTICO - $($Config.ProjectName)" -Color Magenta -Bold
    Write-ColorOutput "=============================================" -Color Magenta
    Write-ColorOutput "📐 CoCoT: Setup baseado em boas práticas de automação" -Color Cyan
    Write-ColorOutput "🌲 ToT: Múltiplas estratégias de configuração" -Color Cyan
    Write-ColorOutput "♻️ ReAct: Simulado para diferentes cenários" -Color Cyan
    Write-ColorOutput ""
    
    # Verificar pré-requisitos
    Write-ColorOutput "🔍 Verificando pré-requisitos..." -Color Cyan
    
    if (-not (Test-NodeVersion)) {
        Write-ColorOutput "❌ Node.js 18+ é necessário" -Color Red
        Write-ColorOutput "💡 Instale: https://nodejs.org/" -Color Cyan
        exit 1
    }
    
    if (-not (Test-PythonVersion)) {
        Write-ColorOutput "❌ Python 3.11+ é necessário" -Color Red
        Write-ColorOutput "💡 Instale: https://python.org/" -Color Cyan
        exit 1
    }
    
    Write-ColorOutput "✅ Pré-requisitos atendidos" -Color Green
    
    # Executar setup
    $setupSteps = @(
        @{ Name = "Instalar dependências Node.js"; Function = "Install-NodeDependencies" }
        @{ Name = "Instalar dependências Python"; Function = "Install-PythonDependencies" }
        @{ Name = "Instalar Playwright"; Function = "Install-Playwright" }
        @{ Name = "Criar diretórios"; Function = "New-Directories" }
        @{ Name = "Configurar variáveis"; Function = "Set-EnvironmentVariables" }
    )
    
    foreach ($step in $setupSteps) {
        Write-ColorOutput "`n🔄 $($step.Name)..." -Color Blue
        $result = & $step.Function
        if (-not $result) {
            Write-ColorOutput "❌ Falha no setup" -Color Red
            exit 1
        }
    }
    
    # Validação final
    if (-not $SkipValidation) {
        Write-ColorOutput "`n🔍 Validação final..." -Color Cyan
        $validationPassed = Test-SetupValidation
        if (-not $validationPassed) {
            Write-ColorOutput "❌ Validação falhou" -Color Red
            Show-TroubleshootingTips
            exit 1
        }
    }
    
    # Verificar aplicação
    Test-ApplicationHealth
    
    # Resumo final
    Show-SetupSummary
    Show-TroubleshootingTips
    
    Write-ColorOutput "`n🎉 SETUP CONCLUÍDO COM SUCESSO!" -Color Green -Bold
    Write-ColorOutput "🚀 Pronto para executar testes E2E!" -Color Green
}

# Executar setup
Main 