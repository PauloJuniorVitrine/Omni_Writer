# scripts/quick_start.ps1
# Início Rápido do Ambiente de Desenvolvimento E2E
# 
# 📐 CoCoT: Baseado em boas práticas de automação de setup
# 🌲 ToT: Múltiplas estratégias de inicialização implementadas
# ♻️ ReAct: Simulado para diferentes cenários de ambiente
#
# **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
# **Data/Hora:** 2025-01-28T13:00:00Z
# **Tracing ID:** QUICK_START_PS1_md1ppfhs
# **Origem:** Necessidade de inicialização rápida para desenvolvedores

param(
    [string]$Mode = "dev",
    [switch]$SkipSetup,
    [switch]$SkipValidation,
    [switch]$AutoStart,
    [switch]$Verbose
)

# Configurações
$Config = @{
    ProjectName = "Omni Writer E2E"
    BaseUrl = "http://localhost:5000"
    TestDir = "tests/e2e"
    LogDir = "logs/e2e"
    ResultsDir = "test-results"
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

function Show-Welcome {
    Write-ColorOutput "🚀 INÍCIO RÁPIDO - $($Config.ProjectName)" -Color Magenta -Bold
    Write-ColorOutput "=========================================" -Color Magenta
    Write-ColorOutput "📐 CoCoT: Setup baseado em boas práticas" -Color Cyan
    Write-ColorOutput "🌲 ToT: Múltiplas estratégias de inicialização" -Color Cyan
    Write-ColorOutput "♻️ ReAct: Simulado para diferentes cenários" -Color Cyan
    Write-ColorOutput ""
    Write-ColorOutput "🎯 Modo: $Mode" -Color White
    Write-ColorOutput "🌐 Base URL: $($Config.BaseUrl)" -Color White
    Write-ColorOutput ""
}

function Test-Prerequisites {
    Write-ColorOutput "🔍 Verificando pré-requisitos..." -Color Cyan
    
    $prerequisites = @{
        "Node.js" = { node --version }
        "npm" = { npm --version }
        "Python" = { python --version }
        "Git" = { git --version }
    }
    
    $allValid = $true
    foreach ($tool in $prerequisites.Keys) {
        try {
            $version = & $prerequisites[$tool] 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "  ✅ ${tool}: $version" -Color Green
            } else {
                Write-ColorOutput "  ❌ ${tool}: Não encontrado" -Color Red
                $allValid = $false
            }
        }
        catch {
            Write-ColorOutput "  ❌ ${tool}: Não encontrado" -Color Red
            $allValid = $false
        }
    }
    
    return $allValid
}

function Start-QuickSetup {
    Write-ColorOutput "⚡ Executando setup rápido..." -Color Cyan
    
    # Verificar se já existe setup
    if (Test-Path "node_modules" -and Test-Path "package.json") {
        Write-ColorOutput "  ℹ️ Setup já existe, verificando..." -Color Yellow
        
        # Verificar dependências
        if (-not (Test-Path "node_modules/@playwright")) {
            Write-ColorOutput "  📦 Instalando Playwright..." -Color Yellow
            npm run test:e2e:install
        }
    } else {
        Write-ColorOutput "  📦 Instalando dependências..." -Color Yellow
        npm ci
        npm run test:e2e:install
    }
    
    # Criar diretórios necessários
    $directories = @($Config.TestDir, $Config.LogDir, $Config.ResultsDir)
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-ColorOutput "  ✅ Criado: $dir" -Color Green
        }
    }
    
    # Configurar variáveis de ambiente
    [Environment]::SetEnvironmentVariable("E2E_ENV", $Mode, "Process")
    [Environment]::SetEnvironmentVariable("E2E_BASE_URL", $Config.BaseUrl, "Process")
    
    Write-ColorOutput "  ✅ Setup rápido concluído" -Color Green
}

function Test-ApplicationHealth {
    Write-ColorOutput "🏥 Verificando saúde da aplicação..." -Color Cyan
    
    try {
        $response = Invoke-WebRequest -Uri $Config.BaseUrl -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-ColorOutput "  ✅ Aplicação respondendo" -Color Green
            return $true
        }
    }
    catch {
        Write-ColorOutput "  ⚠️ Aplicação não está rodando" -Color Yellow
        Write-ColorOutput "  💡 Execute: npm run start:dev" -Color Cyan
        return $false
    }
}

function Start-Application {
    Write-ColorOutput "🚀 Iniciando aplicação..." -Color Cyan
    
    # Verificar se já está rodando
    if (Test-ApplicationHealth) {
        Write-ColorOutput "  ℹ️ Aplicação já está rodando" -Color Yellow
        return $true
    }
    
    # Tentar iniciar aplicação
    Write-ColorOutput "  🔧 Iniciando servidor..." -Color Yellow
    
    try {
        Start-Process -FilePath "npm" -ArgumentList "run", "start:dev" -WindowStyle Minimized
        Start-Sleep -Seconds 10
        
        # Verificar se iniciou
        if (Test-ApplicationHealth) {
            Write-ColorOutput "  ✅ Aplicação iniciada com sucesso" -Color Green
            return $true
        } else {
            Write-ColorOutput "  ❌ Falha ao iniciar aplicação" -Color Red
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ❌ Erro ao iniciar aplicação" -Color Red
        return $false
    }
}

function Show-QuickCommands {
    Write-ColorOutput "`n🚀 COMANDOS RÁPIDOS:" -Color Cyan -Bold
    Write-ColorOutput "===================" -Color Cyan
    
    Write-ColorOutput "🧪 Testes de Smoke:" -Color White
    Write-ColorOutput "  npm run test:e2e:quick" -Color Yellow
    
    Write-ColorOutput "🎭 Modo Debug:" -Color White
    Write-ColorOutput "  npm run test:e2e:debug" -Color Yellow
    
    Write-ColorOutput "👁️ Watch Mode:" -Color White
    Write-ColorOutput "  npm run test:e2e:watch:enhanced" -Color Yellow
    
    Write-ColorOutput "📊 Relatórios:" -Color White
    Write-ColorOutput "  npm run test:e2e:report" -Color Yellow
    
    Write-ColorOutput "🔧 Troubleshooting:" -Color White
    Write-ColorOutput "  npm run test:e2e:troubleshoot" -Color Yellow
    
    Write-ColorOutput "📚 Documentação:" -Color White
    Write-ColorOutput "  npm run test:e2e:docs" -Color Yellow
}

function Show-QuickTips {
    Write-ColorOutput "`n💡 DICAS RÁPIDAS:" -Color Yellow -Bold
    Write-ColorOutput "================" -Color Yellow
    
    Write-ColorOutput "🎯 Para desenvolvimento:" -Color White
    Write-ColorOutput "  - Use watch mode para execução automática" -Color Cyan
    Write-ColorOutput "  - Execute testes de smoke primeiro" -Color Cyan
    Write-ColorOutput "  - Use modo debug para troubleshooting" -Color Cyan
    
    Write-ColorOutput "🚀 Para CI/CD:" -Color White
    Write-ColorOutput "  - Use npm run test:e2e:ci" -Color Cyan
    Write-ColorOutput "  - Configure paralelização adequada" -Color Cyan
    Write-ColorOutput "  - Monitore métricas de performance" -Color Cyan
    
    Write-ColorOutput "🔧 Para manutenção:" -Color White
    Write-ColorOutput "  - Valide testes regularmente" -Color Cyan
    Write-ColorOutput "  - Mantenha dependências atualizadas" -Color Cyan
    Write-ColorOutput "  - Limpe cache periodicamente" -Color Cyan
}

function Start-QuickTest {
    Write-ColorOutput "`n🧪 Executando teste rápido..." -Color Cyan
    
    try {
        $result = npm run test:e2e:quick
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Teste rápido passou!" -Color Green
            return $true
        } else {
            Write-ColorOutput "❌ Teste rápido falhou" -Color Red
            return $false
        }
    }
    catch {
        Write-ColorOutput "❌ Erro ao executar teste" -Color Red
        return $false
    }
}

function Show-QuickStatus {
    Write-ColorOutput "`n📊 STATUS RÁPIDO:" -Color Magenta -Bold
    Write-ColorOutput "================" -Color Magenta
    
    # Verificar aplicação
    $appStatus = if (Test-ApplicationHealth) { "✅ Rodando" } else { "❌ Parada" }
    Write-ColorOutput "🌐 Aplicação: $appStatus" -Color White
    
    # Verificar Playwright
    $playwrightStatus = if (Test-Path "node_modules/@playwright") { "✅ Instalado" } else { "❌ Não instalado" }
    Write-ColorOutput "🎭 Playwright: $playwrightStatus" -Color White
    
    # Verificar diretórios
    $testDirStatus = if (Test-Path $Config.TestDir) { "✅ Existe" } else { "❌ Não existe" }
    Write-ColorOutput "📁 Test Dir: $testDirStatus" -Color White
    
    # Verificar resultados
    $resultsStatus = if (Test-Path $Config.ResultsDir) { "✅ Existe" } else { "❌ Não existe" }
    Write-ColorOutput "📊 Results Dir: $resultsStatus" -Color White
}

# Função principal
function Main {
    Show-Welcome
    
    # Verificar pré-requisitos
    if (-not (Test-Prerequisites)) {
        Write-ColorOutput "❌ Pré-requisitos não atendidos" -Color Red
        Write-ColorOutput "💡 Instale as ferramentas necessárias" -Color Cyan
        exit 1
    }
    
    # Setup rápido
    if (-not $SkipSetup) {
        Start-QuickSetup
    }
    
    # Verificar aplicação
    $appRunning = Test-ApplicationHealth
    
    # Iniciar aplicação se necessário
    if (-not $appRunning -and $AutoStart) {
        Start-Application
    }
    
    # Mostrar status
    Show-QuickStatus
    
    # Executar teste rápido se aplicação estiver rodando
    if ($appRunning -or $AutoStart) {
        Start-QuickTest
    }
    
    # Mostrar comandos e dicas
    Show-QuickCommands
    Show-QuickTips
    
    Write-ColorOutput "`n🎉 INÍCIO RÁPIDO CONCLUÍDO!" -Color Green -Bold
    Write-ColorOutput "🚀 Pronto para desenvolvimento!" -Color Green
}

# Executar início rápido
Main 