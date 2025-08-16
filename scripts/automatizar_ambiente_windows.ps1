# Script PowerShell para automatizar setup e execução do ambiente de testes
# Caminho do projeto: $PSScriptRoot
# Logs: scripts/automatizar_ambiente_windows.log

$ErrorActionPreference = 'Stop'
$logPath = Join-Path $PSScriptRoot 'automatizar_ambiente_windows.log'
function Log {
    param([string]$msg)
    $timestamp = (Get-Date).ToUniversalTime().ToString('u')
    Add-Content -Path $logPath -Value "[$timestamp] $msg"
    Write-Host $msg
}

Log "--- Início do setup automatizado ---"

# 1. Ativar ambiente virtual
$venvPath = Join-Path $PSScriptRoot '..\venv\Scripts\activate.ps1'
if (Test-Path $venvPath) {
    Log "Ativando ambiente virtual..."
    & $venvPath
    Log "Ambiente virtual ativado."
} else {
    Log "Ambiente virtual não encontrado. Abortando."
    exit 1
}

# 2. Instalar dependências
if (Test-Path (Join-Path $PSScriptRoot '..\requirements.txt')) {
    Log "Instalando dependências do requirements.txt..."
    pip install -r ..\requirements.txt | Tee-Object -FilePath $logPath -Append
    Log "Dependências instaladas."
} else {
    Log "Arquivo requirements.txt não encontrado. Abortando."
    exit 1
}

# 3. Iniciar Redis (se instalado como serviço)
try {
    Log "Verificando serviço Redis..."
    $redisService = Get-Service -Name redis* -ErrorAction SilentlyContinue
    if ($redisService -and $redisService.Status -ne 'Running') {
        Start-Service $redisService.Name
        Log "Serviço Redis iniciado."
    } elseif ($redisService) {
        Log "Serviço Redis já está em execução."
    } else {
        Log "Serviço Redis não encontrado. Inicie manualmente se necessário."
    }
} catch {
    Log "Erro ao verificar/iniciar o Redis: $_"
}

# 4. Iniciar worker Celery (solo)
Log "Iniciando worker Celery (modo solo)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PSScriptRoot/..; .\venv\Scripts\activate.ps1; celery -A app.celery_worker.celery worker --loglevel=info --pool=solo" -WindowStyle Normal
Log "Worker Celery iniciado em nova janela."

# 5. Instrução para rodar testes
Log "Abra outro terminal, ative o venv e execute: pytest --tb=short --disable-warnings tests/integration"
Log "--- Fim do setup automatizado ---" 