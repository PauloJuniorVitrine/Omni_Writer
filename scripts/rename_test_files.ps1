# Script de Renomeação Automática de Arquivos de Teste
# Prompt: tests
# Ruleset: geral_rules_melhorado.yaml
# Data/Hora: 2025-01-27T18:45:00Z
# Tracing ID: RENAME_SCRIPT_001

param(
    [string]$TestDirectory = "tests/unit",
    [switch]$DryRun = $false,
    [switch]$Verbose = $false
)

Write-Host "🔧 Script de Renomeação de Arquivos de Teste" -ForegroundColor Cyan
Write-Host "Data/Hora: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')" -ForegroundColor Gray
Write-Host "Tracing ID: RENAME_SCRIPT_001" -ForegroundColor Gray
Write-Host ""

# Contadores
$totalFiles = 0
$renamedFiles = 0
$skippedFiles = 0
$errors = 0

# Função para log estruturado
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $Color
    
    if ($Verbose) {
        Add-Content -Path "logs/rename_test_files.log" -Value $logMessage
    }
}

# Função para validar se arquivo já está no padrão correto
function Test-CorrectPattern {
    param([string]$FileName)
    
    # Padrões aceitos: test_*.py, *_test.spec.py, *_test.py
    $patterns = @(
        '^test_.*\.py$',
        '^.*_test\.spec\.py$',
        '^.*_test\.py$'
    )
    
    foreach ($pattern in $patterns) {
        if ($FileName -match $pattern) {
            return $true
        }
    }
    return $false
}

# Função para gerar novo nome
function Get-NewFileName {
    param([string]$FileName)
    
    # Remove extensão
    $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $extension = [System.IO.Path]::GetExtension($FileName)
    
    # Se já está no padrão correto, retorna o mesmo nome
    if (Test-CorrectPattern $FileName) {
        return $FileName
    }
    
    # Remove prefixo 'test_' se existir
    if ($nameWithoutExt -match '^test_(.+)$') {
        $nameWithoutExt = $matches[1]
    }
    
    # Remove sufixo '_test' se existir
    if ($nameWithoutExt -match '^(.+)_test$') {
        $nameWithoutExt = $matches[1]
    }
    
    # Remove sufixo '.spec' se existir
    if ($nameWithoutExt -match '^(.+)\.spec$') {
        $nameWithoutExt = $matches[1]
    }
    
    # Gera novo nome no padrão: {nome}_test.spec.py
    return "${nameWithoutExt}_test.spec.py"
}

# Função para verificar se o arquivo pode ser renomeado
function Test-CanRename {
    param(
        [string]$FilePath,
        [string]$NewFileName
    )
    
    $directory = Split-Path $FilePath -Parent
    $newPath = Join-Path $directory $NewFileName
    
    # Verifica se o novo arquivo já existe
    if (Test-Path $newPath) {
        Write-Log "ERRO: Arquivo de destino já existe: $newPath" "ERROR" "Red"
        return $false
    }
    
    return $true
}

# Função para renomear arquivo
function Rename-TestFile {
    param(
        [string]$FilePath,
        [string]$NewFileName
    )
    
    try {
        $directory = Split-Path $FilePath -Parent
        $newPath = Join-Path $directory $NewFileName
        
        if ($DryRun) {
            Write-Log "DRY RUN: Renomeando '$FilePath' -> '$NewFileName'" "INFO" "Yellow"
        } else {
            Rename-Item -Path $FilePath -NewName $NewFileName -Force
            Write-Log "Renomeado: '$FilePath' -> '$NewFileName'" "INFO" "Green"
        }
        
        return $true
    }
    catch {
        Write-Log "ERRO ao renomear '$FilePath': $($_.Exception.Message)" "ERROR" "Red"
        return $false
    }
}

# Função principal de processamento
function Process-TestDirectory {
    param([string]$Directory)
    
    Write-Log "Processando diretório: $Directory" "INFO" "Cyan"
    
    if (-not (Test-Path $Directory)) {
        Write-Log "Diretório não encontrado: $Directory" "ERROR" "Red"
        return
    }
    
    # Busca todos os arquivos .py recursivamente
    $files = Get-ChildItem -Path $Directory -Filter "*.py" -Recurse | Where-Object { -not $_.PSIsContainer }
    
    Write-Log "Encontrados $($files.Count) arquivos .py" "INFO" "Cyan"
    
    foreach ($file in $files) {
        $totalFiles++
        $fileName = $file.Name
        $filePath = $file.FullName
        
        Write-Log "Processando: $fileName" "DEBUG" "Gray"
        
        # Verifica se já está no padrão correto
        if (Test-CorrectPattern $fileName) {
            Write-Log "Arquivo já está no padrão correto: $fileName" "INFO" "Blue"
            $skippedFiles++
            continue
        }
        
        # Gera novo nome
        $newFileName = Get-NewFileName $fileName
        
        # Se o nome não mudou, pula
        if ($fileName -eq $newFileName) {
            Write-Log "Nome não precisa ser alterado: $fileName" "INFO" "Blue"
            $skippedFiles++
            continue
        }
        
        # Verifica se pode renomear
        if (-not (Test-CanRename $filePath $newFileName)) {
            $errors++
            continue
        }
        
        # Renomeia o arquivo
        if (Rename-TestFile $filePath $newFileName) {
            $renamedFiles++
        } else {
            $errors++
        }
    }
}

# Função para gerar relatório
function Write-Report {
    Write-Host ""
    Write-Host "📊 RELATÓRIO DE RENOMEAÇÃO" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host "Total de arquivos processados: $totalFiles" -ForegroundColor White
    Write-Host "Arquivos renomeados: $renamedFiles" -ForegroundColor Green
    Write-Host "Arquivos ignorados: $skippedFiles" -ForegroundColor Blue
    Write-Host "Erros encontrados: $errors" -ForegroundColor Red
    
    if ($DryRun) {
        Write-Host ""
        Write-Host "🔍 MODO DRY RUN - Nenhum arquivo foi realmente renomeado" -ForegroundColor Yellow
        Write-Host "Execute sem -DryRun para aplicar as mudanças" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "⏰ Concluído em: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')" -ForegroundColor Gray
}

# Função para criar diretório de logs
function Initialize-Logging {
    $logDir = "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    if ($Verbose) {
        $logFile = "logs/rename_test_files.log"
        if (Test-Path $logFile) {
            Remove-Item $logFile -Force
        }
        Write-Log "Iniciando log de renomeação" "INFO" "Gray"
    }
}

# Execução principal
try {
    Initialize-Logging
    
    Write-Log "Iniciando processo de renomeação" "INFO" "Cyan"
    Write-Log "Diretório de teste: $TestDirectory" "INFO" "Cyan"
    Write-Log "Modo Dry Run: $DryRun" "INFO" "Cyan"
    Write-Log "Modo Verbose: $Verbose" "INFO" "Cyan"
    
    Process-TestDirectory $TestDirectory
    
    Write-Report
    
    Write-Log "Processo concluído com sucesso" "INFO" "Green"
}
catch {
    Write-Log "ERRO CRÍTICO: $($_.Exception.Message)" "ERROR" "Red"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR" "Red"
    exit 1
} 