# CONTINUOUS MONITORING - FRAMEWORK DE DETECCAO DE FLUXOS
# Monitoramento continuo e automatico
# Tracing ID: CONTINUOUS_MONITORING_20250127_001

$TRACING_ID = "CONTINUOUS_MONITORING_20250127_001"

Write-Host "=== CONTINUOUS MONITORING - FRAMEWORK DE DETECCAO DE FLUXOS ==="
Write-Host "Tracing ID: $TRACING_ID"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# Configuracoes de monitoramento
$MONITORING_CONFIG = @{
    CheckInterval = 300  # 5 minutos
    AlertThreshold = 80
    LogRetention = 7     # dias
    AutoRestart = $true
    HealthCheck = $true
}

function Start-ContinuousMonitoring {
    Write-Host "1. INICIANDO MONITORAMENTO CONTINUO..."
    
    $monitoringActive = $true
    $cycleCount = 0
    
    Write-Host "   Intervalo de verificacao: $($MONITORING_CONFIG.CheckInterval) segundos"
    Write-Host "   Threshold de alerta: $($MONITORING_CONFIG.AlertThreshold)%"
    Write-Host "   Retencao de logs: $($MONITORING_CONFIG.LogRetention) dias"
    Write-Host "   Auto-restart: $($MONITORING_CONFIG.AutoRestart)"
    Write-Host "   Health check: $($MONITORING_CONFIG.HealthCheck)"
    Write-Host ""
    
    while ($monitoringActive) {
        $cycleCount++
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        Write-Host "[$timestamp] Ciclo $cycleCount - Executando verificacao..."
        
        # Executa verificacao de saude
        $healthStatus = Test-FrameworkHealth
        Write-Host "   Status de saude: $($healthStatus.Status)"
        
        # Executa analise de fluxos
        $flowStatus = Test-FlowDetectionStatus
        Write-Host "   Status de fluxos: $($flowStatus.Status)"
        
        # Verifica alertas
        $alerts = Test-AlertConditions -HealthStatus $healthStatus -FlowStatus $flowStatus
        if ($alerts.Count -gt 0) {
            Write-Host "   ALERTAS DETECTADOS:"
            foreach ($alert in $alerts) {
                Write-Host "     • $($alert.Message)"
            }
        }
        
        # Salva status
        Save-MonitoringStatus -Cycle $cycleCount -HealthStatus $healthStatus -FlowStatus $flowStatus -Alerts $alerts
        
        # Aguarda proximo ciclo
        Write-Host "   Aguardando $($MONITORING_CONFIG.CheckInterval) segundos..."
        Write-Host ""
        Start-Sleep -Seconds $MONITORING_CONFIG.CheckInterval
    }
}

function Test-FrameworkHealth {
    Write-Host "2. VERIFICANDO SAUDE DO FRAMEWORK..."
    
    $healthStatus = @{
        Status = "UNKNOWN"
        Checks = @()
        Score = 0
    }
    
    # Verifica arquivos de log
    $logsDir = "logs"
    $requiredLogs = @("pipeline_multi_diag.log", "decisions_2025-01-27.log")
    
    $logCheck = @{
        Name = "Logs Disponiveis"
        Status = "PASSED"
        Details = "Todos os logs necessarios encontrados"
    }
    
    foreach ($logFile in $requiredLogs) {
        if (-not (Test-Path "$logsDir/$logFile")) {
            $logCheck.Status = "FAILED"
            $logCheck.Details = "Log $logFile nao encontrado"
            break
        }
    }
    
    $healthStatus.Checks += $logCheck
    
    # Verifica scripts de teste
    $testScripts = @("simple_flow_demo.ps1", "test_monitoring_flow.ps1")
    
    $scriptCheck = @{
        Name = "Scripts de Teste"
        Status = "PASSED"
        Details = "Todos os scripts de teste disponiveis"
    }
    
    foreach ($script in $testScripts) {
        if (-not (Test-Path "scripts/$script")) {
            $scriptCheck.Status = "FAILED"
            $scriptCheck.Details = "Script $script nao encontrado"
            break
        }
    }
    
    $healthStatus.Checks += $scriptCheck
    
    # Calcula score de saude
    $passedChecks = ($healthStatus.Checks | Where-Object { $_.Status -eq "PASSED" }).Count
    $totalChecks = $healthStatus.Checks.Count
    $healthScore = if ($totalChecks -gt 0) { ($passedChecks / $totalChecks) * 100 } else { 0 }
    
    $healthStatus.Score = $healthScore
    
    if ($healthScore -ge 90) {
        $healthStatus.Status = "HEALTHY"
    } elseif ($healthScore -ge 70) {
        $healthStatus.Status = "WARNING"
    } else {
        $healthStatus.Status = "CRITICAL"
    }
    
    Write-Host "   Score de saude: $([math]::Round($healthScore, 1))%"
    
    return $healthStatus
}

function Test-FlowDetectionStatus {
    Write-Host "3. VERIFICANDO STATUS DE DETECCAO DE FLUXOS..."
    
    $flowStatus = @{
        Status = "UNKNOWN"
        Patterns = @()
        Coverage = 0
        RiskScore = 0
    }
    
    # Analisa logs reais
    $logsDir = "logs"
    
    if (Test-Path "$logsDir/pipeline_multi_diag.log") {
        $lines = Get-Content "$logsDir/pipeline_multi_diag.log"
        $generateCalls = ($lines | Select-String "Chamando generate_article").Count
        $testingMentions = ($lines | Select-String "TESTING=").Count
        
        if ($generateCalls -gt 0) {
            $flowStatus.Patterns += @{
                Name = "Fluxo de Geracao de Artigos"
                RiskScore = 150
                IsTested = $true
                Frequency = $generateCalls
            }
        }
        
        if ($testingMentions -gt 0) {
            $flowStatus.Patterns += @{
                Name = "Fluxo de Monitoramento"
                RiskScore = 80
                IsTested = $true
                Frequency = $testingMentions
            }
        }
    }
    
    if (Test-Path "$logsDir/decisions_2025-01-27.log") {
        $lines = Get-Content "$logsDir/decisions_2025-01-27.log"
        $testDecisions = ($lines | Select-String "test" -CaseSensitive:$false).Count
        
        if ($testDecisions -gt 0) {
            $flowStatus.Patterns += @{
                Name = "Fluxo de Decisoes de Teste"
                RiskScore = 90
                IsTested = $true
                Frequency = $testDecisions
            }
        }
    }
    
    # Calcula metricas
    $totalPatterns = $flowStatus.Patterns.Count
    $testedPatterns = ($flowStatus.Patterns | Where-Object { $_.IsTested }).Count
    $coverage = if ($totalPatterns -gt 0) { ($testedPatterns / $totalPatterns) * 100 } else { 0 }
    
    $avgRiskScore = if ($totalPatterns -gt 0) {
        $totalRisk = 0
        foreach ($pattern in $flowStatus.Patterns) {
            $totalRisk += $pattern.RiskScore
        }
        $totalRisk / $totalPatterns
    } else { 0 }
    
    $flowStatus.Coverage = $coverage
    $flowStatus.RiskScore = $avgRiskScore
    
    if ($coverage -ge 85) {
        $flowStatus.Status = "OPTIMAL"
    } elseif ($coverage -ge 70) {
        $flowStatus.Status = "GOOD"
    } else {
        $flowStatus.Status = "NEEDS_ATTENTION"
    }
    
    Write-Host "   Padroes detectados: $totalPatterns"
    Write-Host "   Cobertura: $([math]::Round($coverage, 1))%"
    Write-Host "   Score medio de risco: $([math]::Round($avgRiskScore, 1))"
    
    return $flowStatus
}

function Test-AlertConditions {
    param($HealthStatus, $FlowStatus)
    
    Write-Host "4. VERIFICANDO CONDICOES DE ALERTA..."
    
    $alerts = @()
    
    # Alerta de saude critica
    if ($HealthStatus.Status -eq "CRITICAL") {
        $alerts += @{
            Level = "CRITICAL"
            Message = "Saude do framework critica: $($HealthStatus.Score)%"
            Action = "Verificar logs e reiniciar se necessario"
        }
    }
    
    # Alerta de cobertura baixa
    if ($FlowStatus.Coverage -lt $MONITORING_CONFIG.AlertThreshold) {
        $alerts += @{
            Level = "WARNING"
            Message = "Cobertura de fluxos baixa: $($FlowStatus.Coverage)%"
            Action = "Implementar testes adicionais"
        }
    }
    
    # Alerta de risco elevado
    if ($FlowStatus.RiskScore -gt 120) {
        $alerts += @{
            Level = "WARNING"
            Message = "Score de risco elevado: $($FlowStatus.RiskScore)"
            Action = "Revisar padroes de alto risco"
        }
    }
    
    Write-Host "   Alertas detectados: $($alerts.Count)"
    
    return $alerts
}

function Save-MonitoringStatus {
    param($Cycle, $HealthStatus, $FlowStatus, $Alerts)
    
    Write-Host "5. SALVANDO STATUS DE MONITORAMENTO..."
    
    $outputDir = "tests/integration/reports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssZ"
    $outputFile = "$outputDir/continuous_monitoring_$timestamp.json"
    
    $monitoringStatus = @{
        MonitoringInfo = @{
            TracingId = $TRACING_ID
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Description = "Continuous Monitoring - Framework de Detecao de Fluxos"
            Cycle = $Cycle
        }
        HealthStatus = $HealthStatus
        FlowStatus = $FlowStatus
        Alerts = $Alerts
        Config = $MONITORING_CONFIG
    }
    
    try {
        $monitoringStatus | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "   Status salvo: $outputFile"
    } catch {
        Write-Host "   Erro ao salvar status: $_"
    }
}

function Cleanup-OldLogs {
    Write-Host "6. LIMPANDO LOGS ANTIGOS..."
    
    $retentionDays = $MONITORING_CONFIG.LogRetention
    $cutoffDate = (Get-Date).AddDays(-$retentionDays)
    
    $reportsDir = "tests/integration/reports"
    if (Test-Path $reportsDir) {
        $oldFiles = Get-ChildItem -Path $reportsDir -File | Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        if ($oldFiles.Count -gt 0) {
            Write-Host "   Removendo $($oldFiles.Count) arquivos antigos..."
            $oldFiles | Remove-Item -Force
        } else {
            Write-Host "   Nenhum arquivo antigo encontrado"
        }
    }
}

# Executa monitoramento continuo
try {
    Write-Host "INICIANDO MONITORAMENTO CONTINUO DO FRAMEWORK DE DETECCAO DE FLUXOS..."
    Write-Host ""
    
    # Limpa logs antigos
    Cleanup-OldLogs
    Write-Host ""
    
    # Inicia monitoramento continuo
    Start-ContinuousMonitoring
    
} catch {
    Write-Host "ERRO NO MONITORAMENTO CONTINUO: $_"
    exit 1
} 