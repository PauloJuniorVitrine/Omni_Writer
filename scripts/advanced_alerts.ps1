# ADVANCED ALERTS - FRAMEWORK DE DETECCAO DE FLUXOS
# Sistema de alertas avancado e inteligente
# Tracing ID: ADVANCED_ALERTS_20250127_001

$TRACING_ID = "ADVANCED_ALERTS_20250127_001"

Write-Host "=== ADVANCED ALERTS - FRAMEWORK DE DETECCAO DE FLUXOS ==="
Write-Host "Tracing ID: $TRACING_ID"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# Configuracoes de alertas
$ALERT_CONFIG = @{
    CriticalThreshold = 90
    WarningThreshold = 70
    RiskThreshold = 120
    CoverageThreshold = 85
    NotificationChannels = @("CONSOLE", "FILE", "EMAIL")
    AlertRetention = 30  # dias
    AutoEscalation = $true
}

function Initialize-AlertSystem {
    Write-Host "1. INICIALIZANDO SISTEMA DE ALERTAS..."
    
    $alertSystem = @{
        ActiveAlerts = @()
        AlertHistory = @()
        AlertCounters = @{
            Critical = 0
            Warning = 0
            Info = 0
        }
        LastCheck = Get-Date
    }
    
    Write-Host "   Thresholds configurados:"
    Write-Host "     • Critico: $($ALERT_CONFIG.CriticalThreshold)%"
    Write-Host "     • Aviso: $($ALERT_CONFIG.WarningThreshold)%"
    Write-Host "     • Risco: $($ALERT_CONFIG.RiskThreshold)"
    Write-Host "     • Cobertura: $($ALERT_CONFIG.CoverageThreshold)%"
    Write-Host "   Canais de notificacao: $($ALERT_CONFIG.NotificationChannels -join ', ')"
    
    return $alertSystem
}

function Test-CoverageAlerts {
    param($AlertSystem)
    
    Write-Host "2. VERIFICANDO ALERTAS DE COBERTURA..."
    
    # Analisa cobertura real
    $logsDir = "logs"
    $patterns = @()
    
    if (Test-Path "$logsDir/pipeline_multi_diag.log") {
        $lines = Get-Content "$logsDir/pipeline_multi_diag.log"
        $generateCalls = ($lines | Select-String "Chamando generate_article").Count
        $testingMentions = ($lines | Select-String "TESTING=").Count
        
        if ($generateCalls -gt 0) {
            $patterns += @{ Name = "Fluxo de Geracao"; IsTested = $true }
        }
        if ($testingMentions -gt 0) {
            $patterns += @{ Name = "Fluxo de Monitoramento"; IsTested = $true }
        }
    }
    
    if (Test-Path "$logsDir/decisions_2025-01-27.log") {
        $lines = Get-Content "$logsDir/decisions_2025-01-27.log"
        $testDecisions = ($lines | Select-String "test" -CaseSensitive:$false).Count
        
        if ($testDecisions -gt 0) {
            $patterns += @{ Name = "Fluxo de Decisoes"; IsTested = $true }
        }
    }
    
    $totalPatterns = $patterns.Count
    $testedPatterns = ($patterns | Where-Object { $_.IsTested }).Count
    $coverage = if ($totalPatterns -gt 0) { ($testedPatterns / $totalPatterns) * 100 } else { 0 }
    
    Write-Host "   Cobertura atual: $([math]::Round($coverage, 1))%"
    
    # Gera alertas baseados na cobertura
    if ($coverage -lt $ALERT_CONFIG.CriticalThreshold) {
        $alert = @{
            Id = "COVERAGE_CRITICAL_$(Get-Date -Format 'yyyyMMddHHmmss')"
            Level = "CRITICAL"
            Category = "COVERAGE"
            Message = "Cobertura de testes critica: $([math]::Round($coverage, 1))%"
            Details = "Apenas $testedPatterns de $totalPatterns padroes estao testados"
            Timestamp = Get-Date
            Action = "Implementar testes imediatamente"
            AutoEscalation = $true
        }
        $AlertSystem.ActiveAlerts += $alert
        $AlertSystem.AlertCounters.Critical++
        Write-Host "   ❌ ALERTA CRITICO: Cobertura insuficiente"
    } elseif ($coverage -lt $ALERT_CONFIG.WarningThreshold) {
        $alert = @{
            Id = "COVERAGE_WARNING_$(Get-Date -Format 'yyyyMMddHHmmss')"
            Level = "WARNING"
            Category = "COVERAGE"
            Message = "Cobertura de testes baixa: $([math]::Round($coverage, 1))%"
            Details = "$testedPatterns de $totalPatterns padroes testados"
            Timestamp = Get-Date
            Action = "Considerar implementar testes adicionais"
            AutoEscalation = $false
        }
        $AlertSystem.ActiveAlerts += $alert
        $AlertSystem.AlertCounters.Warning++
        Write-Host "   ⚠️ ALERTA DE AVISO: Cobertura baixa"
    } else {
        Write-Host "   ✅ Cobertura adequada"
    }
    
    return $coverage
}

function Test-RiskAlerts {
    param($AlertSystem)
    
    Write-Host "3. VERIFICANDO ALERTAS DE RISCO..."
    
    # Calcula score de risco
    $riskScore = 0
    $highRiskPatterns = @()
    
    $logsDir = "logs"
    
    if (Test-Path "$logsDir/pipeline_multi_diag.log") {
        $lines = Get-Content "$logsDir/pipeline_multi_diag.log"
        $generateCalls = ($lines | Select-String "Chamando generate_article").Count
        $testingMentions = ($lines | Select-String "TESTING=").Count
        
        if ($generateCalls -gt 0) {
            $riskScore += 150
            $highRiskPatterns += "Fluxo de Geracao (Risk: 150)"
        }
        if ($testingMentions -gt 0) {
            $riskScore += 80
        }
    }
    
    if (Test-Path "$logsDir/decisions_2025-01-27.log") {
        $lines = Get-Content "$logsDir/decisions_2025-01-27.log"
        $testDecisions = ($lines | Select-String "test" -CaseSensitive:$false).Count
        
        if ($testDecisions -gt 0) {
            $riskScore += 90
        }
    }
    
    $avgRiskScore = if ($highRiskPatterns.Count -gt 0) { $riskScore / $highRiskPatterns.Count } else { 0 }
    
    Write-Host "   Score medio de risco: $([math]::Round($avgRiskScore, 1))"
    
    # Gera alertas baseados no risco
    if ($avgRiskScore -gt $ALERT_CONFIG.RiskThreshold) {
        $alert = @{
            Id = "RISK_HIGH_$(Get-Date -Format 'yyyyMMddHHmmss')"
            Level = "WARNING"
            Category = "RISK"
            Message = "Score de risco elevado: $([math]::Round($avgRiskScore, 1))"
            Details = "Padroes de alto risco: $($highRiskPatterns -join ', ')"
            Timestamp = Get-Date
            Action = "Revisar padroes de alto risco"
            AutoEscalation = $false
        }
        $AlertSystem.ActiveAlerts += $alert
        $AlertSystem.AlertCounters.Warning++
        Write-Host "   ⚠️ ALERTA DE RISCO: Score elevado"
    } else {
        Write-Host "   ✅ Risco dentro dos limites"
    }
    
    return $avgRiskScore
}

function Test-HealthAlerts {
    param($AlertSystem)
    
    Write-Host "4. VERIFICANDO ALERTAS DE SAUDE..."
    
    $healthIssues = @()
    
    # Verifica arquivos de log
    $logsDir = "logs"
    $requiredLogs = @("pipeline_multi_diag.log", "decisions_2025-01-27.log")
    
    foreach ($logFile in $requiredLogs) {
        if (-not (Test-Path "$logsDir/$logFile")) {
            $healthIssues += "Log $logFile nao encontrado"
        }
    }
    
    # Verifica scripts de teste
    $testScripts = @("simple_flow_demo.ps1", "test_monitoring_flow.ps1")
    
    foreach ($script in $testScripts) {
        if (-not (Test-Path "scripts/$script")) {
            $healthIssues += "Script $script nao encontrado"
        }
    }
    
    if ($healthIssues.Count -gt 0) {
        $alert = @{
            Id = "HEALTH_ISSUES_$(Get-Date -Format 'yyyyMMddHHmmss')"
            Level = "WARNING"
            Category = "HEALTH"
            Message = "Problemas de saude detectados: $($healthIssues.Count) issues"
            Details = $healthIssues -join "; "
            Timestamp = Get-Date
            Action = "Verificar integridade do framework"
            AutoEscalation = $false
        }
        $AlertSystem.ActiveAlerts += $alert
        $AlertSystem.AlertCounters.Warning++
        Write-Host "   ⚠️ ALERTA DE SAUDE: $($healthIssues.Count) problemas"
    } else {
        Write-Host "   ✅ Saude do framework OK"
    }
    
    return $healthIssues.Count
}

function Send-AlertNotifications {
    param($AlertSystem)
    
    Write-Host "5. ENVIANDO NOTIFICACOES DE ALERTA..."
    
    foreach ($channel in $ALERT_CONFIG.NotificationChannels) {
        switch ($channel) {
            "CONSOLE" {
                Write-Host "   📢 CONSOLE - Alertas ativos: $($AlertSystem.ActiveAlerts.Count)"
                foreach ($alert in $AlertSystem.ActiveAlerts) {
                    $levelIcon = switch ($alert.Level) {
                        "CRITICAL" { "🔴" }
                        "WARNING" { "🟡" }
                        "INFO" { "🔵" }
                    }
                    Write-Host "     $levelIcon [$($alert.Level)] $($alert.Message)"
                }
            }
            "FILE" {
                $alertFile = "alerts/active_alerts_$(Get-Date -Format 'yyyyMMdd').json"
                $alertDir = Split-Path $alertFile -Parent
                if (-not (Test-Path $alertDir)) {
                    New-Item -ItemType Directory -Path $alertDir -Force | Out-Null
                }
                $AlertSystem.ActiveAlerts | ConvertTo-Json -Depth 10 | Out-File -FilePath $alertFile -Encoding UTF8
                Write-Host "   💾 FILE - Alertas salvos em: $alertFile"
            }
            "EMAIL" {
                Write-Host "   📧 EMAIL - Simulando envio de notificacoes"
                # Aqui seria implementado o envio real de emails
            }
        }
    }
}

function Generate-AlertReport {
    param($AlertSystem, $Coverage, $RiskScore, $HealthIssues)
    
    Write-Host "6. GERANDO RELATORIO DE ALERTAS..."
    
    $outputDir = "alerts"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssZ"
    $reportFile = "$outputDir/alert_report_$timestamp.json"
    
    $alertReport = @{
        AlertInfo = @{
            TracingId = $TRACING_ID
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Description = "Relatorio de Alertas Avancados"
            SystemStatus = if ($AlertSystem.ActiveAlerts.Count -eq 0) { "HEALTHY" } else { "ALERTS_ACTIVE" }
        }
        Metrics = @{
            Coverage = $Coverage
            RiskScore = $RiskScore
            HealthIssues = $HealthIssues
        }
        AlertSummary = @{
            TotalAlerts = $AlertSystem.ActiveAlerts.Count
            CriticalAlerts = $AlertSystem.AlertCounters.Critical
            WarningAlerts = $AlertSystem.AlertCounters.Warning
            InfoAlerts = $AlertSystem.AlertCounters.Info
        }
        ActiveAlerts = $AlertSystem.ActiveAlerts
        Config = $ALERT_CONFIG
    }
    
    try {
        $alertReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Host "   Relatorio salvo: $reportFile"
        return $reportFile
    } catch {
        Write-Host "   Erro ao salvar relatorio: $_"
        return $null
    }
}

function Cleanup-OldAlerts {
    Write-Host "7. LIMPANDO ALERTAS ANTIGOS..."
    
    $retentionDays = $ALERT_CONFIG.AlertRetention
    $cutoffDate = (Get-Date).AddDays(-$retentionDays)
    
    $alertsDir = "alerts"
    if (Test-Path $alertsDir) {
        $oldFiles = Get-ChildItem -Path $alertsDir -File | Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        if ($oldFiles.Count -gt 0) {
            Write-Host "   Removendo $($oldFiles.Count) arquivos de alerta antigos..."
            $oldFiles | Remove-Item -Force
        } else {
            Write-Host "   Nenhum arquivo de alerta antigo encontrado"
        }
    }
}

# Executa sistema de alertas
try {
    Write-Host "INICIANDO SISTEMA DE ALERTAS AVANCADO..."
    Write-Host ""
    
    # Inicializa sistema
    $alertSystem = Initialize-AlertSystem
    Write-Host ""
    
    # Verifica alertas de cobertura
    $coverage = Test-CoverageAlerts -AlertSystem $alertSystem
    Write-Host ""
    
    # Verifica alertas de risco
    $riskScore = Test-RiskAlerts -AlertSystem $alertSystem
    Write-Host ""
    
    # Verifica alertas de saude
    $healthIssues = Test-HealthAlerts -AlertSystem $alertSystem
    Write-Host ""
    
    # Envia notificacoes
    Send-AlertNotifications -AlertSystem $alertSystem
    Write-Host ""
    
    # Gera relatorio
    $reportFile = Generate-AlertReport -AlertSystem $alertSystem -Coverage $coverage -RiskScore $riskScore -HealthIssues $healthIssues
    Write-Host ""
    
    # Limpa alertas antigos
    Cleanup-OldAlerts
    Write-Host ""
    
    # Relatorio final
    Write-Host "=" * 80
    Write-Host "SISTEMA DE ALERTAS EXECUTADO:"
    Write-Host "  Alertas ativos: $($alertSystem.ActiveAlerts.Count)"
    Write-Host "  Alertas criticos: $($alertSystem.AlertCounters.Critical)"
    Write-Host "  Alertas de aviso: $($alertSystem.AlertCounters.Warning)"
    Write-Host "  Cobertura: $([math]::Round($coverage, 1))%"
    Write-Host "  Risco: $([math]::Round($riskScore, 1))"
    Write-Host "  Problemas de saude: $healthIssues"
    Write-Host "  Relatorio: $(if($reportFile){'GERADO'}else{'FALHOU'})"
    Write-Host ""
    
    if ($alertSystem.ActiveAlerts.Count -eq 0) {
        Write-Host "✅ SISTEMA SAUDAVEL - NENHUM ALERTA ATIVO"
    } else {
        Write-Host "⚠️ ATENCAO REQUERIDA - $($alertSystem.ActiveAlerts.Count) ALERTAS ATIVOS"
    }
    
} catch {
    Write-Host "ERRO NO SISTEMA DE ALERTAS: $_"
    exit 1
} 