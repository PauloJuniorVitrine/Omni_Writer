# 🔍 DEMONSTRAÇÃO - FRAMEWORK DE DETECÇÃO DE FLUXOS
# 📐 CoCoT + ToT + ReAct - Baseado em Código Real
# 🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
# ✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer
#
# Script de demonstração em PowerShell do framework de detecção de fluxos.
# Analisa logs reais do Omni Writer e gera relatório de demonstração.
#
# Tracing ID: FLOW_DETECTION_DEMO_PS_20250127_001
# Data/Hora: 2025-01-27T18:30:00Z
# Versão: 1.0

$TRACING_ID = "FLOW_DETECTION_DEMO_PS_20250127_001"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] [$TRACING_ID] $Message"
}

function Test-LogFiles {
    Write-Log "Validando arquivos de log..."
    
    $logsDir = "logs"
    $requiredLogs = @(
        "structured_logs.json",
        "pipeline_multi_diag.log",
        "decisions_2025-01-27.log"
    )
    
    $foundLogs = @()
    $missingLogs = @()
    
    foreach ($logFile in $requiredLogs) {
        $logPath = Join-Path $logsDir $logFile
        if (Test-Path $logPath) {
            $foundLogs += $logFile
            Write-Host "  ✅ $logFile - Encontrado"
        } else {
            $missingLogs += $logFile
            Write-Host "  ❌ $logFile - Não encontrado"
        }
    }
    
    return @{
        Found = $foundLogs
        Missing = $missingLogs
    }
}

function Analyze-StructuredLogs {
    Write-Log "Analisando logs estruturados..."
    
    $logPath = "logs/structured_logs.json"
    if (-not (Test-Path $logPath)) {
        Write-Host "  ❌ Arquivo de logs estruturados não encontrado"
        return $null
    }
    
    try {
        $content = Get-Content $logPath -Raw
        $logs = $content -split "`n" | Where-Object { $_.Trim() -ne "" }
        
        Write-Host "  📊 $($logs.Count) entradas de log analisadas"
        
        $services = @()
        $levels = @()
        $endpoints = @()
        
        foreach ($log in $logs) {
            try {
                $logData = $log | ConvertFrom-Json
                if ($logData.service) { $services += $logData.service }
                if ($logData.level) { $levels += $logData.level }
                if ($logData.endpoint) { $endpoints += $logData.endpoint }
            } catch {
                # Ignora linhas inválidas
            }
        }
        
        $uniqueServices = $services | Sort-Object -Unique
        $uniqueLevels = $levels | Sort-Object -Unique
        $uniqueEndpoints = $endpoints | Sort-Object -Unique
        
        Write-Host "  🔧 Serviços encontrados: $($uniqueServices.Count)"
        Write-Host "  📝 Níveis de log: $($uniqueLevels -join ', ')"
        Write-Host "  🌐 Endpoints: $($uniqueEndpoints.Count)"
        
        return @{
            TotalEntries = $logs.Count
            Services = $uniqueServices
            Levels = $uniqueLevels
            Endpoints = $uniqueEndpoints
        }
        
    } catch {
        Write-Host "  ❌ Erro ao analisar logs: $_"
        return $null
    }
}

function Analyze-PipelineLogs {
    Write-Log "Analisando logs de pipeline..."
    
    $logPath = "logs/pipeline_multi_diag.log"
    if (-not (Test-Path $logPath)) {
        Write-Host "  ❌ Arquivo de logs de pipeline não encontrado"
        return $null
    }
    
    try {
        $lines = Get-Content $logPath
        
        Write-Host "  📊 $($lines.Count) linhas de log analisadas"
        
        $pipelineStarts = 0
        $generateCalls = 0
        $testingMentions = 0
        
        foreach ($line in $lines) {
            if ($line -match "Iniciando pipeline multi") {
                $pipelineStarts++
            }
            if ($line -match "Chamando generate_article") {
                $generateCalls++
            }
            if ($line -match "TESTING=") {
                $testingMentions++
            }
        }
        
        Write-Host "  🔄 Inicializações de pipeline: $pipelineStarts"
        Write-Host "  📝 Chamadas de geração: $generateCalls"
        Write-Host "  🧪 Menções de teste: $testingMentions"
        
        return @{
            TotalLines = $lines.Count
            PipelineStarts = $pipelineStarts
            GenerateCalls = $generateCalls
            TestingMentions = $testingMentions
        }
        
    } catch {
        Write-Host "  ❌ Erro ao analisar logs de pipeline: $_"
        return $null
    }
}

function Analyze-DecisionLogs {
    Write-Log "Analisando logs de decisões..."
    
    $logPath = "logs/decisions_2025-01-27.log"
    if (-not (Test-Path $logPath)) {
        Write-Host "  ❌ Arquivo de logs de decisões não encontrado"
        return $null
    }
    
    try {
        $lines = Get-Content $logPath
        
        Write-Host "  📊 $($lines.Count) linhas de log analisadas"
        
        $testDecisions = 0
        $coverageDecisions = 0
        $riskDecisions = 0
        
        foreach ($line in $lines) {
            $lowerLine = $line.ToLower()
            if ($lowerLine -match "test") {
                $testDecisions++
            }
            if ($lowerLine -match "coverage") {
                $coverageDecisions++
            }
            if ($lowerLine -match "risk") {
                $riskDecisions++
            }
        }
        
        Write-Host "  🧪 Decisões sobre testes: $testDecisions"
        Write-Host "  📈 Decisões sobre cobertura: $coverageDecisions"
        Write-Host "  ⚠️ Decisões sobre risco: $riskDecisions"
        
        return @{
            TotalLines = $lines.Count
            TestDecisions = $testDecisions
            CoverageDecisions = $coverageDecisions
            RiskDecisions = $riskDecisions
        }
        
    } catch {
        Write-Host "  ❌ Erro ao analisar logs de decisões: $_"
        return $null
    }
}

function Detect-FlowPatterns {
    param($AnalysisResults)
    
    Write-Log "Detectando padrões de fluxo..."
    
    $patterns = @()
    
    # Padrões baseados em logs estruturados
    if ($AnalysisResults.StructuredLogs) {
        $structured = $AnalysisResults.StructuredLogs
        
        # Padrão de monitoramento
        $monitoringServices = $structured.Services | Where-Object { $_ -match "monitoring" }
        if ($monitoringServices) {
            $patterns += @{
                Name = "Fluxo de Monitoramento"
                Description = "Detectado através de serviços de monitoramento"
                RiskScore = 80
                Services = $monitoringServices
                IsTested = $false
            }
        }
        
        # Padrão de API
        if ($structured.Endpoints) {
            $patterns += @{
                Name = "Fluxo de API"
                Description = "Detectado através de endpoints de API"
                RiskScore = 120
                Endpoints = $structured.Endpoints
                IsTested = $false
            }
        }
    }
    
    # Padrões baseados em logs de pipeline
    if ($AnalysisResults.PipelineLogs) {
        $pipeline = $AnalysisResults.PipelineLogs
        
        if ($pipeline.GenerateCalls -gt 0) {
            $patterns += @{
                Name = "Fluxo de Geração de Artigos"
                Description = "Detectado através de chamadas de geração"
                RiskScore = 150
                Frequency = $pipeline.GenerateCalls
                IsTested = $true
            }
        }
    }
    
    # Padrões baseados em logs de decisões
    if ($AnalysisResults.DecisionLogs) {
        $decision = $AnalysisResults.DecisionLogs
        
        if ($decision.TestDecisions -gt 0) {
            $patterns += @{
                Name = "Fluxo de Decisões de Teste"
                Description = "Detectado através de decisões sobre testes"
                RiskScore = 90
                Frequency = $decision.TestDecisions
                IsTested = $true
            }
        }
    }
    
    Write-Host "  🎯 $($patterns.Count) padrões de fluxo detectados"
    
    foreach ($pattern in $patterns) {
        $status = if ($pattern.IsTested) { "✅ Testado" } else { "❌ Não Testado" }
        Write-Host "    • $($pattern.Name) (Risk: $($pattern.RiskScore)) - $status"
    }
    
    return $patterns
}

function Generate-DemoReport {
    param($AnalysisResults, $Patterns)
    
    Write-Log "Gerando relatório de demonstração..."
    
    $totalPatterns = $Patterns.Count
    $testedPatterns = ($Patterns | Where-Object { $_.IsTested }).Count
    $untestedPatterns = $totalPatterns - $testedPatterns
    $highRiskPatterns = ($Patterns | Where-Object { $_.RiskScore -ge 100 }).Count
    
    $avgRiskScore = if ($totalPatterns -gt 0) {
        ($Patterns | Measure-Object -Property RiskScore -Average).Average
    } else { 0 }
    
    $coverageRate = if ($totalPatterns -gt 0) {
        ($testedPatterns / $totalPatterns) * 100
    } else { 0 }
    
    $report = @{
        DemoInfo = @{
            TracingId = $TRACING_ID
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Description = "Demonstração do Framework de Detecção de Fluxos"
            BasedOnRealLogs = $true
        }
        AnalysisResults = $AnalysisResults
        FlowPatterns = $Patterns
        Statistics = @{
            TotalPatterns = $totalPatterns
            TestedPatterns = $testedPatterns
            UntestedPatterns = $untestedPatterns
            HighRiskPatterns = $highRiskPatterns
            AvgRiskScore = [math]::Round($avgRiskScore, 1)
            CoverageRate = [math]::Round($coverageRate, 1)
        }
    }
    
    return $report
}

function Show-DemoSummary {
    param($Report)
    
    Write-Host ""
            Write-Host "=" * 80
        Write-Host "DEMONSTRACAO - FRAMEWORK DE DETECCAO DE FLUXOS"
        Write-Host "=" * 80
    
    $demoInfo = $Report.DemoInfo
    $stats = $Report.Statistics
    
            Write-Host "Tracing ID: $($demoInfo.TracingId)"
        Write-Host "Timestamp: $($demoInfo.Timestamp)"
        Write-Host "Baseado em logs reais: $($demoInfo.BasedOnRealLogs)"
        
        Write-Host ""
        Write-Host "RESUMO DA ANALISE:"
    Write-Host "   • Total de padrões: $($stats.TotalPatterns)"
    Write-Host "   • Padrões testados: $($stats.TestedPatterns)"
    Write-Host "   • Padrões não testados: $($stats.UntestedPatterns)"
    Write-Host "   • Padrões de alto risco: $($stats.HighRiskPatterns)"
    Write-Host "   • Score médio de risco: $($stats.AvgRiskScore)"
    Write-Host "   • Taxa de cobertura: $($stats.CoverageRate)%"
    
    if ($Report.FlowPatterns) {
        Write-Host ""
        Write-Host "PADROES DETECTADOS:"
        foreach ($pattern in $Report.FlowPatterns) {
            $status = if ($pattern.IsTested) { "OK" } else { "NAO TESTADO" }
            Write-Host "   $status $($pattern.Name) (Risk: $($pattern.RiskScore))"
            Write-Host "      $($pattern.Description)"
        }
    }
    
    Write-Host ""
    Write-Host "=" * 80
}

function Save-DemoReport {
    param($Report)
    
    $outputDir = "tests/integration/reports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssZ"
    $outputFile = Join-Path $outputDir "flow_detection_demo_ps_$timestamp.json"
    
    try {
        $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Log "Relatório salvo: $outputFile"
        return $outputFile
    } catch {
        Write-Log "Erro ao salvar relatório: $_" -Level "ERROR"
        return $null
    }
}

# Função principal
function Main {
    Write-Log "Iniciando demonstração do framework de detecção de fluxos"
    
    try {
        # Valida arquivos de log
        $logValidation = Test-LogFiles
        
        if ($logValidation.Found.Count -eq 0) {
            Write-Log "Nenhum arquivo de log encontrado. Demonstração abortada." -Level "ERROR"
            return 1
        }
        
        # Analisa logs
        $analysisResults = @{}
        
        $structuredAnalysis = Analyze-StructuredLogs
        if ($structuredAnalysis) {
            $analysisResults.StructuredLogs = $structuredAnalysis
        }
        
        $pipelineAnalysis = Analyze-PipelineLogs
        if ($pipelineAnalysis) {
            $analysisResults.PipelineLogs = $pipelineAnalysis
        }
        
        $decisionAnalysis = Analyze-DecisionLogs
        if ($decisionAnalysis) {
            $analysisResults.DecisionLogs = $decisionAnalysis
        }
        
        if ($analysisResults.Count -eq 0) {
            Write-Log "Nenhuma análise foi possível. Demonstração abortada." -Level "ERROR"
            return 1
        }
        
        # Detecta padrões de fluxo
        $patterns = Detect-FlowPatterns -AnalysisResults $analysisResults
        
        # Gera relatório
        $report = Generate-DemoReport -AnalysisResults $analysisResults -Patterns $patterns
        
        # Mostra resumo
        Show-DemoSummary -Report $report
        
        # Salva relatório
        $outputFile = Save-DemoReport -Report $report
        
        if ($outputFile) {
            Write-Host ""
            Write-Host "Relatorio completo salvo em: $outputFile"
        }
        
        Write-Log "Demonstração concluída com sucesso"
        return 0
        
    } catch {
        Write-Log "Erro na demonstracao: $_" -Level "ERROR"
        return 1
    }
}

# Executa demonstração
$exitCode = Main
exit $exitCode 