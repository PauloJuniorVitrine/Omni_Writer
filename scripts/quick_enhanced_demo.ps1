# DEMONSTRACAO RÁPIDA DO FRAMEWORK APRIMORADO
# Análise semântica simplificada e eficiente
# Tracing ID: QUICK_ENHANCED_DEMO_20250713_001

$TRACING_ID = "QUICK_ENHANCED_DEMO_20250713_001"

Write-Host "=== DEMONSTRAÇÃO RÁPIDA DO FRAMEWORK APRIMORADO ==="
Write-Host "Tracing ID: $TRACING_ID"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

function Start-QuickEnhancedDemo {
    Write-Host "1. ANÁLISE SEMÂNTICA RÁPIDA..."
    
    # Análise rápida de logs
    $analysis = Analyze-LogsQuick
    Write-Host "   Entradas processadas: $($analysis.TotalEntries)"
    Write-Host "   Padrões de negócio: $($analysis.BusinessPatterns.Count)"
    Write-Host ""
    
    # Detecção de padrões
    $patterns = Detect-PatternsQuick -Analysis $analysis
    Write-Host "2. DETECÇÃO DE PADRÕES..."
    Write-Host "   Padrões detectados: $($patterns.Count)"
    Write-Host "   Padrões de alto risco: $(($patterns | Where-Object { $_.RiskScore -gt 100 }).Count)"
    Write-Host "   Padrões não testados: $(($patterns | Where-Object { -not $_.IsTested }).Count)"
    Write-Host ""
    
    # Análise de cobertura
    $coverage = Analyze-CoverageQuick -Patterns $patterns
    Write-Host "3. ANÁLISE DE COBERTURA..."
    Write-Host "   Cobertura geral: $([math]::Round($coverage.OverallCoverage, 1))%"
    Write-Host "   Lacunas críticas: $($coverage.CriticalGaps.Count)"
    Write-Host ""
    
    # Avaliação de risco
    $risk = Assess-RiskQuick -Patterns $patterns
    Write-Host "4. AVALIAÇÃO DE RISCO..."
    Write-Host "   Score médio de risco: $([math]::Round($risk.AverageRiskScore, 1))"
    Write-Host "   Padrões críticos: $($risk.CriticalPatterns.Count)"
    Write-Host ""
    
    # Recomendações
    $recommendations = Generate-RecommendationsQuick -Patterns $patterns -Coverage $coverage -Risk $risk
    Write-Host "5. RECOMENDAÇÕES..."
    foreach ($rec in $recommendations) {
        Write-Host "   • $rec"
    }
    Write-Host ""
    
    # Salva resultados
    Save-QuickResults -Analysis $analysis -Patterns $patterns -Coverage $coverage -Risk $risk -Recommendations $recommendations
    
    return @{
        Analysis = $analysis
        Patterns = $patterns
        Coverage = $coverage
        Risk = $risk
        Recommendations = $recommendations
    }
}

function Analyze-LogsQuick {
    $analysis = @{
        TotalEntries = 0
        BusinessPatterns = @{}
        ComplexityCounts = @{ 'high' = 0; 'medium' = 0; 'low' = 0 }
        SentimentCounts = @{ 'positive' = 0; 'negative' = 0; 'neutral' = 0 }
    }
    
    $logsDir = "logs"
    
    if (Test-Path "$logsDir/pipeline_multi_diag.log") {
        $lines = Get-Content "$logsDir/pipeline_multi_diag.log"
        $analysis.TotalEntries += $lines.Count
        
        foreach ($line in $lines) {
            $info = Analyze-LineQuick -Line $line
            
            # Agrupa por contexto
            if (-not $analysis.BusinessPatterns.ContainsKey($info.Context)) {
                $analysis.BusinessPatterns[$info.Context] = @()
            }
            $analysis.BusinessPatterns[$info.Context] += $line
            
            # Conta complexidade e sentimento
            $analysis.ComplexityCounts[$info.Complexity]++
            $analysis.SentimentCounts[$info.Sentiment]++
        }
    }
    
    if (Test-Path "$logsDir/decisions_2025-01-27.log") {
        $lines = Get-Content "$logsDir/decisions_2025-01-27.log"
        $analysis.TotalEntries += $lines.Count
        
        foreach ($line in $lines) {
            $info = Analyze-LineQuick -Line $line
            $analysis.ComplexityCounts[$info.Complexity]++
            $analysis.SentimentCounts[$info.Sentiment]++
        }
    }
    
    return $analysis
}

function Analyze-LineQuick {
    param($Line)
    
    $lineLower = $Line.ToLower()
    
    # Contexto de negócio
    $context = "general"
    if ($lineLower -match "generate_article|content_creation") {
        $context = "article_generation"
    } elseif ($lineLower -match "test|coverage|validation") {
        $context = "testing"
    } elseif ($lineLower -match "monitor|health|metrics") {
        $context = "monitoring"
    }
    
    # Complexidade
    $complexity = "low"
    if ($lineLower -match "error|exception|fallback") {
        $complexity = "high"
    } elseif ($lineLower -match "validation|transform") {
        $complexity = "medium"
    }
    
    # Sentimento
    $sentiment = "neutral"
    if ($lineLower -match "success|completed|ok") {
        $sentiment = "positive"
    } elseif ($lineLower -match "error|failed|critical") {
        $sentiment = "negative"
    }
    
    return @{
        Context = $context
        Complexity = $complexity
        Sentiment = $sentiment
    }
}

function Detect-PatternsQuick {
    param($Analysis)
    
    $patterns = @()
    
    foreach ($context in $Analysis.BusinessPatterns.Keys) {
        $messages = $Analysis.BusinessPatterns[$context]
        
        if ($messages.Count -ge 3) {
            $pattern = @{
                Name = "Fluxo de $($context.Replace('_', ' ').ToUpper())"
                Context = $context
                Frequency = $messages.Count
                RiskScore = Calculate-RiskQuick -Context $context -Frequency $messages.Count -Messages $messages
                IsTested = Check-TestedQuick -Context $context -Messages $messages
                Complexity = Get-DominantComplexity -Messages $messages
                BusinessImpact = Assess-ImpactQuick -Context $context -Frequency $messages.Count
                SuggestedTests = Generate-TestsQuick -Context $context
            }
            $patterns += $pattern
        }
    }
    
    return $patterns
}

function Calculate-RiskQuick {
    param($Context, $Frequency, $Messages)
    
    $baseScore = 50
    if ($Context -eq "article_generation") { $baseScore = 100 }
    elseif ($Context -eq "testing") { $baseScore = 80 }
    elseif ($Context -eq "monitoring") { $baseScore = 60 }
    
    # Ajusta por frequência
    $frequencyMultiplier = [math]::Min($Frequency / 10, 2.0)
    
    # Ajusta por erros
    $errorCount = 0
    foreach ($message in $Messages) {
        if ($message -match "error|failed|exception") {
            $errorCount++
        }
    }
    $errorMultiplier = 1.0 + ($errorCount / $Messages.Count) * 0.5
    
    return [int]($baseScore * $frequencyMultiplier * $errorMultiplier)
}

function Check-TestedQuick {
    param($Context, $Messages)
    
    $testKeywords = @('test', 'spec', 'coverage', 'validation')
    
    foreach ($message in $Messages) {
        foreach ($keyword in $testKeywords) {
            if ($message -match $keyword) {
                return $true
            }
        }
    }
    
    return $false
}

function Get-DominantComplexity {
    param($Messages)
    
    $complexityCounts = @{ 'high' = 0; 'medium' = 0; 'low' = 0 }
    
    foreach ($message in $Messages) {
        $info = Analyze-LineQuick -Line $message
        $complexityCounts[$info.Complexity]++
    }
    
    $maxCount = 0
    $dominant = "low"
    
    foreach ($complexity in $complexityCounts.Keys) {
        if ($complexityCounts[$complexity] -gt $maxCount) {
            $maxCount = $complexityCounts[$complexity]
            $dominant = $complexity
        }
    }
    
    return $dominant
}

function Assess-ImpactQuick {
    param($Context, $Frequency)
    
    if ($Context -eq "article_generation" -and $Frequency -gt 20) {
        return "critical"
    } elseif ($Context -in @("article_generation", "testing") -and $Frequency -gt 10) {
        return "high"
    } else {
        return "medium"
    }
}

function Generate-TestsQuick {
    param($Context)
    
    $tests = @{
        "article_generation" = @("test_article_pipeline", "test_content_validation")
        "testing" = @("test_execution_flow", "test_coverage_analysis")
        "monitoring" = @("test_health_checks", "test_metrics_collection")
    }
    
    if ($tests.ContainsKey($Context)) {
        return $tests[$Context]
    } else {
        return @("test_$Context")
    }
}

function Analyze-CoverageQuick {
    param($Patterns)
    
    $totalPatterns = $Patterns.Count
    $testedPatterns = ($Patterns | Where-Object { $_.IsTested }).Count
    $overallCoverage = if ($totalPatterns -gt 0) { ($testedPatterns / $totalPatterns) * 100 } else { 0 }
    
    # Identifica lacunas críticas
    $criticalGaps = @()
    foreach ($pattern in $Patterns) {
        if (-not $pattern.IsTested -and (
            $pattern.RiskScore -gt 100 -or 
            $pattern.BusinessImpact -in @("high", "critical")
        )) {
            $criticalGaps += @{
                Name = $pattern.Name
                RiskScore = $pattern.RiskScore
                BusinessImpact = $pattern.BusinessImpact
                SuggestedTests = $pattern.SuggestedTests
            }
        }
    }
    
    return @{
        OverallCoverage = $overallCoverage
        TotalPatterns = $totalPatterns
        TestedPatterns = $testedPatterns
        UntestedPatterns = $totalPatterns - $testedPatterns
        CriticalGaps = $criticalGaps
    }
}

function Assess-RiskQuick {
    param($Patterns)
    
    if ($Patterns.Count -eq 0) {
        return @{
            AverageRiskScore = 0
            CriticalPatterns = @()
        }
    }
    
    $riskScores = @()
    $criticalPatterns = @()
    
    foreach ($pattern in $Patterns) {
        $riskScores += $pattern.RiskScore
        
        if ($pattern.RiskScore -gt 100) {
            $criticalPatterns += @{
                Name = $pattern.Name
                RiskScore = $pattern.RiskScore
                BusinessImpact = $pattern.BusinessImpact
                IsTested = $pattern.IsTested
            }
        }
    }
    
    $averageRisk = ($riskScores | Measure-Object -Average).Average
    
    return @{
        AverageRiskScore = $averageRisk
        CriticalPatterns = $criticalPatterns
    }
}

function Generate-RecommendationsQuick {
    param($Patterns, $Coverage, $Risk)
    
    $recommendations = @()
    
    # Recomendações baseadas na cobertura
    if ($Coverage.OverallCoverage -lt 85) {
        $recommendations += "Implementar testes para atingir cobertura mínima de 85% (atual: $([math]::Round($Coverage.OverallCoverage, 1))%)"
    }
    
    # Recomendações baseadas em lacunas críticas
    foreach ($gap in $Coverage.CriticalGaps) {
        $recommendations += "PRIORIDADE ALTA: Implementar testes para '$($gap.Name)' (Risk: $($gap.RiskScore), Impact: $($gap.BusinessImpact))"
    }
    
    # Recomendações baseadas no risco
    if ($Risk.AverageRiskScore -gt 80) {
        $recommendations += "Revisar padrões de alto risco (média: $([math]::Round($Risk.AverageRiskScore, 1)))"
    }
    
    # Recomendações específicas por padrão
    foreach ($pattern in $Patterns) {
        if (-not $pattern.IsTested) {
            $tests = $pattern.SuggestedTests -join ', '
            $recommendations += "Implementar testes para '$($pattern.Name)': $tests"
        }
    }
    
    return $recommendations
}

function Save-QuickResults {
    param($Analysis, $Patterns, $Coverage, $Risk, $Recommendations)
    
    Write-Host "6. SALVANDO RESULTADOS..."
    
    $outputDir = "tests/integration/reports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssZ"
    $outputFile = "$outputDir/quick_enhanced_demo_$timestamp.json"
    
    $results = @{
        QuickEnhancedDemo = @{
            Analysis = $Analysis
            Patterns = $Patterns
            Coverage = $Coverage
            Risk = $Risk
            Recommendations = $Recommendations
        }
        Metadata = @{
            TracingId = $TRACING_ID
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Version = "2.0"
            Description = "Demonstração Rápida do Framework Aprimorado"
        }
    }
    
    try {
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "   Resultados salvos: $outputFile"
    } catch {
        Write-Host "   Erro ao salvar resultados: $_"
    }
}

# Executa demonstração rápida
try {
    Write-Host "INICIANDO DEMONSTRAÇÃO RÁPIDA DO FRAMEWORK APRIMORADO..."
    Write-Host ""
    
    $results = Start-QuickEnhancedDemo
    
    Write-Host "=== RESUMO DOS RESULTADOS ==="
    Write-Host "Total de padrões: $($results.Patterns.Count)"
    Write-Host "Cobertura geral: $([math]::Round($results.Coverage.OverallCoverage, 1))%"
    Write-Host "Score médio de risco: $([math]::Round($results.Risk.AverageRiskScore, 1))"
    Write-Host "Recomendações geradas: $($results.Recommendations.Count)"
    Write-Host ""
    Write-Host "✅ DEMONSTRAÇÃO CONCLUÍDA COM SUCESSO!"
    
} catch {
    Write-Host "❌ ERRO NA DEMONSTRAÇÃO: $_"
    exit 1
} 