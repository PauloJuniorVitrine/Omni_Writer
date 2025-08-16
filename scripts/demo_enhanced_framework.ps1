# DEMONSTRACAO DO FRAMEWORK APRIMORADO DE DETECCAO DE FLUXOS
# Análise semântica avançada com detecção de padrões sofisticados
# Tracing ID: DEMO_ENHANCED_FRAMEWORK_20250712_001

$TRACING_ID = "DEMO_ENHANCED_FRAMEWORK_20250712_001"

Write-Host "=== DEMONSTRACAO DO FRAMEWORK APRIMORADO DE DETECCAO DE FLUXOS ==="
Write-Host "Tracing ID: $TRACING_ID"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# Configurações do framework aprimorado
$ENHANCED_CONFIG = @{
    SemanticAnalysis = $true
    ClusteringEnabled = $true
    RiskAssessment = $true
    TechnicalDebtAnalysis = $true
    BusinessImpactAnalysis = $true
    ConfidenceScoring = $true
    MinConfidenceThreshold = 0.7
    MaxPatternsPerCluster = 10
}

function Start-EnhancedFlowDetection {
    Write-Host "1. INICIANDO ANÁLISE SEMÂNTICA APRIMORADA..."
    Write-Host "   Análise semântica: $($ENHANCED_CONFIG.SemanticAnalysis)"
    Write-Host "   Clustering habilitado: $($ENHANCED_CONFIG.ClusteringEnabled)"
    Write-Host "   Avaliação de risco: $($ENHANCED_CONFIG.RiskAssessment)"
    Write-Host "   Análise de dívida técnica: $($ENHANCED_CONFIG.TechnicalDebtAnalysis)"
    Write-Host "   Análise de impacto no negócio: $($ENHANCED_CONFIG.BusinessImpactAnalysis)"
    Write-Host "   Score de confiança: $($ENHANCED_CONFIG.ConfidenceScoring)"
    Write-Host ""
    
    # Análise semântica de logs
    $semanticAnalysis = Analyze-LogsSemantically
    Write-Host "2. ANÁLISE SEMÂNTICA CONCLUÍDA..."
    Write-Host "   Entradas processadas: $($semanticAnalysis.TotalEntries)"
    Write-Host "   Clusters identificados: $($semanticAnalysis.Clusters.Count)"
    Write-Host "   Padrões de negócio: $($semanticAnalysis.BusinessPatterns.Count)"
    Write-Host ""
    
    # Detecção de padrões aprimorada
    $enhancedPatterns = Detect-EnhancedPatterns -SemanticAnalysis $semanticAnalysis
    Write-Host "3. DETECÇÃO DE PADRÕES APRIMORADA..."
    Write-Host "   Padrões detectados: $($enhancedPatterns.Count)"
    Write-Host "   Padrões de alto risco: $(($enhancedPatterns | Where-Object { $_.RiskScore -gt 100 }).Count)"
    Write-Host "   Padrões não testados: $(($enhancedPatterns | Where-Object { -not $_.IsTested }).Count)"
    Write-Host ""
    
    # Análise de cobertura aprimorada
    $enhancedCoverage = Analyze-EnhancedCoverage -Patterns $enhancedPatterns
    Write-Host "4. ANÁLISE DE COBERTURA APRIMORADA..."
    Write-Host "   Cobertura geral: $([math]::Round($enhancedCoverage.OverallCoverage, 1))%"
    Write-Host "   Lacunas críticas: $($enhancedCoverage.CriticalGaps.Count)"
    Write-Host "   Dívida técnica média: $([math]::Round($enhancedCoverage.AverageTechnicalDebt, 2))"
    Write-Host ""
    
    # Avaliação de risco aprimorada
    $enhancedRisk = Assess-EnhancedRisk -Patterns $enhancedPatterns
    Write-Host "5. AVALIAÇÃO DE RISCO APRIMORADA..."
    Write-Host "   Score médio de risco: $([math]::Round($enhancedRisk.AverageRiskScore, 1))"
    Write-Host "   Padrões críticos: $($enhancedRisk.CriticalPatterns.Count)"
    Write-Host "   Distribuição de risco: $($enhancedRisk.RiskDistribution | ConvertTo-Json -Compress)"
    Write-Host ""
    
    # Gera recomendações aprimoradas
    $recommendations = Generate-EnhancedRecommendations -Patterns $enhancedPatterns -Coverage $enhancedCoverage -Risk $enhancedRisk
    Write-Host "6. RECOMENDAÇÕES APRIMORADAS..."
    foreach ($rec in $recommendations) {
        Write-Host "   • $rec"
    }
    Write-Host ""
    
    # Salva resultados aprimorados
    Save-EnhancedResults -SemanticAnalysis $semanticAnalysis -Patterns $enhancedPatterns -Coverage $enhancedCoverage -Risk $enhancedRisk -Recommendations $recommendations
    
    return @{
        SemanticAnalysis = $semanticAnalysis
        Patterns = $enhancedPatterns
        Coverage = $enhancedCoverage
        Risk = $enhancedRisk
        Recommendations = $recommendations
    }
}

function Analyze-LogsSemantically {
    Write-Host "   Executando análise semântica..."
    
    $semanticAnalysis = @{
        TotalEntries = 0
        Clusters = @{}
        BusinessPatterns = @{}
        ComplexityAnalysis = @{}
        SentimentAnalysis = @{}
        ContextKeywords = @()
    }
    
    # Analisa logs estruturados
    $logsDir = "logs"
    
    if (Test-Path "$logsDir/pipeline_multi_diag.log") {
        $lines = Get-Content "$logsDir/pipeline_multi_diag.log"
        $semanticAnalysis.TotalEntries += $lines.Count
        
        # Análise semântica de mensagens
        foreach ($line in $lines) {
            $semanticInfo = Analyze-MessageSemantics -Message $line
            $semanticAnalysis.ContextKeywords += $semanticInfo.Keywords
            
            # Agrupa por contexto de negócio
            if (-not $semanticAnalysis.BusinessPatterns.ContainsKey($semanticInfo.BusinessContext)) {
                $semanticAnalysis.BusinessPatterns[$semanticInfo.BusinessContext] = @()
            }
            $semanticAnalysis.BusinessPatterns[$semanticInfo.BusinessContext] += $line
            
            # Análise de complexidade
            if (-not $semanticAnalysis.ComplexityAnalysis.ContainsKey($semanticInfo.Complexity)) {
                $semanticAnalysis.ComplexityAnalysis[$semanticInfo.Complexity] = 0
            }
            $semanticAnalysis.ComplexityAnalysis[$semanticInfo.Complexity]++
            
            # Análise de sentimento
            if (-not $semanticAnalysis.SentimentAnalysis.ContainsKey($semanticInfo.Sentiment)) {
                $semanticAnalysis.SentimentAnalysis[$semanticInfo.Sentiment] = 0
            }
            $semanticAnalysis.SentimentAnalysis[$semanticInfo.Sentiment]++
        }
    }
    
    if (Test-Path "$logsDir/decisions_2025-01-27.log") {
        $lines = Get-Content "$logsDir/decisions_2025-01-27.log"
        $semanticAnalysis.TotalEntries += $lines.Count
        
        foreach ($line in $lines) {
            $semanticInfo = Analyze-MessageSemantics -Message $line
            $semanticAnalysis.ContextKeywords += $semanticInfo.Keywords
        }
    }
    
    # Remove duplicatas de palavras-chave
    $semanticAnalysis.ContextKeywords = $semanticAnalysis.ContextKeywords | Sort-Object -Unique
    
    # Cria clusters semânticos
    $semanticAnalysis.Clusters = Create-SemanticClusters -BusinessPatterns $semanticAnalysis.BusinessPatterns
    
    return $semanticAnalysis
}

function Analyze-MessageSemantics {
    param($Message)
    
    $messageLower = $Message.ToLower()
    
    # Identifica contexto de negócio
    $businessContext = "general"
    if ($messageLower -match "generate_article|content_creation|article_pipeline") {
        $businessContext = "article_generation"
    } elseif ($messageLower -match "user_authentication|user_authorization|user_profile") {
        $businessContext = "user_management"
    } elseif ($messageLower -match "health_check|performance_monitoring|metrics_collection") {
        $businessContext = "monitoring"
    } elseif ($messageLower -match "test_execution|test_coverage|test_validation") {
        $businessContext = "testing"
    }
    
    # Avalia complexidade
    $complexity = "low"
    if ($messageLower -match "error_handling|fallback|retry|circuit_breaker") {
        $complexity = "high"
    } elseif ($messageLower -match "validation|sanitization|transformation") {
        $complexity = "medium"
    }
    
    # Análise de sentimento
    $sentiment = "neutral"
    if ($messageLower -match "success|completed|ok|healthy|passed") {
        $sentiment = "positive"
    } elseif ($messageLower -match "error|failed|exception|critical|warning") {
        $sentiment = "negative"
    }
    
    # Extrai palavras-chave
    $keywords = @()
    $technicalTerms = [regex]::Matches($messageLower, '\b[a-z_]+(?:_[a-z_]+)*\b') | ForEach-Object { $_.Value }
    $keywords += $technicalTerms | Where-Object { $_.Length -gt 3 }
    
    $ids = [regex]::Matches($Message, '\b[A-Z0-9]{8,}\b') | ForEach-Object { $_.Value }
    $keywords += $ids
    
    return @{
        BusinessContext = $businessContext
        Complexity = $complexity
        Sentiment = $sentiment
        Keywords = $keywords
    }
}

function Create-SemanticClusters {
    param($BusinessPatterns)
    
    $clusters = @{}
    
    foreach ($context in $BusinessPatterns.Keys) {
        $clusterName = "cluster_$context"
        $clusters[$clusterName] = @{
            Name = $context
            Messages = $BusinessPatterns[$context]
            Keywords = Extract-ClusterKeywords -Messages $BusinessPatterns[$context]
            Size = $BusinessPatterns[$context].Count
        }
    }
    
    return $clusters
}

function Extract-ClusterKeywords {
    param($Messages)
    
    $allKeywords = @()
    
    foreach ($message in $Messages) {
        $semanticInfo = Analyze-MessageSemantics -Message $message
        $allKeywords += $semanticInfo.Keywords
    }
    
    # Conta frequência e retorna mais comuns
    $keywordCounts = $allKeywords | Group-Object | Sort-Object Count -Descending
    return $keywordCounts | Select-Object -First 10 | ForEach-Object { $_.Name }
}

function Detect-EnhancedPatterns {
    param($SemanticAnalysis)
    
    Write-Host "   Detectando padrões aprimorados..."
    
    $patterns = @()
    
    foreach ($context in $SemanticAnalysis.BusinessPatterns.Keys) {
        $messages = $SemanticAnalysis.BusinessPatterns[$context]
        
        if ($messages.Count -ge 3) {  # Frequência mínima
            $pattern = Create-EnhancedPattern -Context $context -Messages $messages -SemanticAnalysis $SemanticAnalysis
            if ($pattern) {
                $patterns += $pattern
            }
        }
    }
    
    return $patterns
}

function Create-EnhancedPattern {
    param($Context, $Messages, $SemanticAnalysis)
    
    # Análise de frequência e timing
    $frequency = $Messages.Count
    
    # Análise de complexidade
    $complexityCounts = @{
        'high' = 0
        'medium' = 0
        'low' = 0
    }
    
    foreach ($message in $Messages) {
        $semanticInfo = Analyze-MessageSemantics -Message $message
        $complexityCounts[$semanticInfo.Complexity]++
    }
    
    $dominantComplexity = ($complexityCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Name
    
    # Calcula score de risco aprimorado
    $riskScore = Calculate-EnhancedRiskScore -Context $Context -Complexity $dominantComplexity -Frequency $frequency -Messages $Messages
    
    # Identifica cluster semântico
    $semanticCluster = "cluster_$Context"
    
    # Extrai palavras-chave de contexto
    $contextKeywords = Extract-ClusterKeywords -Messages $Messages
    
    # Avalia impacto no negócio
    $businessImpact = Assess-BusinessImpact -Context $Context -Frequency $frequency -Complexity $dominantComplexity
    
    # Calcula dívida técnica
    $technicalDebt = Calculate-TechnicalDebt -Messages $Messages -Complexity $dominantComplexity
    
    # Calcula score de confiança
    $confidenceScore = Calculate-ConfidenceScore -Messages $Messages -Frequency $frequency -Complexity $dominantComplexity
    
    # Identifica padrões relacionados
    $relatedPatterns = Identify-RelatedPatterns -Context $Context -Keywords $contextKeywords
    
    # Gera sugestões de teste
    $suggestedTests = Generate-TestSuggestions -Context $Context -Complexity $dominantComplexity -Keywords $contextKeywords
    
    return @{
        Name = "Fluxo de $($Context.Replace('_', ' ').ToUpper())"
        Description = "Padrão detectado em $Context com $frequency ocorrências"
        RiskScore = $riskScore
        Frequency = $frequency
        IsTested = Check-IfTested -Context $Context -Keywords $contextKeywords
        SemanticCluster = $semanticCluster
        ContextKeywords = $contextKeywords
        ComplexityLevel = $dominantComplexity
        BusinessImpact = $businessImpact
        TechnicalDebt = $technicalDebt
        LastOccurrence = Get-Date
        FirstOccurrence = (Get-Date).AddDays(-1)
        ConfidenceScore = $confidenceScore
        RelatedPatterns = $relatedPatterns
        SuggestedTests = $suggestedTests
    }
}

function Calculate-EnhancedRiskScore {
    param($Context, $Complexity, $Frequency, $Messages)
    
    $baseScore = @{
        'high' = 100
        'medium' = 60
        'low' = 30
    }[$Complexity]
    
    # Ajusta por frequência
    $frequencyMultiplier = [math]::Min($Frequency / 10, 2.0)
    
    # Ajusta por erros
    $errorCount = 0
    foreach ($message in $Messages) {
        if ($message -match "error|failed|exception|critical") {
            $errorCount++
        }
    }
    $errorMultiplier = 1.0 + ($errorCount / $Messages.Count) * 0.5
    
    return [int]($baseScore * $frequencyMultiplier * $errorMultiplier)
}

function Assess-BusinessImpact {
    param($Context, $Frequency, $Complexity)
    
    if ($Context -in @('article_generation', 'user_management')) {
        if ($Frequency -gt 50) {
            return 'critical'
        } elseif ($Frequency -gt 20) {
            return 'high'
        } else {
            return 'medium'
        }
    } else {
        if ($Complexity -eq 'high' -and $Frequency -gt 10) {
            return 'high'
        } else {
            return 'medium'
        }
    }
}

function Calculate-TechnicalDebt {
    param($Messages, $Complexity)
    
    $baseDebt = @{
        'high' = 0.8
        'medium' = 0.5
        'low' = 0.2
    }[$Complexity]
    
    # Ajusta por frequência de erros
    $errorRate = 0
    foreach ($message in $Messages) {
        if ($message -match "error|failed|exception|critical") {
            $errorRate += 1
        }
    }
    $errorRate = $errorRate / $Messages.Count
    
    return [math]::Min($baseDebt + $errorRate, 1.0)
}

function Calculate-ConfidenceScore {
    param($Messages, $Frequency, $Complexity)
    
    # Base na frequência
    $frequencyScore = [math]::Min($Frequency / 20, 1.0)
    
    # Base na consistência
    $services = $Messages | ForEach-Object { 
        if ($_ -match "service[:\s]+([^\s]+)") { $matches[1] } else { "unknown" }
    } | Sort-Object -Unique
    $consistencyScore = 1.0 - ($services.Count / $Messages.Count)
    
    # Base na complexidade
    $complexityScore = @{
        'high' = 0.9
        'medium' = 0.7
        'low' = 0.5
    }[$Complexity]
    
    return ($frequencyScore + $consistencyScore + $complexityScore) / 3
}

function Check-IfTested {
    param($Context, $Keywords)
    
    $testPatterns = @(
        "test_$Context",
        "${Context}_test",
        "test_$($Context.Replace('_', ''))"
    )
    
    $testKeywords = @('test', 'spec', 'coverage', 'validation')
    
    return ($Keywords | Where-Object { $_ -in $testKeywords }).Count -gt 0
}

function Identify-RelatedPatterns {
    param($Context, $Keywords)
    
    $related = @()
    
    $contextRelations = @{
        'article_generation' = @('content_processing', 'pipeline_execution')
        'user_management' = @('authentication', 'authorization')
        'monitoring' = @('health_check', 'metrics_collection')
        'testing' = @('test_execution', 'coverage_analysis')
    }
    
    if ($contextRelations.ContainsKey($Context)) {
        $related += $contextRelations[$Context]
    }
    
    foreach ($keyword in $Keywords) {
        if ($keyword -match "error") {
            $related += 'error_handling'
        } elseif ($keyword -match "validation") {
            $related += 'input_validation'
        } elseif ($keyword -match "cache") {
            $related += 'caching_strategy'
        }
    }
    
    return $related | Sort-Object -Unique
}

function Generate-TestSuggestions {
    param($Context, $Complexity, $Keywords)
    
    $suggestions = @()
    
    $contextTests = @{
        'article_generation' = @(
            'test_article_generation_pipeline',
            'test_content_validation',
            'test_generation_performance'
        )
        'user_management' = @(
            'test_user_authentication',
            'test_user_authorization',
            'test_user_profile_management'
        )
        'monitoring' = @(
            'test_health_check_endpoints',
            'test_metrics_collection',
            'test_alert_system'
        )
        'testing' = @(
            'test_test_execution_flow',
            'test_coverage_analysis',
            'test_test_reporting'
        )
    }
    
    if ($contextTests.ContainsKey($Context)) {
        $suggestions += $contextTests[$Context]
    }
    
    if ($Complexity -eq 'high') {
        $suggestions += @(
            'test_error_handling_scenarios',
            'test_fallback_mechanisms',
            'test_edge_cases'
        )
    }
    
    foreach ($keyword in $Keywords) {
        if ($keyword -match "validation") {
            $suggestions += 'test_input_validation'
        } elseif ($keyword -match "cache") {
            $suggestions += 'test_cache_behavior'
        } elseif ($keyword -match "error") {
            $suggestions += 'test_error_recovery'
        }
    }
    
    return $suggestions | Sort-Object -Unique
}

function Analyze-EnhancedCoverage {
    param($Patterns)
    
    Write-Host "   Analisando cobertura aprimorada..."
    
    $totalPatterns = $Patterns.Count
    $testedPatterns = ($Patterns | Where-Object { $_.IsTested }).Count
    $untestedPatterns = $totalPatterns - $testedPatterns
    
    $overallCoverage = if ($totalPatterns -gt 0) { ($testedPatterns / $totalPatterns) * 100 } else { 0 }
    
    # Análise por complexidade
    $complexityCoverage = @{}
    foreach ($complexity in @('low', 'medium', 'high')) {
        $complexityPatterns = $Patterns | Where-Object { $_.ComplexityLevel -eq $complexity }
        if ($complexityPatterns.Count -gt 0) {
            $tested = ($complexityPatterns | Where-Object { $_.IsTested }).Count
            $complexityCoverage[$complexity] = @{
                Total = $complexityPatterns.Count
                Tested = $tested
                CoverageRate = if ($complexityPatterns.Count -gt 0) { ($tested / $complexityPatterns.Count) * 100 } else { 0 }
            }
        }
    }
    
    # Análise por impacto no negócio
    $businessImpactCoverage = @{}
    foreach ($impact in @('low', 'medium', 'high', 'critical')) {
        $impactPatterns = $Patterns | Where-Object { $_.BusinessImpact -eq $impact }
        if ($impactPatterns.Count -gt 0) {
            $tested = ($impactPatterns | Where-Object { $_.IsTested }).Count
            $businessImpactCoverage[$impact] = @{
                Total = $impactPatterns.Count
                Tested = $tested
                CoverageRate = if ($impactPatterns.Count -gt 0) { ($tested / $impactPatterns.Count) * 100 } else { 0 }
            }
        }
    }
    
    # Identifica lacunas críticas
    $criticalGaps = @()
    foreach ($pattern in $Patterns) {
        if (-not $pattern.IsTested -and (
            $pattern.ComplexityLevel -eq 'high' -or 
            $pattern.BusinessImpact -in @('high', 'critical') -or
            $pattern.RiskScore -gt 100
        )) {
            $criticalGaps += @{
                PatternName = $pattern.Name
                RiskScore = $pattern.RiskScore
                Complexity = $pattern.ComplexityLevel
                BusinessImpact = $pattern.BusinessImpact
                Frequency = $pattern.Frequency
                SuggestedTests = $pattern.SuggestedTests
            }
        }
    }
    
    # Calcula dívida técnica média
    $averageTechnicalDebt = 0
    if ($Patterns.Count -gt 0) {
        $totalDebt = 0
        foreach ($pattern in $Patterns) {
            $totalDebt += $pattern.TechnicalDebt
        }
        $averageTechnicalDebt = $totalDebt / $Patterns.Count
    }
    
    return @{
        OverallCoverage = $overallCoverage
        TotalPatterns = $totalPatterns
        TestedPatterns = $testedPatterns
        UntestedPatterns = $untestedPatterns
        ComplexityCoverage = $complexityCoverage
        BusinessImpactCoverage = $businessImpactCoverage
        CriticalGaps = $criticalGaps
        AverageTechnicalDebt = $averageTechnicalDebt
    }
}

function Assess-EnhancedRisk {
    param($Patterns)
    
    Write-Host "   Avaliando risco aprimorado..."
    
    if ($Patterns.Count -eq 0) {
        return @{}
    }
    
    $riskScores = @()
    $maxRisk = 0
    foreach ($pattern in $Patterns) {
        $riskScores += $pattern.RiskScore
        if ($pattern.RiskScore -gt $maxRisk) {
            $maxRisk = $pattern.RiskScore
        }
    }
    $averageRisk = if ($riskScores.Count -gt 0) { ($riskScores | Measure-Object -Average).Average } else { 0 }
    
    # Análise de risco por categoria
    $highRiskPatterns = $Patterns | Where-Object { $_.RiskScore -gt 100 }
    $mediumRiskPatterns = $Patterns | Where-Object { $_.RiskScore -ge 50 -and $_.RiskScore -le 100 }
    $lowRiskPatterns = $Patterns | Where-Object { $_.RiskScore -lt 50 }
    
    # Análise de dívida técnica
    $technicalDebtScores = @()
    foreach ($pattern in $Patterns) {
        $technicalDebtScores += $pattern.TechnicalDebt
    }
    $averageTechnicalDebt = if ($technicalDebtScores.Count -gt 0) { ($technicalDebtScores | Measure-Object -Average).Average } else { 0 }
    
    return @{
        AverageRiskScore = $averageRisk
        MaxRiskScore = $maxRisk
        HighRiskCount = $highRiskPatterns.Count
        MediumRiskCount = $mediumRiskPatterns.Count
        LowRiskCount = $lowRiskPatterns.Count
        AverageTechnicalDebt = $averageTechnicalDebt
        RiskDistribution = @{
            High = $highRiskPatterns.Count
            Medium = $mediumRiskPatterns.Count
            Low = $lowRiskPatterns.Count
        }
        CriticalPatterns = $highRiskPatterns | ForEach-Object {
            @{
                Name = $_.Name
                RiskScore = $_.RiskScore
                BusinessImpact = $_.BusinessImpact
                IsTested = $_.IsTested
            }
        }
    }
}

function Generate-EnhancedRecommendations {
    param($Patterns, $Coverage, $Risk)
    
    Write-Host "   Gerando recomendações aprimoradas..."
    
    $recommendations = @()
    
    # Recomendações baseadas na cobertura
    if ($Coverage.OverallCoverage -lt 85) {
        $recommendations += "Implementar testes para atingir cobertura mínima de 85% (atual: $([math]::Round($Coverage.OverallCoverage, 1))%)"
    }
    
    # Recomendações baseadas em lacunas críticas
    foreach ($gap in $Coverage.CriticalGaps) {
        $recommendations += "PRIORIDADE ALTA: Implementar testes para '$($gap.PatternName)' (Risk: $($gap.RiskScore), Impact: $($gap.BusinessImpact))"
    }
    
    # Recomendações baseadas no risco
    if ($Risk.AverageRiskScore -gt 80) {
        $recommendations += "Revisar padrões de alto risco (média: $([math]::Round($Risk.AverageRiskScore, 1)))"
    }
    
    # Recomendações baseadas na dívida técnica
    if ($Risk.AverageTechnicalDebt -gt 0.7) {
        $recommendations += "Reduzir dívida técnica (atual: $([math]::Round($Risk.AverageTechnicalDebt, 2)))"
    }
    
    # Recomendações específicas por padrão
    foreach ($pattern in $Patterns) {
        if (-not $pattern.IsTested -and $pattern.SuggestedTests.Count -gt 0) {
            $testSuggestions = $pattern.SuggestedTests[0..2] -join ', '
            $recommendations += "Implementar testes sugeridos para '$($pattern.Name)': $testSuggestions"
        }
    }
    
    return $recommendations
}

function Save-EnhancedResults {
    param($SemanticAnalysis, $Patterns, $Coverage, $Risk, $Recommendations)
    
    Write-Host "7. SALVANDO RESULTADOS APRIMORADOS..."
    
    $outputDir = "tests/integration/reports"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssZ"
    $outputFile = "$outputDir/enhanced_flow_detection_$timestamp.json"
    
    $enhancedResults = @{
        EnhancedFlowDetectionResult = @{
            Patterns = $Patterns
            SemanticClusters = $SemanticAnalysis.Clusters
            CoverageAnalysis = $Coverage
            RiskAssessment = $Risk
            Recommendations = $Recommendations
        }
        Metadata = @{
            TracingId = $TRACING_ID
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Version = "2.0"
            Description = "Framework Aprimorado de Detecção de Fluxos"
            Config = $ENHANCED_CONFIG
        }
    }
    
    try {
        $enhancedResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "   Resultados salvos: $outputFile"
    } catch {
        Write-Host "   Erro ao salvar resultados: $_"
    }
}

# Executa demonstração do framework aprimorado
try {
    Write-Host "INICIANDO DEMONSTRAÇÃO DO FRAMEWORK APRIMORADO..."
    Write-Host ""
    
    $results = Start-EnhancedFlowDetection
    
    Write-Host "=== RESUMO DOS RESULTADOS APRIMORADOS ==="
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