# Ativa o ambiente virtual
Write-Host "Ativando ambiente virtual..."
. .\venv\Scripts\Activate.ps1

# Seta variáveis de ambiente para Redis local
$env:CELERY_BROKER_URL="redis://localhost:6379/0"
$env:CELERY_RESULT_BACKEND="redis://localhost:6379/0"

# Inicia o Redis via Docker (se não estiver rodando)
Write-Host "Iniciando Redis via Docker (se necessário)..."
docker start redis 2>$null
if ($LASTEXITCODE -ne 0) {
    docker run -d -p 6379:6379 --name redis redis:7-alpine
}

# Inicia o worker Celery em background e salva log (stdout + stderr)
Write-Host "Iniciando worker Celery..."
Start-Job -ScriptBlock {
    .\venv\Scripts\celery.exe -A app.celery_worker worker --loglevel=info *> "celery_worker.log"
}

# Aguarda o worker inicializar
Start-Sleep -Seconds 5

# Executa o teste de integração
Write-Host "Executando teste de integração Celery..."
pytest tests/integration/test_celery_worker_integration.py -v --tb=short | Tee-Object -FilePath "celery_test_output.log"

Write-Host "`n--- FIM DO TESTE ---"
Write-Host "Veja o resultado do teste em: celery_test_output.log"
Write-Host "Veja o log do worker em: celery_worker.log"