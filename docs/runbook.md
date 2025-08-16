# Runbook — Omni Writer

## Rotinas de Operação
- Iniciar serviços: `flask run`, `celery -A app.celery_worker worker --loglevel=info`
- Parar serviços: `Ctrl+C` ou `kill <pid>`
- Verificar status: logs em `/logs/`, status via API `/status/<trace_id>`

## Troubleshooting
- Falha ao iniciar: verifique variáveis de ambiente e dependências (`requirements.txt`)
- Erros de geração: consulte logs em `/logs/` e status via API
- Falha de integração com OpenAI/DeepSeek: valide chaves e conectividade

## Contingência
- Backup: copie diretórios `artigos_gerados/` e `logs/`
- Restore: recoloque arquivos de backup nos diretórios originais
- Recuperação de falha: reinicie serviços e consulte logs para diagnóstico

## Contatos/Escalonamento
- Suporte N1: devops@empresa.com
- Suporte N2: techlead@empresa.com
- Escalonamento: gerente@empresa.com 