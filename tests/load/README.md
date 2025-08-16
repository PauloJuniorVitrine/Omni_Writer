# Testes de Carga - Omni Gerador de Artigos

## Estrutura
- Scripts de carga: `/tests/load/locustfile_*.py`
- Resultados e logs: `/tests/load/results/`

## Pré-requisitos
- Python 3.8+
- Instale o Locust:
  ```bash
  pip install locust
  ```
- O servidor Flask deve estar rodando em `localhost:5000` com suporte a múltiplas threads:
  ```bash
  $env:FLASK_APP="app.main"; flask run --host=127.0.0.1 --port=5000 --with-threads
  # ou (recomendado para Windows)
  pip install waitress
  python -m waitress --host=127.0.0.1 --port=5000 app.main:app
  ```

## Execução dos Testes de Carga

### 1. Geração de Artigos (`/generate`)
```bash
locust -f tests/load/locustfile_generate.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/generate_10u
# Aumente para 50, 100, 200, 500 usuários conforme o ciclo
```

### 2. Download (`/download`, `/download_multi`)
```bash
locust -f tests/load/locustfile_download.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/download_10u
```

### 3. SSE/Events (`/events/<trace_id>`)
```bash
locust -f tests/load/locustfile_events.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/events_10u
```

### 4. Webhook (`/webhook`)
```bash
locust -f tests/load/locustfile_webhook.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/webhook_10u
```

### 5. Feedback (`/feedback`)
```bash
locust -f tests/load/locustfile_feedback.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/feedback_10u
```

### 6. Status (`/status/<trace_id>`)
```bash
locust -f tests/load/locustfile_status.py --headless -u 10 -r 2 -t 2m --host=http://localhost:5000 --csv=tests/load/results/status_10u
```

> **Aumente o número de usuários (-u) e o ramp-up (-r) progressivamente em cada ciclo:**
> 10, 50, 100, 200, 500, etc.

## Execução Multi-Região (Distribuição Geográfica)
- Para simular usuários de diferentes localidades, utilize proxies HTTP/SOCKS ou VPNs.
- Exemplo com proxy HTTP:
  ```bash
  $env:HTTP_PROXY="http://proxy-endereco:porta"; locust -f tests/load/locustfile_generate.py ...
  ```
- Para VPN, conecte-se à região desejada antes de executar o Locust.

## Teste de Estresse Extremo (Break Point)
- Aumente o número de usuários até observar falha ou degradação severa.
- Exemplo:
  ```bash
  locust -f tests/load/locustfile_generate.py --headless -u 1000 -r 50 -t 10m --host=http://localhost:5000 --csv=tests/load/results/generate_breakpoint
  ```
- Registre o ponto de quebra, tempo de resposta e tempo de recuperação após reduzir a carga.

## Monitoramento Externo de Recursos
- Monitore CPU, RAM, disco e conexões durante o teste:
  - **Windows:** Task Manager, Resource Monitor
  - **Linux:** htop, top, iotop
  - **Avançado:** Grafana, Prometheus, Datadog
- Registre picos e gargalos para análise posterior.

## Análise Automática dos Resultados
- Após cada ciclo, execute:
  ```bash
  python tests/load/analyze_load_results.py
  ```
- Será gerado um relatório `.md` em `/tests/load/results/` com alertas automáticos e comparativo entre execuções.

## Logging, Análise e Thresholds
- Resultados `.csv` e `.stats` são salvos em `/tests/load/results/`.
- Analise as colunas:
  - `Average Response Time`, `95% Response Time`, `# Fails`, `Requests/s`
- **Thresholds automáticos:**
  - >20% das respostas >800ms = ALERTA
  - >2% de erros 5xx = ALERTA
  - CPU >90% por >15s = ALERTA (monitore via Task Manager, htop, etc.)

## Pós-Teste e Limpeza
- Limpe arquivos temporários e resultados antigos após cada ciclo.
- Valide integridade do banco, arquivos e ambiente.

## Observações
- Não execute em produção.
- Não use dados reais.
- Todos os scripts são versionáveis e auditáveis.

---

**Para dúvidas, análise de resultados ou automação de relatórios, consulte a equipe de engenharia de performance.** 