import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ===== MÉTRICAS CUSTOMIZADAS =====
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const requestsPerSecond = new Counter('requests_per_second');

// ===== CONFIGURAÇÕES =====
export const options = {
  // Cenários de teste
  scenarios: {
    // Teste de carga constante
    constant_load: {
      executor: 'constant-vus',
      vus: 10,
      duration: '2m',
      exec: 'constantLoad',
      tags: { test_type: 'constant_load' }
    },
    
    // Teste de pico de carga
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 50 },  // Rampa de subida
        { duration: '1m', target: 50 },   // Pico de carga
        { duration: '30s', target: 0 }    // Rampa de descida
      ],
      exec: 'spikeLoad',
      tags: { test_type: 'spike_test' }
    },
    
    // Teste de stress
    stress_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 200,
      stages: [
        { duration: '2m', target: 50 },   // Aumento gradual
        { duration: '5m', target: 100 },  // Carga alta
        { duration: '2m', target: 0 }     // Redução
      ],
      exec: 'stressTest',
      tags: { test_type: 'stress_test' }
    },
    
    // Teste de endurance
    endurance_test: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 50,
      maxVUs: 100,
      exec: 'enduranceTest',
      tags: { test_type: 'endurance_test' }
    }
  },
  
  // Thresholds (limites de performance)
  thresholds: {
    http_req_duration: ['p(95)<2000'],    // 95% das requisições < 2s
    http_req_failed: ['rate<0.1'],        // Taxa de erro < 10%
    'response_time': ['p(95)<1500'],      // Response time customizado
    'errors': ['rate<0.05']               // Taxa de erro customizada < 5%
  }
};

// ===== VARIÁVEIS GLOBAIS =====
const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
const API_KEY = __ENV.API_KEY || 'test-api-key';

// ===== FUNÇÕES DE TESTE =====

// Teste de carga constante
export function constantLoad() {
  const payload = {
    prompt: "Escreva um artigo sobre inteligência artificial",
    max_tokens: 500,
    temperature: 0.7
  };
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
      'User-Agent': 'k6-load-test'
    },
    timeout: '30s'
  };
  
  const startTime = Date.now();
  const response = http.post(`${BASE_URL}/api/generate`, JSON.stringify(payload), params);
  const endTime = Date.now();
  
  // Registrar métricas
  responseTime.add(endTime - startTime);
  requestsPerSecond.add(1);
  
  // Verificar resposta
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 5s': (r) => r.timings.duration < 5000,
    'has content': (r) => r.body.length > 0,
    'valid json': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch {
        return false;
      }
    }
  });
  
  errorRate.add(!success);
  
  // Sleep entre requisições
  sleep(1);
}

// Teste de pico de carga
export function spikeLoad() {
  const payload = {
    prompt: "Gere um resumo executivo sobre blockchain",
    max_tokens: 300,
    temperature: 0.5
  };
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
      'User-Agent': 'k6-spike-test'
    },
    timeout: '15s'
  };
  
  const startTime = Date.now();
  const response = http.post(`${BASE_URL}/api/generate`, JSON.stringify(payload), params);
  const endTime = Date.now();
  
  responseTime.add(endTime - startTime);
  requestsPerSecond.add(1);
  
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 3s': (r) => r.timings.duration < 3000,
    'has content': (r) => r.body.length > 0
  });
  
  errorRate.add(!success);
  
  sleep(0.5);
}

// Teste de stress
export function stressTest() {
  const prompts = [
    "Escreva um artigo sobre machine learning",
    "Gere um post sobre desenvolvimento web",
    "Crie um texto sobre cloud computing",
    "Redija um artigo sobre DevOps",
    "Escreva sobre segurança da informação"
  ];
  
  const randomPrompt = prompts[Math.floor(Math.random() * prompts.length)];
  
  const payload = {
    prompt: randomPrompt,
    max_tokens: Math.floor(Math.random() * 400) + 100,
    temperature: Math.random() * 0.8 + 0.2
  };
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
      'User-Agent': 'k6-stress-test'
    },
    timeout: '20s'
  };
  
  const startTime = Date.now();
  const response = http.post(`${BASE_URL}/api/generate`, JSON.stringify(payload), params);
  const endTime = Date.now();
  
  responseTime.add(endTime - startTime);
  requestsPerSecond.add(1);
  
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 10s': (r) => r.timings.duration < 10000,
    'has content': (r) => r.body.length > 0
  });
  
  errorRate.add(!success);
  
  sleep(0.2);
}

// Teste de endurance
export function enduranceTest() {
  const payload = {
    prompt: "Escreva um artigo técnico sobre APIs REST",
    max_tokens: 400,
    temperature: 0.6
  };
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
      'User-Agent': 'k6-endurance-test'
    },
    timeout: '25s'
  };
  
  const startTime = Date.now();
  const response = http.post(`${BASE_URL}/api/generate`, JSON.stringify(payload), params);
  const endTime = Date.now();
  
  responseTime.add(endTime - startTime);
  requestsPerSecond.add(1);
  
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 8s': (r) => r.timings.duration < 8000,
    'has content': (r) => r.body.length > 0,
    'valid json': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.hasOwnProperty('content') || data.hasOwnProperty('text');
      } catch {
        return false;
      }
    }
  });
  
  errorRate.add(!success);
  
  sleep(0.8);
}

// ===== FUNÇÕES AUXILIARES =====

// Setup (executado uma vez no início)
export function setup() {
  console.log('🚀 Starting Omni Writer Load Tests');
  console.log(`📍 Base URL: ${BASE_URL}`);
  console.log(`🔑 API Key: ${API_KEY ? 'Configured' : 'Not configured'}`);
  
  // Teste de conectividade
  const healthCheck = http.get(`${BASE_URL}/health`);
  
  if (healthCheck.status !== 200) {
    console.warn('⚠️ Health check failed, but continuing with tests...');
  } else {
    console.log('✅ Health check passed');
  }
  
  return {
    baseUrl: BASE_URL,
    apiKey: API_KEY,
    startTime: new Date().toISOString()
  };
}

// Teardown (executado uma vez no final)
export function teardown(data) {
  console.log('🏁 Load tests completed');
  console.log(`⏱️ Test duration: ${data.startTime} to ${new Date().toISOString()}`);
  
  // Gerar relatório resumido
  const summary = {
    test_info: {
      base_url: data.baseUrl,
      start_time: data.startTime,
      end_time: new Date().toISOString()
    },
    metrics: {
      total_requests: requestsPerSecond.count,
      error_rate: errorRate.rate,
      avg_response_time: responseTime.mean,
      p95_response_time: responseTime.percentile(95)
    }
  };
  
  console.log('📊 Test Summary:', JSON.stringify(summary, null, 2));
}

// ===== HANDLERS DE EVENTOS =====

// Handler para requisições que falharam
export function handleSummary(data) {
  return {
    'k6-results.json': JSON.stringify(data),
    'stdout': textSummary(data, { indent: ' ', enableColors: true })
  };
}

// Função auxiliar para formatação do resumo
function textSummary(data, options) {
  const { metrics, root_group } = data;
  
  let summary = '\n';
  summary += '🚀 OMNI WRITER LOAD TEST RESULTS\n';
  summary += '================================\n\n';
  
  // Métricas principais
  if (metrics.http_req_duration) {
    summary += `📊 Response Time:\n`;
    summary += `   - Average: ${metrics.http_req_duration.avg.toFixed(2)}ms\n`;
    summary += `   - P95: ${metrics.http_req_duration.p(95).toFixed(2)}ms\n`;
    summary += `   - P99: ${metrics.http_req_duration.p(99).toFixed(2)}ms\n\n`;
  }
  
  if (metrics.http_req_rate) {
    summary += `📈 Request Rate:\n`;
    summary += `   - Average: ${metrics.http_req_rate.avg.toFixed(2)} req/s\n`;
    summary += `   - Max: ${metrics.http_req_rate.max.toFixed(2)} req/s\n\n`;
  }
  
  if (metrics.http_req_failed) {
    summary += `❌ Error Rate:\n`;
    summary += `   - Failed: ${(metrics.http_req_failed.rate * 100).toFixed(2)}%\n`;
    summary += `   - Total Errors: ${metrics.http_req_failed.count}\n\n`;
  }
  
  if (metrics.http_reqs) {
    summary += `📋 Total Requests:\n`;
    summary += `   - Count: ${metrics.http_reqs.count}\n`;
    summary += `   - Rate: ${metrics.http_reqs.rate.toFixed(2)} req/s\n\n`;
  }
  
  // Thresholds
  if (root_group && root_group.thresholds) {
    summary += `🎯 Threshold Results:\n`;
    for (const [name, threshold] of Object.entries(root_group.thresholds)) {
      const status = threshold.ok ? '✅' : '❌';
      summary += `   ${status} ${name}: ${threshold.value}\n`;
    }
  }
  
  return summary;
}


