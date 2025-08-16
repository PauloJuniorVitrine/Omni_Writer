import random
import json
import time

def gerar_prompts(n=None):
    n = n or random.randint(1, 3)
    return [f"prompt {i}" for i in range(1, n+1)]

def gerar_instancia(nome=None, prompts=None):
    return {
        "nome": nome or f"inst{random.randint(1, 10000)}",
        "modelo": "openai",
        "api_key": "sk-teste",
        "prompts": prompts or gerar_prompts()
    }

def gerar_payload_generate():
    prompts = gerar_prompts()
    instancias = [gerar_instancia(prompts=prompts)]
    return {
        "instancias_json": json.dumps(instancias),
        "prompts": "\n".join(prompts)
    }

def gerar_payload_feedback():
    return {
        "id_artigo": random.randint(1, 10000),
        "prompt": f"prompt {random.randint(1, 10)}",
        "avaliacao": random.choice(["positivo", "negativo"]),
        "comentario": f"Comentário teste {random.randint(1, 10000)}"
    }

def gerar_url_webhook():
    return f"http://localhost/webhook_teste_{random.randint(1, 10000)}"

def gerar_trace_id():
    return f"test-{random.randint(1, 10000)}"

def log_response_time(start, end, endpoint, status):
    elapsed = end - start
    print(f"[LOAD][{endpoint}] Status: {status} | Tempo: {elapsed:.3f}s")
    return elapsed 