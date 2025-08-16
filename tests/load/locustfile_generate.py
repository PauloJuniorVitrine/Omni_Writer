from locust import HttpUser, task, between
from utils_load import gerar_payload_generate, log_response_time
import time
import json

class GenerateUser(HttpUser):
    """Usuário Locust para carga no endpoint /generate."""
    wait_time = between(1, 3)

    @task(5)
    def generate(self):
        data = gerar_payload_generate()
        start = time.time()
        with self.client.post("/generate", data=data, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/generate", resp.status_code)
            if resp.status_code == 200 and b"erro" not in resp.content.lower():
                resp.success()
            else:
                resp.failure(f"Status: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def generate_payload_invalido(self):
        """Envia payload malformado para testar resiliência."""
        data = {
            "instancias_json": "{nome:inst1,modelo:openai,api_key:sk-teste,prompts:[prompt 1]}",  # JSON inválido
            "prompts": "prompt 1"
        }
        start = time.time()
        with self.client.post("/generate", data=data, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/generate[inválido]", resp.status_code)
            if resp.status_code in (200, 400):
                resp.success()
            else:
                resp.failure(f"Payload inválido: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def generate_limite_prompts(self):
        """Envia payload com número máximo de prompts para testar limite."""
        prompts = [f"prompt {i}" for i in range(1, 101)]
        instancias = [{
            "nome": "inst1",
            "modelo": "openai",
            "api_key": "sk-teste",
            "prompts": prompts
        }]
        data = {
            "instancias_json": json.dumps(instancias),
            "prompts": "\n".join(prompts)
        }
        start = time.time()
        with self.client.post("/generate", data=data, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/generate[limite]", resp.status_code)
            if resp.status_code in (200, 400) and (b"limite" in resp.content or b"erro" in resp.content.lower() or b"50" in resp.content):
                resp.success()
            else:
                resp.failure(f"Limite prompts: {resp.status_code}, Body: {resp.content[:200]}") 