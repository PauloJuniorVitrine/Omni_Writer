from locust import HttpUser, task, between
from utils_load import gerar_trace_id, log_response_time
import time
import random

class StatusUser(HttpUser):
    """Usuário Locust para carga no endpoint /status/<trace_id>."""
    wait_time = between(1, 2)

    @task(3)
    def check_status(self):
        trace_id = gerar_trace_id()
        start = time.time()
        with self.client.get(f"/status/{trace_id}", catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, f"/status/{trace_id}", resp.status_code)
            if resp.status_code in (200, 404):
                resp.success()
            else:
                resp.failure(f"/status/{trace_id} falhou: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def check_status_invalido(self):
        """Simula trace_id malformado para testar resposta de erro controlado."""
        trace_id = "!!!" + str(random.randint(10000, 99999))
        start = time.time()
        with self.client.get(f"/status/{trace_id}", catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, f"/status/{trace_id}[inválido]", resp.status_code)
            if resp.status_code in (400, 404):
                resp.success()
            else:
                resp.failure(f"/status/{trace_id}[inválido] falhou: {resp.status_code}, Body: {resp.content[:200]}") 