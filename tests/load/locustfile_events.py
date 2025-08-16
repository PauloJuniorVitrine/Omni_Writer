from locust import HttpUser, task, between
from utils_load import gerar_trace_id, log_response_time
import time
import random

class EventsUser(HttpUser):
    """Usuário Locust para carga no endpoint /events/<trace_id>."""
    wait_time = between(1, 2)

    @task(3)
    def sse_events(self):
        trace_id = gerar_trace_id()
        start = time.time()
        with self.client.get(f"/events/{trace_id}", stream=True, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, f"/events/{trace_id}", resp.status_code)
            if resp.status_code == 200 and b"data:" in resp.content:
                resp.success()
            else:
                resp.failure(f"/events/{trace_id} falhou: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def sse_events_invalido(self):
        """Simula trace_id inválido para testar resposta de erro controlado."""
        trace_id = "invalido-" + str(random.randint(10000, 99999))
        start = time.time()
        with self.client.get(f"/events/{trace_id}", stream=True, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, f"/events/{trace_id}[inválido]", resp.status_code)
            if resp.status_code in (200, 404, 400):
                resp.success()
            else:
                resp.failure(f"/events/{trace_id}[inválido] falhou: {resp.status_code}, Body: {resp.content[:200]}") 