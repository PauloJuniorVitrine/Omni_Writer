from locust import HttpUser, task, between
from utils_load import gerar_payload_feedback, log_response_time
import json
import time

class FeedbackUser(HttpUser):
    """Usuário Locust para carga no endpoint /feedback."""
    wait_time = between(1, 2)

    @task(3)
    def send_feedback(self):
        payload = gerar_payload_feedback()
        headers = {"Content-Type": "application/json"}
        start = time.time()
        with self.client.post("/feedback", data=json.dumps(payload), headers=headers, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/feedback", resp.status_code)
            if resp.status_code == 200 and (b"ok" in resp.content or b"status" in resp.content):
                resp.success()
            else:
                resp.failure(f"/feedback falhou: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def send_feedback_invalido(self):
        """Envia payload faltando campos obrigatórios para testar resposta de erro controlado."""
        payload = {"comentario": "Teste sem id_artigo"}
        headers = {"Content-Type": "application/json"}
        start = time.time()
        with self.client.post("/feedback", data=json.dumps(payload), headers=headers, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/feedback[inválido]", resp.status_code)
            if resp.status_code in (400, 422) and (b"error" in resp.content.lower() or b"id" in resp.content.lower()):
                resp.success()
            else:
                resp.failure(f"Feedback inválido: {resp.status_code}, Body: {resp.content[:200]}") 