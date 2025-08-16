from locust import HttpUser, task, between
from utils_load import gerar_url_webhook, log_response_time
import time

class WebhookUser(HttpUser):
    """Usuário Locust para carga no endpoint /webhook."""
    wait_time = between(1, 2)

    @task(3)
    def register_webhook(self):
        url = gerar_url_webhook()
        data = {"url": url}
        start = time.time()
        with self.client.post("/webhook", data=data, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/webhook", resp.status_code)
            if resp.status_code == 200 and (b"ok" in resp.content or b"status" in resp.content):
                resp.success()
            else:
                resp.failure(f"/webhook falhou: {resp.status_code}, Body: {resp.content[:200]}")

    @task(1)
    def register_webhook_invalido(self):
        """Envia payload sem campo 'url' para testar resposta de erro controlado."""
        data = {"foo": "bar"}
        start = time.time()
        with self.client.post("/webhook", data=data, catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/webhook[inválido]", resp.status_code)
            if resp.status_code in (400, 422) and (b"error" in resp.content.lower() or b"url" in resp.content.lower()):
                resp.success()
            else:
                resp.failure(f"Webhook inválido: {resp.status_code}, Body: {resp.content[:200]}") 