from locust import HttpUser, task, constant_pacing
import random

class WebhookStressUser(HttpUser):
    wait_time = constant_pacing(0.2)

    @task
    def register_webhook(self):
        url = f"http://localhost:{8000 + random.randint(1, 1000)}"
        payload = {"url": url}
        with self.client.post("/webhook", data=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 