from locust import HttpUser, task, between
import random

class WebhookThresholdUser(HttpUser):
    wait_time = between(0.5, 2)

    @task
    def register_webhook(self):
        url = f"http://localhost:{8000 + random.randint(1, 100)}"
        payload = {"url": url}
        with self.client.post("/webhook", data=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 