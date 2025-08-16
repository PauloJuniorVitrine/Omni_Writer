from locust import HttpUser, task, between
import random

class GenerateArticleBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def generate_article(self):
        payload = {
            "api_key": "sk-teste",
            "model_type": "openai",
            "prompts": [{"text": f"prompt baseline {random.randint(1,1000)}", "index": 0}]
        }
        with self.client.post("/generate", data=payload, catch_response=True) as response:
            if response.status_code == 200 and "download_link" in response.text:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 