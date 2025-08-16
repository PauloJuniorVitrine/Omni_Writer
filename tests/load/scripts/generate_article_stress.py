from locust import HttpUser, task, constant_pacing
import random

class GenerateArticleStressUser(HttpUser):
    wait_time = constant_pacing(0.2)  # Requisições muito rápidas

    @task
    def generate_article(self):
        payload = {
            "api_key": "sk-teste",
            "model_type": random.choice(["openai", "deepseek"]),
            "prompts": [
                {"text": f"prompt stress {i} - {random.randint(1,10000)}", "index": i}
                for i in range(5)  # Payload maior
            ]
        }
        with self.client.post("/generate", data=payload, catch_response=True) as response:
            if response.status_code == 200 and "download_link" in response.text:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 