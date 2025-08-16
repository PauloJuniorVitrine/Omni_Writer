from locust import HttpUser, task, between
import random

class GenerateArticleThresholdUser(HttpUser):
    wait_time = between(0.5, 2)

    @task
    def generate_article(self):
        payload = {
            "api_key": "sk-teste",
            "model_type": random.choice(["openai", "deepseek"]),
            "prompts": [
                {"text": f"prompt threshold {random.randint(1,1000)}", "index": i}
                for i in range(random.randint(1, 3))
            ]
        }
        with self.client.post("/generate", data=payload, catch_response=True) as response:
            if response.status_code == 200 and "download_link" in response.text:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 