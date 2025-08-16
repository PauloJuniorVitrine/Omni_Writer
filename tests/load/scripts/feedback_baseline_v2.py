from locust import HttpUser, task, between

class FeedbackUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def send_feedback(self):
        data = {
            "user_id": "usuario123",
            "artigo_id": "artigo456",
            "tipo": "positivo",
            "comentario": "Ótimo artigo!"
        }
        headers = {"Authorization": "Bearer token_valido"}
        self.client.post("/feedback", data=data, headers=headers) 