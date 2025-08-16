from locust import HttpUser, task, between

class ExportPromptsUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def export_prompts(self):
        self.client.get("/export_prompts") 