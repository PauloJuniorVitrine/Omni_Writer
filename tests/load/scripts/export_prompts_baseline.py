from locust import HttpUser, task, between

class ExportPromptsBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def export_prompts(self):
        with self.client.get("/export_prompts", catch_response=True) as response:
            if response.status_code == 200 and response.headers.get("Content-Type", "").startswith("text/csv"):
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Content-Type: {response.headers.get('Content-Type')}") 