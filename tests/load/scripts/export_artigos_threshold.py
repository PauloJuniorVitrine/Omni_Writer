from locust import HttpUser, task, between

class ExportArtigosThresholdUser(HttpUser):
    wait_time = between(0.5, 2)

    @task
    def export_artigos(self):
        with self.client.get("/export_artigos_csv", catch_response=True) as response:
            if response.status_code == 200 and response.headers.get("Content-Type", "").startswith("text/csv"):
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Content-Type: {response.headers.get('Content-Type')}") 