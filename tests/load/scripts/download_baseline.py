from locust import HttpUser, task, between

class DownloadBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def download_zip(self):
        with self.client.get("/download", catch_response=True) as response:
            if response.status_code == 200 and response.headers.get("Content-Type", "").startswith("application/zip"):
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Content-Type: {response.headers.get('Content-Type')}") 