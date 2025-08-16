# Dockerfile para omni_gerador_artigos
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app/main.py

# ENTRYPOINT e CMD flexíveis para app ou worker
ENTRYPOINT []
CMD ["python", "app/main.py"] 