# Сборка из корня репозитория: docker-compose с context: . и dockerfile: client_worker/Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Общий модуль вычислений (тот же код, что у оркестратора)
COPY shared /app/shared
COPY client_worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY client_worker/ .

ENV PYTHONPATH=/app

CMD ["python", "worker.py"]
