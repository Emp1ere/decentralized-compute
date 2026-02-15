# Сборка из корня репозитория: docker-compose с context: . и dockerfile: orchestrator_node/Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Общий модуль вычислений (один источник правды для верификации)
COPY shared /app/shared
# Desktop agent bundle for /download/desktop-agent endpoint
COPY desktop_agent /app/desktop_agent
# Модуль оркестратора
COPY orchestrator_node/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY orchestrator_node/ .

# Импорт shared.computation_types из /app
ENV PYTHONPATH=/app

EXPOSE 5000
CMD ["python", "app.py"]
