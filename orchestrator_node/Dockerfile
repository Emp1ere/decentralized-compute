FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Порт, на котором слушает Flask
EXPOSE 5000

# Запускаем наш сервер-оркестратор
CMD ["python", "app.py"]