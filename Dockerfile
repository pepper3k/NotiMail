FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir requests flask prometheus_client apprise

COPY NotiMail.py .

VOLUME ["/app/config", "/app/data", "/app/logs"]

ENTRYPOINT ["python", "NotiMail.py", "-c", "/app/config/config.ini"]
