FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache su-exec

COPY requirements-all.txt requirements.txt ./
RUN pip install --no-cache-dir -r requirements-all.txt

RUN adduser -D -u 1000 notimail

COPY NotiMail.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

RUN mkdir -p /app/config /app/data /app/logs \
    && chown -R notimail:notimail /app

VOLUME ["/app/config", "/app/data", "/app/logs"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f "python NotiMail.py" > /dev/null || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
