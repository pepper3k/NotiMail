#!/bin/sh
chown -R notimail:notimail /app/config /app/data /app/logs /app/secrets
exec su-exec notimail python NotiMail.py -c /app/config/config.ini "$@"
