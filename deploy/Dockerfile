FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=127.0.0.1 \
    PORT=8080 \
    GATEWAY_DB=/var/lib/harness-gateway/gateway.db

WORKDIR /app
COPY gateway.py /app/gateway.py
RUN useradd --system --home /nonexistent --shell /usr/sbin/nologin gateway \
    && mkdir -p /var/lib/harness-gateway \
    && chown gateway:gateway /var/lib/harness-gateway
USER gateway
VOLUME ["/var/lib/harness-gateway"]
EXPOSE 8080
ENTRYPOINT ["python", "/app/gateway.py"]
