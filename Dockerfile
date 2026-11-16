FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1 \
    PORT=8080
EXPOSE 8080

# Secrets arrive as env vars (fly secrets):
#   CLAWPANEL_DB_KEY          (server-only service role)
#   CLAWPANEL_OAUTH_PROFILES  (legacy connector profile configuration)
#   NVIDIA_API_KEY            (optional vector search)
CMD ["sh", "-c", "clawpanel-mcp --http --host 0.0.0.0 --port ${PORT}"]
