FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1 \
    PORT=8080
EXPOSE 8080

# Secrets arrive as env vars (fly secrets):
#   ZME_SUPABASE_KEY   (anon — never the service-role key)
#   NVIDIA_API_KEY     (optional; enables the vector arm of hybrid search)
#   ZME_MCP_TOKEN      (bearer token guarding /mcp)
CMD ["sh", "-c", "clawpanel-mcp --http --host 0.0.0.0 --port ${PORT}"]
