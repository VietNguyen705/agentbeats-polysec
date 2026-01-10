# CyberGym Green Agent - Multi-stage Dockerfile
# Build targets: green, purple

# =============================================================================
# Base stage - common dependencies
# =============================================================================
FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy local dependency repos
COPY tutorial-main/ /deps/tutorial-main/
COPY cybergym-main/ /deps/cybergym-main/

# Install Python dependencies
RUN pip install --no-cache-dir \
    a2a-sdk>=0.2.0 \
    pydantic>=2.0.0 \
    python-dotenv>=1.0.0 \
    uvicorn>=0.30.0 \
    httpx>=0.27.0 \
    loguru>=0.7.0 \
    openai>=1.0.0 \
    anthropic>=0.40.0 \
    google-genai>=1.0.0 \
    boto3>=1.35.0

# Install local dependencies
RUN pip install --no-cache-dir -e /deps/tutorial-main -e /deps/cybergym-main

# Set PYTHONPATH
ENV PYTHONPATH="/deps/tutorial-main/src:/deps/cybergym-main/src:/app"

# =============================================================================
# Green agent stage
# =============================================================================
FROM base AS green

# Copy application code
COPY src/ /app/src/
COPY scenarios/ /app/scenarios/
COPY pyproject.toml /app/

# Copy task data for bundled tasks
COPY task_data/ /app/task_data/

# Default to external CyberGym server and bundled task data
ENV CYBERGYM_SERVER=http://134.209.61.175:8666
ENV CYBERGYM_DATA=/app/task_data

EXPOSE 8001

ENTRYPOINT ["python", "-m", "src.green_agent"]
CMD ["--host", "0.0.0.0", "--port", "8001"]

# =============================================================================
# Purple agent stage
# =============================================================================
FROM base AS purple

# Copy application code
COPY src/ /app/src/
COPY pyproject.toml /app/

EXPOSE 8002

ENTRYPOINT ["python", "-m", "src.purple_agent"]
CMD ["--host", "0.0.0.0", "--port", "8002"]
