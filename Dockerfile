# ==============================================================================
# SECURESHIP PRODUCTION DOCKERFILE (MULTI-STAGE BUILD)
# ==============================================================================

# Stage 1: Build Web Security Dashboard
FROM node:20-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

# Stage 2: Production Python Engine & Web Server
FROM python:3.11-slim
WORKDIR /app

# Create unprivileged non-root user (Adheres to DevSecOps Least-Privilege)
RUN adduser --disabled-password --gecos "" --uid 10001 secureship && \
    mkdir -p /home/secureship/.secureship && \
    chown -R secureship:secureship /home/secureship

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/secureship/.local/bin:${PATH}"

# Copy and install core engine
COPY --chown=secureship:secureship engine/ /app/engine/
RUN pip install --no-cache-dir /app/engine

# Copy built dashboard static assets
COPY --from=dashboard-builder --chown=secureship:secureship /app/dashboard/dist /app/dashboard/dist

EXPOSE 8787
USER secureship

CMD ["secureship", "serve", "--host", "0.0.0.0", "--port", "8787"]
