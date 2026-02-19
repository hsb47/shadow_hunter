# ══════════════════════════════════════════════════════════
# Shadow Hunter — Cloud Run Dockerfile (Hardened)
# Builds the full application (API + Analyzer + Simulator)
# No Npcap/libpcap needed — runs in DEMO mode on Cloud Run
# ══════════════════════════════════════════════════════════

FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml .

# Install Python dependencies
RUN pip install --no-cache-dir --user \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.32.0" \
    "pydantic>=2.9.0" \
    "pydantic-settings>=2.6.0" \
    "httpx>=0.27.0" \
    "loguru>=0.7.2" \
    "networkx>=3.0" \
    "scapy>=2.5.0" \
    "aiosqlite>=0.20.0" \
    "scikit-learn>=1.4.0" \
    "numpy>=1.26.0" \
    "joblib>=1.3.0"

# ── Production Stage ──
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r shadowuser && useradd -r -g shadowuser -d /app -s /sbin/nologin shadowuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/shadowuser/.local
ENV PATH=/home/shadowuser/.local/bin:$PATH

# Copy all application source code
COPY --chown=shadowuser:shadowuser pkg/ pkg/
COPY --chown=shadowuser:shadowuser services/ services/
COPY --chown=shadowuser:shadowuser run_local.py .

# Python can find our packages
ENV PYTHONPATH=/app

# Cloud Run injects PORT (default 8080)
ENV PORT=8080

# Switch to non-root user
USER shadowuser

# Run in demo mode (no --live flag)
CMD ["python", "run_local.py"]
