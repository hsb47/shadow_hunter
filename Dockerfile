# ══════════════════════════════════════════════════════════
# Shadow Hunter — Cloud Run Dockerfile
# Builds the full application (API + Analyzer + Simulator)
# No Npcap/libpcap needed — runs in DEMO mode on Cloud Run
# ══════════════════════════════════════════════════════════

FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml .

# Install Python dependencies (skip scapy's pcap and heavy ML libs that aren't needed for demo)
RUN pip install --no-cache-dir --user \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.32.0" \
    "pydantic>=2.9.0" \
    "pydantic-settings>=2.6.0" \
    "httpx>=0.27.0" \
    "loguru>=0.7.2" \
    "networkx>=3.0" \
    "scapy>=2.5.0"

# ── Production Stage ──
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy all application source code
COPY pkg/ pkg/
COPY services/ services/
COPY run_local.py .

# Python can find our packages
ENV PYTHONPATH=/app

# Cloud Run injects PORT (default 8080)
ENV PORT=8080

# Run in demo mode (no --live flag)
CMD ["python", "run_local.py"]
