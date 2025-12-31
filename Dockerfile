# Compliance Evidence Locker - Docker Image
# Automated generation of immutable audit evidence for FDA/HIPAA compliance

FROM python:3.11-slim

LABEL org.opencontainers.image.title="compliance-evidence-locker"
LABEL org.opencontainers.image.description="Immutable audit evidence chain for FDA 21 CFR Part 11 compliance"
LABEL org.opencontainers.image.vendor="Big Data Plumbing"

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY evidence_locker ./evidence_locker
COPY control_definitions ./control_definitions

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Create data directory
RUN mkdir -p /data

ENV PORT=8080
EXPOSE 8080

# Default: run the CLI (can be overridden to run API)
ENTRYPOINT ["evidence-locker"]
CMD ["--help"]

