# Compliance Evidence Locker: Docker image
# A CLI that keeps audit events in a SHA-256 hash chain and tags them with 21 CFR Part 11 controls

FROM python:3.11-slim

LABEL org.opencontainers.image.title="compliance-evidence-locker"
LABEL org.opencontainers.image.description="Audit events in a SHA-256 hash chain, tagged with 21 CFR Part 11 §11.10 controls (prototype)"

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

ENTRYPOINT ["evidence-locker"]
CMD ["--help"]

