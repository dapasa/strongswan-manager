# -- Stage 1: Builder --------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform 1.8.2
RUN curl -fsSL https://releases.hashicorp.com/terraform/1.8.2/terraform_1.8.2_linux_amd64.zip \
        -o /tmp/terraform.zip \
    && unzip /tmp/terraform.zip -d /usr/local/bin/ \
    && rm /tmp/terraform.zip \
    && terraform --version

# Install Terragrunt 0.57.12
RUN curl -fsSL https://github.com/gruntwork-io/terragrunt/releases/download/v0.57.12/terragrunt_linux_amd64 \
        -o /usr/local/bin/terragrunt \
    && chmod +x /usr/local/bin/terragrunt \
    && terragrunt --version

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# -- Stage 2: Runtime -------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Terraform & Terragrunt binaries from builder
COPY --from=builder /usr/local/bin/terraform /usr/local/bin/terraform
COPY --from=builder /usr/local/bin/terragrunt /usr/local/bin/terragrunt

# Copy Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

# Create non-root user
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser \
    && chown -R appuser:appuser /app

# Create repos volume mount point owned by appuser
RUN mkdir -p /repos && chown appuser:appuser /repos

USER appuser

EXPOSE 8000

ENTRYPOINT ["bash", "scripts/start.sh"]
