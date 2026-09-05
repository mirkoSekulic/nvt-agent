# Optional packaging layer, usable with either a broker or runtime base image.
# Build both with their normal images first, then select BASE_IMAGE explicitly.
ARG BASE_IMAGE=nvt-agent:latest
FROM ${BASE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/nvt-azure \
    && /opt/nvt-azure/bin/pip install --no-cache-dir azure-cli==2.89.1 PyYAML==6.0.3
ENV AZURE_EXTENSION_DIR=/opt/nvt-azure/extensions
RUN AZURE_CONFIG_DIR=/tmp/nvt-azure-install /opt/nvt-azure/bin/az extension add --name log-analytics --version 1.0.0b1 --yes \
    && rm -rf /tmp/nvt-azure-install
