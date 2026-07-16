FROM ghcr.io/catthehacker/ubuntu:act-24.04

ENV PYTHONUNBUFFERED=1
ENV NVT_BROKER_BIND=0.0.0.0:7347

RUN apt-get update \
  && apt-get install -y --no-install-recommends git openssl python3-yaml \
  && rm -rf /var/lib/apt/lists/*

COPY broker /opt/nvt-broker/broker
COPY shared /opt/nvt-broker/shared

WORKDIR /opt/nvt-broker

RUN chmod +x /opt/nvt-broker/broker/brokerd.py /opt/nvt-broker/broker/seed_supervisor.py

EXPOSE 7347
ENTRYPOINT ["/opt/nvt-broker/broker/brokerd.py"]
