FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        qemu-system-x86 e2fsprogs openssh-client ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
