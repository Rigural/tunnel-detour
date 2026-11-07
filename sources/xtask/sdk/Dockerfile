FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libncurses-dev gawk git gettext rsync file unzip zstd bzip2 xz-utils python3 perl wget ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /sdk
