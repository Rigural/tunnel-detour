FROM adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0 AS adguard
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nftables iproute2 iputils-ping unbound openssl curl busybox-static \
        util-linux wireguard-tools ca-certificates zstd \
    && apt-get clean

WORKDIR /tmp
COPY --from=adguard /opt/adguardhome/AdGuardHome /usr/local/bin/AdGuardHome
