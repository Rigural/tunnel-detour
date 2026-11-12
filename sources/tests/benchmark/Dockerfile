FROM openwrt/rootfs@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af
ADD --checksum=sha256:4dded51ce29f9cbb3af21b5c97fdccd974b59555c67a3f03a3b5b57cfa09e573 https://downloads.openwrt.org/releases/25.12.6/packages/x86_64/packages/socat-1.8.1.1-r1.apk /tmp/socat.apk
# The feed authenticates packages through its signed index. Require its fetched
# archive to match the pinned source instead of disabling local signature checks.
RUN apk update && apk fetch --output /tmp socat && cmp /tmp/socat-1.8.1.1-r1.apk /tmp/socat.apk && apk add ip-full kmod-inet-diag socat=1.8.1.1-r1 && rm /tmp/socat.apk /tmp/socat-1.8.1.1-r1.apk
