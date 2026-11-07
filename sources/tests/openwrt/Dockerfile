FROM adguard/adguardhome@sha256:e2e1b48c832f7705be915873f95de0d5114de573736441d7f2923a8a6293027c AS adguard
FROM openwrt/rootfs@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af

RUN apk --no-cache add ip-full nftables-json curl unbound-daemon && apk del dnsmasq
COPY --from=adguard /opt/adguardhome/AdGuardHome /usr/bin/AdGuardHome
COPY sources/tests/openwrt/network /etc/config/network
COPY sources/tests/openwrt/firewall /etc/config/firewall
COPY sources/tests/openwrt/unbound.conf /etc/tunnel-detour-lab-unbound.conf
COPY --chmod=755 sources/tests/openwrt/lab.init /etc/init.d/tunnel-detour-lab
COPY --chmod=755 sources/openwrt/files/tunnel-detour.init /etc/init.d/tunnel-detour
COPY sources/openwrt/files/tunnel-detour.config /etc/config/tunnel-detour
COPY sources/openwrt/luci/overview.js /www/luci-static/resources/view/tunnel-detour/overview.js
COPY sources/openwrt/luci/menu.json /usr/share/luci/menu.d/luci-app-tunnel-detour.json
COPY sources/openwrt/luci/acl.json /usr/share/rpcd/acl.d/luci-app-tunnel-detour.json
RUN chmod 600 /etc/config/tunnel-detour && mkdir -p /usr/libexec/rpcd && ln -s /usr/bin/tunnel-detour /usr/libexec/rpcd/tunnel-detour && ln -s ../init.d/tunnel-detour-lab /etc/rc.d/S15tunnel-detour-lab
CMD ["/sbin/init"]
