FROM adguard/adguardhome@sha256:e2e1b48c832f7705be915873f95de0d5114de573736441d7f2923a8a6293027c AS adguard
FROM openwrt/rootfs@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af AS base

RUN apk --no-cache add ip-full nftables-json conntrack curl unbound-daemon openssl-util kmod-dummy kmod-veth wireguard-tools kmod-wireguard kmod-inet-diag tcpdump
RUN apk --no-cache --no-scripts add rp-pppoe-server
RUN rm -f /etc/rc.d/S98sysntpd
# Block the host kernel log before logd starts in native containers. Docker
# provides the marker; QEMU keeps its own private kernel log.
RUN grep -q 'procd_open_instance logd' /etc/init.d/log && sed -i '/procd_open_instance logd/i\    if [ -d /etc/tunnel-detour-container ] && ! [ /proc/kmsg -ef /dev/null ]; then mount -o bind /dev/null /proc/kmsg || return 1; mount -o remount,bind,ro /dev/null /proc/kmsg || return 1; fi' /etc/init.d/log
COPY sources/tests/openwrt/network /etc/config/network
COPY sources/tests/openwrt/firewall /etc/config/firewall
COPY sources/tests/openwrt/unbound.conf /etc/tunnel-detour-lab-unbound.conf
COPY sources/tests/openwrt/dhcp /etc/config/dhcp
COPY --chmod=755 sources/tests/openwrt/lab.init /etc/init.d/tunnel-detour-lab
COPY --chmod=755 sources/openwrt/files/tunnel-detour.init /etc/init.d/tunnel-detour
COPY --chmod=755 sources/openwrt/files/tunnel-detour-inbound.init /etc/init.d/tunnel-detour-inbound
COPY sources/openwrt/files/tunnel-detour.config /etc/config/tunnel-detour
COPY sources/openwrt/luci/overview.js /www/luci-static/resources/view/tunnel-detour/overview.js
COPY sources/openwrt/luci/inbound.js /www/luci-static/resources/view/tunnel-detour/inbound.js
COPY sources/openwrt/luci/overview.css /www/luci-static/resources/view/tunnel-detour/overview.css
COPY sources/openwrt/luci/menu.json /usr/share/luci/menu.d/luci-app-tunnel-detour.json
COPY sources/openwrt/luci/acl.json /usr/share/rpcd/acl.d/luci-app-tunnel-detour.json
RUN chmod 600 /etc/config/tunnel-detour && mkdir -p /usr/libexec/rpcd && ln -s /usr/bin/tunnel-detour /usr/libexec/rpcd/tunnel-detour && ln -s ../init.d/tunnel-detour-lab /etc/rc.d/S25tunnel-detour-lab && ln -s ../init.d/tunnel-detour-inbound /etc/rc.d/S96tunnel-detour-inbound && ln -s ../init.d/tunnel-detour-inbound /etc/rc.d/K09tunnel-detour-inbound
CMD ["/sbin/init"]

FROM base AS dnsmasq-lab

FROM dnsmasq-lab AS dhcpv6-wan-lab
RUN apk --no-cache --no-scripts add kea-dhcp6

FROM base AS transition-lab
COPY --from=adguard /opt/adguardhome/AdGuardHome /usr/bin/AdGuardHome

FROM base AS adguard-lab
RUN apk del dnsmasq
COPY --from=adguard /opt/adguardhome/AdGuardHome /usr/bin/AdGuardHome
