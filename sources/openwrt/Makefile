include $(TOPDIR)/rules.mk

PKG_NAME:=tunnel-detour
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_URL:=https://github.com/Rigural/tunnel-detour-adguard-home
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/tunnel-detour
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Tunnel Detour for AdGuard Home
  DEPENDS:=+libgcc +procd +rpcd +ubus +uci +ip-full +nftables-json +kmod-nft-nat
endef

define Package/tunnel-detour/description
  Tunnel Detour for AdGuard Home provides domain-based VPN exceptions for OpenWrt, managed through LuCI.
endef

define Package/tunnel-detour/conffiles
/etc/config/tunnel-detour
endef

define Package/luci-app-tunnel-detour
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Tunnel Detour for AdGuard Home - LuCI interface
  DEPENDS:=+luci-base +tunnel-detour
  PKGARCH:=all
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./LICENSE ./THIRD-PARTY-LICENSES $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

# cargo xtask package builds this binary with this SDK's compiler and stages only
# explicit public inputs. The SDK remains responsible for native APK generation.
define Build/Compile
	$(INSTALL_BIN) ./service-binary $(PKG_BUILD_DIR)/tunnel-detour
endef

define Package/tunnel-detour/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tunnel-detour $(1)/usr/bin/tunnel-detour
	$(INSTALL_BIN) ./files/tunnel-detour.init $(1)/etc/init.d/tunnel-detour
	$(INSTALL_CONF) ./files/tunnel-detour.config $(1)/etc/config/tunnel-detour
	$(LN) /usr/bin/tunnel-detour $(1)/usr/libexec/rpcd/tunnel-detour
	$(INSTALL_DIR) $(1)/usr/share/licenses/tunnel-detour
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(PKG_BUILD_DIR)/THIRD-PARTY-LICENSES $(1)/usr/share/licenses/tunnel-detour/
endef

define Package/tunnel-detour/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/rpcd reload
fi
endef

define Package/tunnel-detour/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/usr/bin/tunnel-detour --uninstall || exit 1
fi
endef

define Package/tunnel-detour/postrm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/rpcd reload
fi
endef

define Package/luci-app-tunnel-detour/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/tunnel-detour $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./luci/overview.js $(1)/www/luci-static/resources/view/tunnel-detour/overview.js
	$(INSTALL_DATA) ./luci/overview.css $(1)/www/luci-static/resources/view/tunnel-detour/overview.css
	$(INSTALL_DATA) ./luci/menu.json $(1)/usr/share/luci/menu.d/luci-app-tunnel-detour.json
	$(INSTALL_DATA) ./luci/acl.json $(1)/usr/share/rpcd/acl.d/luci-app-tunnel-detour.json
endef

define Package/luci-app-tunnel-detour/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/rpcd reload
fi
endef

$(eval $(call BuildPackage,tunnel-detour))
$(eval $(call BuildPackage,luci-app-tunnel-detour))
