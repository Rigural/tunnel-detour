//! Explicit IPv6 exception configuration; address families never enable implicitly.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};
use tunnel_detour_core::FakeIpRange;

use crate::{ConfigError, ServiceError, kernel};

#[derive(Deserialize)]
struct WanRoute {
    dst: Option<String>,
    gateway: Option<Ipv6Addr>,
    #[serde(default)]
    metric: u32,
    #[serde(rename = "type")]
    kind: Option<String>,
}

fn select_gateway(routes: Vec<WanRoute>) -> Result<Option<Ipv6Addr>, ServiceError> {
    let defaults: Vec<_> = routes
        .into_iter()
        .filter(|route| route.dst.as_deref() == Some("default"))
        .collect();
    let metric = defaults
        .iter()
        .map(|route| route.metric)
        .min()
        .ok_or(ServiceError::Ipv6Path)?;
    let mut gateways = BTreeSet::new();
    for route in defaults.into_iter().filter(|route| route.metric == metric) {
        if route.kind.as_deref().is_some_and(|kind| kind != "unicast") {
            return Err(ServiceError::Ipv6Path);
        }
        gateways.insert(route.gateway.filter(|gateway| !gateway.is_unspecified()));
    }
    if gateways.len() != 1 {
        return Err(ServiceError::Ipv6Path);
    }
    gateways.into_iter().next().ok_or(ServiceError::Ipv6Path)
}

/// Read the selected device's main-table path. netifd's interface status also
/// includes auxiliary policy tables; those must not select the WAN gateway.
pub(crate) async fn wan_gateway(device: &str) -> Result<Option<Ipv6Addr>, ServiceError> {
    let output = kernel::command(
        "ip",
        &["-j", "-6", "route", "show", "table", "main", "dev", device].map(str::to_owned),
        None,
    )
    .await?;
    if !output.success {
        return Err(ServiceError::Ipv6Path);
    }
    select_gateway(serde_json::from_slice(&output.stdout)?)
}

#[derive(Deserialize)]
struct Address {
    local: std::net::IpAddr,
    prefixlen: u8,
    #[serde(default)]
    tentative: bool,
    #[serde(default)]
    dadfailed: bool,
    #[serde(default)]
    temporary: bool,
    preferred_life_time: u64,
    valid_life_time: u64,
}

impl Address {
    fn usable(&self) -> bool {
        !self.tentative
            && !self.dadfailed
            && self.preferred_life_time > 0
            && self.valid_life_time > 0
    }
}

#[derive(Deserialize)]
struct Interface {
    ifname: String,
    flags: Vec<String>,
    addr_info: Vec<Address>,
}

async fn interfaces() -> Result<Vec<Interface>, ServiceError> {
    let result = kernel::command_with_limit(
        "ip",
        &["-j".into(), "address".into(), "show".into()],
        None,
        1_048_576,
    )
    .await?;
    if !result.success {
        return Err(ServiceError::Ipv6Path);
    }
    Ok(serde_json::from_slice(&result.stdout)?)
}

fn find<'a>(interfaces: &'a [Interface], name: &str) -> Result<&'a Interface, ServiceError> {
    interfaces
        .iter()
        .find(|interface| {
            interface.ifname == name && interface.flags.iter().any(|flag| flag == "UP")
        })
        .ok_or(ServiceError::Ipv6Path)
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ipv6Wan {
    pub device: String,
    pub source: Ipv6Addr,
    pub gateway: Option<Ipv6Addr>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ipv6Settings {
    pub lan_networks: Vec<Ipv6Net>,
    pub wan: Ipv6Wan,
}

/// Native unicast only: transition mechanisms can conceal an IPv4 private or
/// management endpoint and do not inherit authorization from an IPv6 spelling.
fn native_internet(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] & 0xe000 == 0x2000
        && segments[0] != 0x2002 // 6to4 embeds an IPv4 gateway.
        && segments[..2] != [0x2001, 0] // Teredo embeds an IPv4 peer.
        && segments[..3] != [0x2001, 2, 0] // Benchmark identities, including Fake-IP.
        && !(segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0010) // ORCHID.
        && !(segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0020) // ORCHIDv2.
}

impl Ipv6Settings {
    /// Derive the selected logical interfaces' existing context without adopting
    /// DHCP or RA. Sorting stable preferred sources keeps address-list order and
    /// decreasing lifetimes out of the native reload fingerprint.
    pub(crate) async fn discover(
        lan_device: &str,
        wan_device: String,
        gateway: Option<Ipv6Addr>,
    ) -> Result<Self, ServiceError> {
        Self::select(&interfaces().await?, lan_device, wan_device, gateway)
    }

    fn select(
        interfaces: &[Interface],
        lan_device: &str,
        wan_device: String,
        gateway: Option<Ipv6Addr>,
    ) -> Result<Self, ServiceError> {
        let lan = find(interfaces, lan_device)?;
        let wan = find(interfaces, &wan_device)?;
        let mut sources: Vec<_> = wan
            .addr_info
            .iter()
            .filter(|address| address.usable() && !address.temporary)
            .filter_map(|address| match address.local {
                std::net::IpAddr::V6(ip) if native_internet(ip) => Some(ip),
                _ => None,
            })
            .collect();
        sources.sort();
        let source = sources.first().copied().ok_or(ServiceError::Ipv6Path)?;
        let mut lan_networks = Vec::new();
        for address in lan.addr_info.iter().filter(|address| address.usable()) {
            if let std::net::IpAddr::V6(ip) = address.local
                && (native_internet(ip) || ip.is_unique_local())
            {
                lan_networks.push(
                    Ipv6Net::new(ip, address.prefixlen)
                        .map_err(|_| ServiceError::Ipv6Path)?
                        .trunc(),
                );
            }
        }
        lan_networks.sort();
        lan_networks.dedup();
        Ok(Self {
            lan_networks,
            wan: Ipv6Wan {
                device: wan_device,
                source,
                gateway,
            },
        })
    }

    pub(crate) fn validate(&self, lan_device: &str, range: FakeIpRange) -> Result<(), ConfigError> {
        let synthetic = range.ipv6_range();
        self.wan.validate()?;
        if self.wan.device == lan_device
            || self.lan_networks.is_empty()
            || self.lan_networks.len() > 16
        {
            return Err(ConfigError::Ipv6);
        }
        for (index, network) in self.lan_networks.iter().enumerate() {
            let address = network.network();
            if network.addr() != address
                || network.prefix_len() == 0
                || !(native_internet(address) || address.is_unique_local())
                || network.contains(&self.wan.source)
                || synthetic.contains(&address)
                || network.contains(&synthetic.network())
                || self.lan_networks[..index].iter().any(|other| {
                    network.contains(&other.network()) || other.contains(&network.network())
                })
            {
                return Err(ConfigError::Ipv6);
            }
        }
        Ok(())
    }

    pub(crate) fn allows_client(&self, address: Ipv6Addr) -> bool {
        !address.is_unspecified()
            && !address.is_multicast()
            && self
                .lan_networks
                .iter()
                .any(|network| network.contains(&address))
    }

    pub(crate) fn permits_target(&self, address: Ipv6Addr) -> bool {
        native_internet(address) && address != self.wan.source && !self.allows_client(address)
    }

    /// Inspect actual assignments without changing addresses, routes, DHCP or RA.
    /// A usable source must still be preferred; a deprecated old prefix cannot
    /// continue serving new or established exception sessions unnoticed.
    pub(crate) async fn inspect(&self, lan_device: &str) -> Result<(), ServiceError> {
        let interfaces = interfaces().await?;
        let wan = find(&interfaces, &self.wan.device)?;
        if !wan.addr_info.iter().any(|address| {
            address.usable() && address.local == std::net::IpAddr::V6(self.wan.source)
        }) {
            return Err(ServiceError::Ipv6Path);
        }
        let lan = find(&interfaces, lan_device)?;
        for allowed in &self.lan_networks {
            let present = lan.addr_info.iter().any(|address| {
                let std::net::IpAddr::V6(local) = address.local else {
                    return false;
                };
                address.usable()
                    && Ipv6Net::new(local, address.prefixlen).is_ok_and(|network| {
                        network.prefix_len() <= allowed.prefix_len()
                            && network.contains(&allowed.network())
                    })
            });
            if !present {
                return Err(ServiceError::Ipv6Path);
            }
        }
        Ok(())
    }
}

impl Ipv6Wan {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !crate::config::valid_device(&self.device) {
            return Err(ConfigError::Device);
        }
        if self.device == "lo"
            || !native_internet(self.source)
            || self.gateway.is_some_and(|gateway| {
                gateway == self.source
                    || !(native_internet(gateway) || gateway.is_unicast_link_local())
            })
        {
            return Err(ConfigError::Ipv6);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn r123_ipv6_wan_gateway_requires_one_preferred_unicast_default_and_preserves_on_link_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let select = |value| select_gateway(serde_json::from_value(value)?);
        assert_eq!(
            select(json!([
                {"dst":"2001:db8:2::/64"},
                {"dst":"default","gateway":"fe80::3","metric":500},
                {"dst":"default","gateway":"fe80::2","from":"2001:db8:1::/64"},
                {"dst":"default","gateway":"fe80::2","from":"2001:db8:2::/64"}
            ]))?,
            Some("fe80::2".parse()?)
        );
        assert_eq!(select(json!([{"dst":"default"}]))?, None);
        assert_eq!(
            select(
                json!([{"dst":"default","metric":10},{"dst":"default","gateway":"fe80::2","metric":20}])
            )?,
            None
        );
        assert_eq!(select(json!([{"dst":"default","gateway":"::"}]))?, None);
        for invalid in [
            json!([]),
            json!([{"dst":"2001:db8:2::/64","gateway":"fe80::2"}]),
            json!([{"dst":"default","gateway":"fe80::2"},{"dst":"default","gateway":"fe80::3"}]),
            json!([{"dst":"default"},{"dst":"default","gateway":"fe80::2"}]),
            json!([{"dst":"default","type":"blackhole"}]),
            json!([{"dst":"default","type":"unreachable"}]),
        ] {
            assert!(
                select(invalid).is_err(),
                "an unavailable or ambiguous WAN path was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn r115_native_selection_uses_existing_preferred_stable_sources_and_prefixes_without_lifetime_or_order_churn()
    -> Result<(), Box<dyn std::error::Error>> {
        let address = |local: &str, prefixlen, preferred, temporary| json!({"local":local,"prefixlen":prefixlen,"preferred_life_time":preferred,"valid_life_time":600,"temporary":temporary});
        let mut value = json!([
            {"ifname":"lan0","flags":["UP"],"addr_info":[address("2001:db8:1::1",64,600,false),address("fd00:1234::1",64,600,false),address("fe80::1",64,600,false)]},
            {"ifname":"wan0","flags":["UP"],"addr_info":[address("2001:db8:2::3",64,600,false),address("2001:db8:2::1",64,600,true),address("2001:db8:2::2",64,600,false),address("2001:db8:2::4",64,0,false)]}
        ]);
        let selected = Ipv6Settings::select(
            &serde_json::from_value::<Vec<Interface>>(value.clone())?,
            "lan0",
            "wan0".into(),
            Some("fe80::2".parse()?),
        )?;
        assert_eq!(selected.wan.source, "2001:db8:2::2".parse::<Ipv6Addr>()?);
        assert_eq!(
            selected
                .lan_networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["2001:db8:1::/64", "fd00:1234::/64"]
        );
        value[1]["addr_info"]
            .as_array_mut()
            .ok_or("missing addresses")?
            .reverse();
        for entry in value.as_array_mut().ok_or("missing interfaces")? {
            for address in entry["addr_info"]
                .as_array_mut()
                .ok_or("missing addresses")?
            {
                if address["preferred_life_time"] != 0 {
                    address["preferred_life_time"] = json!(300);
                }
                address["valid_life_time"] = json!(500);
            }
        }
        let reordered = Ipv6Settings::select(
            &serde_json::from_value::<Vec<Interface>>(value.clone())?,
            "lan0",
            "wan0".into(),
            Some("fe80::2".parse()?),
        )?;
        assert!(
            selected == reordered,
            "lifetime countdown or address order changed the selected context"
        );
        for address in value[1]["addr_info"]
            .as_array_mut()
            .ok_or("missing addresses")?
        {
            address["preferred_life_time"] = json!(0);
        }
        assert!(
            Ipv6Settings::select(
                &serde_json::from_value::<Vec<Interface>>(value.clone())?,
                "lan0",
                "wan0".into(),
                None
            )
            .is_err(),
            "deprecated or temporary sources were silently selected"
        );
        value[0]["flags"] = json!([]);
        assert!(
            Ipv6Settings::select(
                &serde_json::from_value::<Vec<Interface>>(value)?,
                "lan0",
                "wan0".into(),
                None
            )
            .is_err()
        );
        Ok(())
    }
}
