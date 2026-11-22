//! Docker management network identity shared by the runner and its native fixtures.

use std::{error::Error, process::Command};

pub const NETWORK_PREFIX: &str = "tunnel-detour-management-";
pub const TASK_LABEL: &str = "tunnel-detour.task=local-validation";
pub const SUBNET: &str = "10.203.0.0/24";

/// Refuse to start the suite if a previous native laboratory still owns its subnet.
/// Never remove an existing network or assume it belongs to this checkout.
pub fn check_management_network() -> Result<(), Box<dyn Error>> {
    let output = Command::new("docker")
        .args([
            "network",
            "ls",
            "--filter",
            &format!("label={TASK_LABEL}"),
            "--format",
            "{{.Name}}",
        ])
        .output()?;
    if !output.status.success() {
        return Err("native OpenWrt laboratory: Docker network inventory failed".into());
    }
    for name in std::str::from_utf8(&output.stdout)?.lines() {
        if !name.starts_with(NETWORK_PREFIX) {
            continue;
        }
        let detail = Command::new("docker")
            .args([
                "network",
                "inspect",
                "--format",
                "{{json .IPAM.Config}}",
                name,
            ])
            .output()?;
        if !detail.status.success() {
            return Err("native OpenWrt laboratory: Docker network inspection failed".into());
        }
        let ranges: Vec<serde_json::Value> = serde_json::from_slice(&detail.stdout)?;
        if ranges.iter().any(|range| range["Subnet"] == SUBNET) {
            return Err(format!(
                "native OpenWrt laboratory cannot start: Docker network {name} still owns \
                 {SUBNET}. Wait for its run to finish, or inspect and remove the network if \
                 it is empty and left by an interrupted run."
            )
            .into());
        }
    }
    Ok(())
}
