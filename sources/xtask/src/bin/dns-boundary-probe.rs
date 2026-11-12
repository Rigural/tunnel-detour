//! Reproduce record-count memory amplification in a separately limited process.

use hickory_proto::op::Message;
use rustix::process::{Resource, Rlimit, setrlimit};
use std::{error::Error, fs, process::ExitCode};

fn run() -> Result<(), Box<dyn Error>> {
    if std::env::var("TUNNEL_DETOUR_DNS_PARSER_LAB").as_deref() != Ok("1") {
        return Err("use the isolated DNS parser requirement test".into());
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let virtual_kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.split_whitespace().next())
        .ok_or("missing process address-space accounting")?
        .parse()?;
    // The malformed input has no records at all. An 8-MiB allowance above the
    // measured live image is generous, but rejects the vulnerable roughly 18-MB reserve.
    let budget = virtual_kib
        .checked_mul(1024)
        .and_then(|bytes| bytes.checked_add(8 * 1024 * 1024))
        .ok_or("DNS parser memory budget overflow")?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(budget),
            maximum: Some(budget),
        },
    )?;
    for offset in [6, 8, 10] {
        let mut packet = [0_u8; 12];
        packet[2] = 0x80; // A response with no encoded records and one forged count.
        packet[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        if Message::from_vec(&packet).is_ok() {
            return Err("a forged DNS count without encoded records was accepted".into());
        }
    }
    println!("forged DNS counts rejected within an 8-MiB incremental address-space budget");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
