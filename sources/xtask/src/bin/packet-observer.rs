//! Bounded passive capture for separately authorized hardware diagnostics.
#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    xtask::packet::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
