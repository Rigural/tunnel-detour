use std::{env, error::Error, fs::File, io::Read, path::Path, process::ExitCode};

use tokio_util::sync::CancellationToken;
use tunnel_detour_service::{
    BoundInbound, BoundService, InboundConfig, ServiceConfig, cleanup_inbound_uci, cleanup_uci,
    dns_revision, load_inbound_uci, load_uci, rpc_call, rpc_methods, validate_patterns,
};

fn load(path: &Path) -> Result<ServiceConfig, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
    Ok(ServiceConfig::from_json(&bytes)?)
}

fn load_inbound(path: &Path) -> Result<InboundConfig, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
    Ok(InboundConfig::from_json(&bytes)?)
}

async fn inbound_candidate(path: Option<&Path>) -> Result<InboundConfig, Box<dyn Error>> {
    match path {
        Some(path) => load_inbound(path),
        None => load_inbound_uci(false)
            .await?
            .ok_or_else(|| "inbound publications are disabled".into()),
    }
}

async fn run_inbound(path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut service = BoundInbound::bind(inbound_candidate(path).await?).await?;
    let mut audit = tokio::time::interval(std::time::Duration::from_secs(5));
    audit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    audit.tick().await;
    let mut status = tokio::time::interval(std::time::Duration::from_secs(1));
    status.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    status.tick().await;
    tracing::info!("inbound publications ready");
    loop {
        tokio::select! {
            _ = termination.recv() => break,
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    let error = tunnel_detour_service::ServiceError::Io(error);
                    service.fence(&error).await?;
                    return Err(error.into());
                }
                break;
            },
            result = service.relay_step() => {
                if let Err(error) = result {
                    service.fence(&error).await?;
                    return Err(error.into());
                }
            },
            _ = status.tick() => {
                if let Err(error) = service.refresh_status() {
                    service.fence(&error).await?;
                    return Err(error.into());
                }
            },
            _ = audit.tick() => {
                if let Err(error) = service.audit().await {
                    service.fence(&error).await?;
                    return Err(error.into());
                }
            },
            _ = reload.recv() => match inbound_candidate(path).await {
                Ok(config) => {
                    if let Err(error) = service.reconfigure(config).await {
                        tracing::error!(code = error.code(), "inbound reconciliation failed");
                        if !service.is_healthy() {
                            service.fence(&error).await?;
                            return Err(error.into());
                        }
                        if let Err(report) = service.report_error(&error) {
                            service.fence(&report).await?;
                            return Err(report.into());
                        }
                    }
                },
                Err(_) => {
                    if let Err(error) = service.audit().await {
                        service.fence(&error).await?;
                        return Err(error.into());
                    }
                    if let Err(error) = service.report_status(Some("inbound_configuration_failed")) {
                        service.fence(&error).await?;
                        return Err(error.into());
                    }
                    tracing::error!("inbound configuration is invalid; keeping the previous policy");
                },
            },
        }
    }
    service.stop().await?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let config = match arguments.as_slice() {
        [option] if option == "--migrate-adguard-credentials" => { tunnel_detour_service::migrate_adguard_credentials().await?; return Ok(()); },
        [option] if option == "list" => { println!("{}", rpc_methods()); return Ok(()); },
        [option, method] if option == "call" => {
            let method = method.to_str().ok_or("method must be UTF-8")?;
            let mut input = Vec::new();
            std::io::stdin().take(1_048_577).read_to_end(&mut input)?;
            println!("{}", rpc_call(method, &input).await?);
            return Ok(());
        },
        [option] if option == "--uninstall" => { cleanup_uci(true).await?; return Ok(()); },
        [option] if option == "--cleanup-disabled" => {
            if load_uci(false).await?.is_some() { return Err("cleanup requires a disabled configuration".into()); }
            cleanup_uci(false).await?; return Ok(());
        },
        [option, path] if option == "--config" => load(Path::new(path))?,
        [option, path] if option == "--inbound-config" => { run_inbound(Some(Path::new(path))).await?; return Ok(()); },
        [option] if option == "--inbound-uci" => { run_inbound(None).await?; return Ok(()); },
        [option] if option == "--cleanup-inbound" => { cleanup_inbound_uci().await?; return Ok(()); },
        [option] if option == "--dns-revision" => { println!("{}", dns_revision().await?); return Ok(()); },
        [option] if option == "--check-inbound-uci" => {
            tunnel_detour_service::check_inbound_config(&load_inbound_uci(true).await?.ok_or("inbound configuration is missing")?).await?;
            println!("{{\"valid\":true}}"); return Ok(());
        },
        [option] if option == "--uci" => match load_uci(false).await? { Some(config) => config, None => { cleanup_uci(false).await?; return Ok(()); } },
        [option] if option == "--check-uci" => {
            load_uci(true).await?.ok_or("UCI configuration is disabled")?;
            println!("{{\"valid\":true}}"); return Ok(());
        },
        [option, path] if option == "--check-inbound-config" => {
            let mut bytes = Vec::new();
            File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
            InboundConfig::from_json(&bytes)?.check_network_and_paths().await?;
            println!("{{\"valid\":true,\"checked\":\"network_and_paths\"}}");
            return Ok(());
        },
        [option, patterns @ ..] if option == "--validate-patterns" => {
            let lines = patterns.iter().map(|value| value.to_str().ok_or("patterns must be UTF-8")).collect::<Result<Vec<_>, _>>()?.join("\n");
            let result = validate_patterns(&lines);
            println!("{result}");
            if result["valid"] != true { return Err("invalid patterns".into()); }
            return Ok(());
        },
        _ => return Err("usage: tunnel-detour --uci | --config <file> | --check-uci | --inbound-uci | --inbound-config <file> | --check-inbound-uci | --check-inbound-config <file> | --cleanup-inbound | --dns-revision | --migrate-adguard-credentials | --validate-patterns <patterns...> | --cleanup-disabled | --uninstall | list | call <method>".into()),
    };
    let service = BoundService::bind(config).await?;
    let cancel = CancellationToken::new();
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let running = service.run_with_reload(cancel.clone(), reload);
    tokio::pin!(running);
    tokio::select! {
        result = &mut running => result?,
        _ = termination.recv() => { cancel.cancel(); running.await?; },
        result = tokio::signal::ctrl_c() => { result?; cancel.cancel(); running.await?; },
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Some(result) = tunnel_detour_service::transport_worker_entrypoint() {
        return result;
    }
    tracing_subscriber::fmt().with_target(false).init();
    let result = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(run()),
        Err(error) => Err(Box::new(error) as Box<dyn Error>),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
