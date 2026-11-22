use std::{env, error::Error, io::Read, path::Path, process::ExitCode};

use tokio_util::sync::CancellationToken;
use tracing_subscriber::{
    filter::{dynamic_filter_fn, filter_fn},
    prelude::*,
};
use tunnel_detour_service::{
    BoundInbound, BoundService, InboundConfig, ObservabilityLog, ServiceConfig, ServiceError,
    cleanup_inbound_uci, cleanup_uci, clear_uci_observations, dns_revision, load_inbound_uci,
    load_uci, queue_uci_revocation, rpc_call, rpc_methods, validate_patterns,
};

fn load_inbound(path: &Path) -> Result<InboundConfig, Box<dyn Error>> {
    Ok(tokio::task::block_in_place(|| {
        InboundConfig::load_file(path)
    })?)
}

async fn inbound_candidate(path: Option<&Path>) -> Result<InboundConfig, Box<dyn Error>> {
    match path {
        Some(path) => load_inbound(path),
        None => {
            let candidate = load_inbound_uci(false).await;
            if !candidate
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .is_some_and(InboundConfig::observability_enabled)
            {
                clear_uci_observations(true);
            }
            candidate?.ok_or_else(|| "inbound publications are disabled".into())
        }
    }
}

async fn run_inbound(
    path: Option<&Path>,
    logging: &ObservabilityLog,
) -> Result<(), Box<dyn Error>> {
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let config = inbound_candidate(path).await?;
    let mut service = BoundInbound::bind(config)
        .await?
        .with_observability_log(logging.clone());
    let mut audit = tokio::time::interval(std::time::Duration::from_secs(5));
    audit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    audit.tick().await;
    let mut status = tokio::time::interval(std::time::Duration::from_secs(1));
    status.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    status.tick().await;
    tracing::info!(target: "tunnel_detour::diagnostics", "inbound publications ready");
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
                if let Err(error) = service.refresh_diagnostics() {
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
            _ = reload.recv() => match match path {
                Some(path) => load_inbound(path),
                None => service.load_uci_candidate().await.map_err(Box::<dyn Error>::from)
                    .and_then(|candidate| candidate.ok_or_else(|| "inbound publications are disabled".into())),
            } {
                Ok(config) => {
                    if let Err(error) = service.reconfigure(config).await {
                        tracing::error!(
                            target: "tunnel_detour::health",
                            code = error.code(),
                            nat_stage = error.inbound_nat_stage(),
                            "inbound reconciliation failed"
                        );
                        if !service.is_healthy() {
                            service.fence(&error).await?;
                            return Err(error.into());
                        }
                        if let Err(report) = service
                            .disable_observability()
                            .and_then(|()| service.report_error(&error))
                        {
                            service.fence(&report).await?;
                            return Err(report.into());
                        }
                    }
                },
                Err(candidate_error) => {
                    if let Err(error) = service.disable_observability() {
                        service.fence(&error).await?;
                        return Err(error.into());
                    }
                    if let Err(error) = service.audit().await {
                        service.fence(&error).await?;
                        return Err(error.into());
                    }
                    let code = candidate_error.downcast_ref::<ServiceError>().map_or("inbound_configuration_failed", ServiceError::code);
                    if let Err(error) = service.report_status(Some(code)) {
                        service.fence(&error).await?;
                        return Err(error.into());
                    }
                    tracing::warn!(
                        target: "tunnel_detour::health",
                        code,
                        "inbound configuration is invalid; keeping the previous policy"
                    );
                },
            },
        }
    }
    service.stop().await?;
    Ok(())
}

async fn run(logging: &ObservabilityLog) -> Result<(), Box<dyn Error>> {
    let reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let mut config_path = None;
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
        [option, path] if option == "--config" => {
            let path = Path::new(path);
            let config = tokio::task::block_in_place(|| ServiceConfig::load_file(path))?;
            config_path = Some(path.to_owned());
            config
        },
        [option, path] if option == "--inbound-config" => { run_inbound(Some(Path::new(path)), logging).await?; return Ok(()); },
        [option] if option == "--inbound-uci" => { run_inbound(None, logging).await?; return Ok(()); },
        [option] if option == "--cleanup-inbound" => { cleanup_inbound_uci().await?; return Ok(()); },
        [option] if option == "--queue-dns-revocation" => { queue_uci_revocation(false).await?; return Ok(()); },
        [option] if option == "--queue-inbound-revocation" => { queue_uci_revocation(true).await?; return Ok(()); },
        [option] if option == "--dns-revision" => { println!("{}", dns_revision().await?); return Ok(()); },
        [option] if option == "--check-inbound-uci" => {
            tunnel_detour_service::check_inbound_config(&load_inbound_uci(true).await?.ok_or("inbound configuration is missing")?).await?;
            println!("{{\"valid\":true}}"); return Ok(());
        },
        [option] if option == "--uci" => {
            let candidate = load_uci(false).await;
            if !candidate.as_ref().ok().and_then(Option::as_ref).is_some_and(ServiceConfig::observability_enabled) {
                clear_uci_observations(false);
            }
            match candidate? { Some(config) => config, None => { cleanup_uci(false).await?; return Ok(()); } }
        },
        [option] if option == "--check-uci" => {
            load_uci(true).await?.ok_or("UCI configuration is disabled")?;
            println!("{{\"valid\":true}}"); return Ok(());
        },
        [option, path] if option == "--check-inbound-config" => {
            load_inbound(Path::new(path))?.check_network_and_paths().await?;
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
    let service = BoundService::bind(config)
        .await?
        .with_observability_log(logging.clone());
    let service = match config_path {
        Some(path) => service.with_config_path(path),
        None => service,
    };
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
    let daemon = env::args_os().nth(1).is_some_and(|argument| {
        matches!(
            argument.to_str(),
            Some("--uci" | "--config" | "--inbound-uci" | "--inbound-config")
        )
    });
    let logging = ObservabilityLog::default();
    let writer = logging.clone();
    let filter = logging.clone();
    // Admit only explicitly classified events. Diagnostic writes recheck consent
    // at the writer so revocation also covers events that are already formatted.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .with_filter(filter_fn(|event| {
                    event.target() == "tunnel_detour::health"
                        && *event.level() <= tracing::Level::WARN
                })),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(dynamic_filter_fn(move |event, _| {
                    event.target() == "tunnel_detour::diagnostics"
                        && *event.level() <= tracing::Level::INFO
                        && filter.enabled()
                })),
        )
        .init();
    let result = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(run(&logging)),
        Err(error) => Err(Box::new(error) as Box<dyn Error>),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if daemon {
                let service_error = error.downcast_ref::<ServiceError>();
                let code = service_error.map_or("startup_or_configuration", ServiceError::code);
                if let Some(stage) = service_error.and_then(ServiceError::inbound_nat_stage) {
                    eprintln!("Tunnel Detour daemon exited: {code} nat_stage={stage}");
                } else {
                    eprintln!("Tunnel Detour daemon exited: {code}");
                }
            } else if let Some(error) = error.downcast_ref::<ServiceError>() {
                eprintln!("{}", error.code());
            } else {
                eprintln!("{error}");
            }
            ExitCode::FAILURE
        }
    }
}
