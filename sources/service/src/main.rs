use std::{env, error::Error, fs::File, io::Read, path::Path, process::ExitCode};

use tokio_util::sync::CancellationToken;
use tunnel_detour_service::{
    BoundService, ServiceConfig, cleanup_uci, load_uci, rpc_call, rpc_methods, validate_patterns,
};

fn load(path: &Path) -> Result<ServiceConfig, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
    Ok(ServiceConfig::from_json(&bytes)?)
}

async fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let config = match arguments.as_slice() {
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
        [option] if option == "--uci" => match load_uci(false).await? { Some(config) => config, None => { cleanup_uci(false).await?; return Ok(()); } },
        [option] if option == "--check-uci" => {
            load_uci(true).await?.ok_or("UCI configuration is disabled")?;
            println!("{{\"valid\":true}}"); return Ok(());
        },
        [option, patterns @ ..] if option == "--validate-patterns" => {
            let lines = patterns.iter().map(|value| value.to_str().ok_or("patterns must be UTF-8")).collect::<Result<Vec<_>, _>>()?.join("\n");
            let result = validate_patterns(&lines);
            println!("{result}");
            if result["valid"] != true { return Err("invalid patterns".into()); }
            return Ok(());
        },
        _ => return Err("usage: tunnel-detour --uci | --config <file> | --check-uci | --validate-patterns <patterns...> | --cleanup-disabled | --uninstall | list | call <method>".into()),
    };
    let service = BoundService::bind(config).await?;
    let cancel = CancellationToken::new();
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let running = service.run(cancel.clone());
    tokio::pin!(running);
    tokio::select! {
        result = &mut running => result?,
        _ = termination.recv() => { cancel.cancel(); running.await?; },
        result = tokio::signal::ctrl_c() => { result?; cancel.cancel(); running.await?; },
    }
    Ok(())
}

fn main() -> ExitCode {
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
