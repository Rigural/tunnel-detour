//! Direct IPv4 capability reference using the same generator and origin, without a relay.

use super::*;

pub(super) async fn measure(
    api: &Api,
    worker: &Path,
    output: &Path,
    spec: Scenario<'_>,
    image: &ImageSnapshot,
    retain_generator_network: bool,
) -> Result<Vec<Value>> {
    let origin_worker = actor_copy(worker, "origin")?;
    let generator_worker = actor_copy(worker, "generator")?;
    let mut lab = Lab {
        containers: Vec::new(),
        networks: Vec::new(),
        failure_directory: Some(output.to_path_buf()),
        actor_image: Some(image.tag.clone()),
    };
    let lan = lab.network(
        &format!("td-relay-endpoints-{}", std::process::id()),
        "192.0.2.0/24",
        "192.0.2.254",
        false,
    )?;
    let origin_command = spec.origin_command();
    let refs: Vec<_> = origin_command.iter().map(String::as_str).collect();
    let origin = lab.create(&origin_worker, &lan, "192.0.2.2", "4", None, &refs)?;
    if spec.prepared {
        start_prepared(&lab, &origin)?;
    } else {
        docker(&strings(&["start", &origin]))?;
    }
    api.ready(&origin).await?;
    let generator_command = spec.generator_command("192.0.2.2:8080");
    let refs: Vec<_> = generator_command.iter().map(String::as_str).collect();
    let network_owner = if retain_generator_network {
        Some(lab.generator_network_owner(worker, &lan, "192.0.2.3")?)
    } else {
        None
    };
    let generator_network = network_owner
        .as_ref()
        .map_or_else(|| lan.clone(), |owner| format!("container:{owner}"));
    let generator = lab.create(
        &generator_worker,
        &generator_network,
        "192.0.2.3",
        "4",
        None,
        &refs,
    )?;
    if spec.prepared {
        start_prepared(&lab, &generator)?;
        api.ready(&generator).await?;
    }
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "kind":"direct endpoint capability; one IPv4 bridge; no translation or relay",
            "image":image.inspection[0]["Id"],"image_tag":image.tag,"image_layers":image.inspection[0]["RootFS"]["Layers"],"worker_sha256":digest(worker)?,"actor_cpus":4,"actor_runtime_threads":4,
            "memory_limit_bytes":268435456,"uid":65534,"capabilities":[],
            "workload":spec.workload,"connections":spec.connections,"message_bytes":spec.message_bytes,
            "window":spec.window.description(),
            "generator_network":if retain_generator_network {Some(RETAINED_GENERATOR_NETWORK)} else {None},
            "periodic_cgroup_sampling":spec.observation == Observation::Full,
            "origin_command":origin_command,"generator_command":generator_command,
            "kernel":docker(&strings(&["exec",&origin,"uname","-r"]))?
        }))?,
    )?;
    let network_before = match &network_owner {
        Some(owner) => Some(api.stats(owner).await?),
        None => None,
    };
    let origin_before = api.stats(&origin).await?;
    if spec.prepared {
        docker(&strings(&[
            "exec",
            &generator,
            "touch",
            "/tmp/application-start",
        ]))?;
    } else {
        docker(&strings(&["start", &generator]))?;
    }
    let started = tokio::time::Instant::now();
    let mut samples = Vec::new();
    let mut polls = 0_u32;
    tokio::time::timeout(Duration::from_secs(60),async {
        loop {
            let state=api.get(&format!("/containers/{generator}/json")).await?;
            if spec.observation == Observation::Full {
                samples.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"origin":api.stats(&origin).await?,"generator":api.stats(&generator).await?}));
            }
            if state["State"]["Running"]==false {
                if state["State"]["ExitCode"]!=0 {return Err(format!("direct endpoint failed: {}",docker(&strings(&["logs",&generator]))?).into());}
                break;
            }
            polls += 1;
            if polls>=600 {return Err("endpoint observation limit exceeded".into());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_,Box<dyn Error>>(())
    }).await??;
    let result = client_result(&generator)?;
    let origin_result = if spec.echo() {
        Value::Null
    } else {
        api.bulk_result(&origin).await?
    };
    let mut report = json!({"variant":"direct","case":spec.description(),"connections":spec.connections,"workload":spec.workload,
        "result":result,"origin_result":origin_result,"samples":samples,
        "origin_before":origin_before,"origin_after":api.stats(&origin).await?,
        "observation":spec.observation.label(),
        "observation_scope":"no relay or PSS observer; periodic cgroup samples only in full mode; client cumulative CPU is reported by the generator"});
    if let Some(owner) = &network_owner {
        let state = api.get(&format!("/containers/{owner}/json")).await?;
        if state["State"]["Running"] != true {
            return Err("endpoint owner exited before direct peer confirmation".into());
        }
        report["generator_network"] = json!(RETAINED_GENERATOR_NETWORK);
        report["generator_network_owner"] = json!({"before":network_before,"after":api.stats(owner).await?,"state":state["State"],"scope":"independent endpoint cgroup, excluded from generator CPU"});
    }
    std::fs::write(
        output.join("direct.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    let summary = summarize_report(&report)?;
    docker(&strings(&["kill", "--signal=TERM", &origin]))?;
    if docker(&strings(&["wait", &origin]))? != "0" {
        return Err("direct origin did not stop cleanly".into());
    }
    lab.remove(&generator)?;
    lab.remove(&origin)?;
    if let Some(owner) = network_owner {
        lab.remove(&owner)?;
    }
    lab.finish_networks()?;
    println!("Direct endpoint results: {}", output.display());
    lab.failure_directory = None;
    Ok(vec![summary])
}
