//! Fixed-arrival DNS traffic; generator resources remain outside the measured node.

use super::{Result, actor_resources};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use xtask::latency;

async fn query(remote: SocketAddr, id: u16, scheduled: Instant) -> Result<(Duration, Duration)> {
    let mut question = Message::new(id, MessageType::Query, OpCode::Query);
    question.metadata.recursion_desired = true;
    question.add_query(Query::query(
        Name::from_ascii("selected.example.net.")?,
        RecordType::A,
    ));
    let packet = question.to_vec()?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(remote).await?;
    let sent = Instant::now();
    socket.send(&packet).await?;
    let mut bytes = [0; 4096];
    let length = socket.recv(&mut bytes).await?;
    let received = Instant::now();
    let answer = Message::from_vec(&bytes[..length])?;
    if answer.metadata.id != id
        || answer.metadata.message_type != MessageType::Response
        || answer.metadata.response_code != ResponseCode::NoError
        || answer.metadata.truncation
        || answer.metadata.authentic_data
        || answer.queries != question.queries
        || answer.answers.len() != 1
        || !matches!(&answer.answers[0].data, RData::A(value) if value.0 == Ipv4Addr::new(198,18,0,1))
    {
        return Err("DNS load received an invalid synthetic identity response".into());
    }
    Ok((
        received.duration_since(sent),
        received.duration_since(scheduled),
    ))
}

struct Samples {
    replies: u64,
    errors: u64,
    rtt: Vec<u64>,
    scheduled: Vec<u64>,
}

impl Samples {
    fn record(
        &mut self,
        result: std::result::Result<Result<(Duration, Duration)>, tokio::task::JoinError>,
    ) -> Result {
        match result? {
            Ok((rtt, scheduled)) => {
                self.replies = self.replies.checked_add(1).ok_or("DNS count overflow")?;
                let rtt = latency::bucket(rtt.as_micros())?;
                let scheduled = latency::bucket(scheduled.as_micros())?;
                self.rtt[rtt] = self.rtt[rtt]
                    .checked_add(1)
                    .ok_or("DNS histogram overflow")?;
                self.scheduled[scheduled] = self.scheduled[scheduled]
                    .checked_add(1)
                    .ok_or("DNS histogram overflow")?;
            }
            Err(_) => {
                self.errors = self
                    .errors
                    .checked_add(1)
                    .ok_or("DNS error count overflow")?
            }
        }
        Ok(())
    }
}

pub(super) async fn client(remote: SocketAddr, seconds: u64) -> Result {
    if remote != "192.0.2.1:53".parse::<SocketAddr>()? || !(1..=50).contains(&seconds) {
        return Err("DNS load requires the synthetic LAN endpoint and 1–50 seconds".into());
    }
    let started = Instant::now();
    let requests = seconds
        .checked_mul(200)
        .ok_or("DNS offered load overflow")?;
    let mut jobs = JoinSet::new();
    let mut samples = Samples {
        replies: 0,
        errors: 0,
        rtt: vec![0; latency::BUCKETS],
        scheduled: vec![0; latency::BUCKETS],
    };
    let mut rejected = 0_u64;
    println!("{}", serde_json::json!({"ready":true,"role":"dns-load"}));
    let epoch = Instant::now();
    let operation = async {
        for index in 0..requests {
            let scheduled =
                epoch + Duration::from_millis(index.checked_mul(5).ok_or("DNS schedule overflow")?);
            sleep_until(scheduled).await;
            while let Some(completed) = jobs.try_join_next() {
                samples.record(completed)?;
            }
            if jobs.len() >= 64 {
                rejected = rejected
                    .checked_add(1)
                    .ok_or("DNS rejection count overflow")?;
                continue;
            }
            let id = u16::try_from(index)?;
            jobs.spawn(async move {
                timeout(Duration::from_secs(2), query(remote, id, scheduled)).await?
            });
        }
        while let Some(completed) = jobs.join_next().await {
            samples.record(completed)?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    jobs.abort_all();
    while let Some(completed) = jobs.join_next().await {
        match completed {
            Err(error) if error.is_cancelled() => {}
            other => samples.record(other)?,
        }
    }
    operation?;
    if samples.replies + samples.errors + rejected != requests {
        return Err("DNS request accounting mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"role":"dns-load","offered_requests":requests,"offered_qps":200,"scheduled_seconds":seconds,
        "successful_replies":samples.replies,"request_errors":samples.errors,"generator_capacity_rejections":rejected,"max_in_flight":64,
        "histogram_schema":latency::schema(),"rtt_histogram_microseconds":samples.rtt,"scheduled_histogram_microseconds":samples.scheduled,
        "latency_scope":"successful UDP replies; RTT from send to receipt, scheduled latency also includes generator scheduling/bind time; errors and local-capacity refusals reported separately",
        "actor_resources":actor_resources(started)?})
    );
    Ok(())
}
