use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::{DnsWireDecision, ExceptionPolicy, answer_dns};

use crate::{ServiceConfig, ServiceError, StatusHandle, runtime::now, upstream::RealResolver};

#[derive(Clone)]
pub(crate) struct DnsHandler {
    pub config: Arc<ServiceConfig>,
    pub policy: Arc<Mutex<ExceptionPolicy>>,
    pub resolver: RealResolver,
    pub status: StatusHandle,
}

impl DnsHandler {
    async fn process(&self, request: Vec<u8>) -> Result<Vec<u8>, ServiceError> {
        self.status.dns_query()?;
        let decision = tokio::task::block_in_place(|| {
            self.resolver.snapshot()?;
            let mut policy = self.policy.lock().map_err(|_| ServiceError::Poisoned)?;
            answer_dns(&mut policy, &request, now()?).map_err(ServiceError::from)
        });
        match decision {
            Ok(DnsWireDecision::Reply(response)) => Ok(response),
            Ok(DnsWireDecision::Forward(query)) => self.resolver.exchange(&query).await,
            Ok(DnsWireDecision::ServiceBinding(query)) => {
                let upstream = self.resolver.exchange(query.packet()).await?;
                tokio::task::block_in_place(|| {
                    let mut policy = self.policy.lock().map_err(|_| ServiceError::Poisoned)?;
                    query
                        .answer(&mut policy, &upstream, now()?)
                        .map_err(ServiceError::from)
                })
            }
            Err(error) if !error.is_critical() => {
                self.status.failure(&error)?;
                let query = Message::from_vec(&request).map_err(|_| ServiceError::Protocol)?;
                if query.metadata.message_type != MessageType::Query {
                    return Err(error);
                }
                let mut response = Message::response(query.metadata.id, query.metadata.op_code);
                response.metadata.response_code = ResponseCode::ServFail;
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.add_queries(query.queries.into_iter().take(1));
                Ok(response.to_vec().map_err(|_| ServiceError::Protocol)?)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn udp(
        &self,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        packet: Vec<u8>,
    ) -> Result<(), ServiceError> {
        let udp_limit = match Message::from_vec(&packet) {
            Ok(query) => query
                .edns
                .as_ref()
                .map_or(512, |edns| edns.max_payload().clamp(512, 1232)),
            Err(_) => return Err(ServiceError::Protocol),
        };
        let mut reply = timeout(self.config.dns_timeout(), self.process(packet))
            .await
            .map_err(|_| ServiceError::Timeout)??;
        if reply.len() > usize::from(udp_limit) {
            reply = Message::from_vec(&reply)
                .map_err(|_| ServiceError::Protocol)?
                .truncate()
                .to_vec()
                .map_err(|_| ServiceError::Protocol)?;
        }
        socket.send_to(&reply, peer).await?;
        Ok(())
    }

    pub async fn tcp(
        &self,
        mut stream: TcpStream,
        cancel: CancellationToken,
    ) -> Result<(), ServiceError> {
        // Bound pipelined connection lifetime and request count as well as individual messages.
        let lifetime = async {
            for _ in 0..16 {
                let length = match stream.read_u16().await {
                    Ok(length) => length,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                };
                if length < 12 {
                    return Err(ServiceError::Protocol);
                }
                let mut packet = vec![0; usize::from(length)];
                stream.read_exact(&mut packet).await?;
                let reply = timeout(self.config.dns_timeout(), self.process(packet))
                    .await
                    .map_err(|_| ServiceError::Timeout)??;
                stream
                    .write_u16(u16::try_from(reply.len()).map_err(|_| ServiceError::Protocol)?)
                    .await?;
                stream.write_all(&reply).await?;
            }
            Ok(())
        };
        tokio::select! {
            result = timeout(self.config.dns_timeout().saturating_mul(2), lifetime) => result.map_err(|_| ServiceError::Timeout)?,
            () = cancel.cancelled() => Ok(()),
        }
    }
}
