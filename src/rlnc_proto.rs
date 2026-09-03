//! Request-response push codec for RLNC packets (`/ec-sim/rlnc/1.0.0`).

use std::io;

use futures::prelude::*;
use libp2p::request_response::{self, Codec, ProtocolSupport};
use libp2p::StreamProtocol;

use crate::rlnc::WirePacket;

pub const RLNC_PROTOCOL: &str = "/ec-sim/rlnc/1.0.0";

/// Tiny ack carried in the response.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct RlncAck;

#[derive(Debug, Clone, Default)]
pub struct RlncCodec;

impl Codec for RlncCodec {
    type Protocol = StreamProtocol;
    type Request = WirePacket;
    type Response = RlncAck;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<WirePacket>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();
        io.take(16 * 1024 * 1024).read_to_end(&mut vec).await?;
        WirePacket::decode(&vec).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<RlncAck>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();
        io.take(1024).read_to_end(&mut vec).await?;
        bincode::deserialize(&vec).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req.encode()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await
    }
}

pub type RlncBehaviour = request_response::Behaviour<RlncCodec>;

pub fn rlnc_behaviour() -> RlncBehaviour {
    request_response::Behaviour::with_codec(
        RlncCodec,
        [(
            StreamProtocol::new(RLNC_PROTOCOL),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}
