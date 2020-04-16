//! APIs for communicating with peers.
//! - Use PeerLink::spawn() to establish a fully authenticated connection over a given socket stream.
//! - Use PeerID to identify the peer.
use core::fmt;
use futures::stream::StreamExt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::io;
use tokio::prelude::*;
use tokio::sync;
use tokio::task;

use curve25519_dalek::ristretto::CompressedRistretto;
use rand_core::{CryptoRng, RngCore};

use crate::cybershake;
use tokio_util::codec::{Encoder, Decoder, FramedRead, FramedWrite};
use futures::SinkExt;

/// Identifier of the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerID(pub cybershake::PublicKey);

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub struct PeerAddr {
    pub id: PeerID,
    pub addr: SocketAddr,
}

/// Various kinds of messages that peers can send and receive between each other.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PeerMessage {
    // Upon connection, a peer tells its listening port for dialing in, if it's available.
    Hello(u16),
    // A list of known peers.
    Peers(Vec<PeerAddr>),
    // An underlying message.
    // TODO: change this to a Bytes buffer or generic type, to avoid unnecessary copying.
    Data(Vec<u8>),
}

/// Interface for communication with the peer.
pub struct PeerLink {
    peer_id: PeerID,
    channel: sync::mpsc::Sender<PeerMessage>,
}

/// Notifications that we receive from the peer.
#[derive(Clone, Debug)]
pub enum PeerNotification {
    /// Received a message from a peer
    Received(PeerID, PeerMessage),
    /// Peer got disconnected. This message is not sent if the peer was stopped by the host.
    Disconnected(PeerID),
}

impl PeerLink {
    /// Returns the ID of the peer.
    pub fn id(&self) -> &PeerID {
        &self.peer_id
    }

    /// Sends a message to the peer.
    pub async fn send(&mut self, msg: PeerMessage) -> () {
        // We intentionally ignore the error because it's only returned if the recipient has disconnected,
        // but even Ok is of no guarantee that the message will be delivered, so we simply ignore the error entirely.
        // Specifically, in this implementation, Node's task does not stop until all senders disappear,
        // so we will never have an error condition here.
        self.channel.send(msg).await.unwrap_or(())
    }

    /// Spawns a peer task that will send notifications to a provided channel.
    /// Returns a PeerLink through which commands can be sent.
    ///
    pub async fn spawn<S, N, RNG, E, D>(
        host_identity: &cybershake::PrivateKey,
        expected_peer_id: Option<PeerID>,
        mut notifications_channel: sync::mpsc::Sender<N>,
        socket: S,
        rng: &mut RNG,
        encoder: E,
        decoder: D,
    ) -> Result<Self, io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
        N: From<PeerNotification> + 'static,
        RNG: RngCore + CryptoRng,
        E: Encoder<PeerMessage, Error = io::Error> + Unpin + 'static,
        D: Decoder<Item = PeerMessage, Error = io::Error> + Unpin + 'static,
    {
        let (r, w) = io::split(socket);
        let r = Box::pin(io::BufReader::new(r));
        let w = Box::pin(io::BufWriter::new(w));

        let (id_pubkey, outgoing, incoming) =
            cybershake::cybershake(host_identity, r, w, rng).await?;

        let mut outgoing = FramedWrite::new(outgoing, encoder);
        let incoming = FramedRead::new(incoming, decoder);

        let id = PeerID(id_pubkey);
        let retid = id.clone();

        if let Some(expected_pid) = expected_peer_id {
            if id != expected_pid {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Remote and expected id do not match.",
                ));
            }
        }

        let (cmd_sender, cmd_receiver) = sync::mpsc::channel::<PeerMessage>(100);

        enum PeerEvent {
            Send(PeerMessage),
            Receive(Result<PeerMessage, io::Error>),
            Stopped,
        }

        // This configures a merged stream of commands from the host and messages from the peer.
        let mut stream = futures::stream::select(
            cmd_receiver
                .map(PeerEvent::Send)
                // when the owner drops the PeerLink, we'll get the Stopped event.
                .chain(futures::stream::once(async { PeerEvent::Stopped })),
            incoming.map(PeerEvent::Receive),
        )
        .boxed_local();

        task::spawn_local(async move {
            while let Some(event) = stream.next().await {
                // First, handle successful events (think of this as Result::async_map)
                let result: Result<(), Option<_>> = (async {
                    match event {
                        PeerEvent::Send(msg) => {
                            outgoing.send(msg).await.map_err(Some)
                        }
                        PeerEvent::Receive(msg) => {
                            let msg = msg.map_err(Some)?;

                            notifications_channel
                                .send(PeerNotification::Received(id.clone(), msg).into())
                                .await
                                .map_err(|_| None) // stop the actor if the recipient no longer interested in notifications.
                        }
                        PeerEvent::Stopped => Err(None),
                    }
                })
                .await;

                // Second, handle the errors that occured before or after event processing.
                if let Err(_maybe_err) = result {
                    let _ = notifications_channel
                        .send(PeerNotification::Disconnected(id.clone()).into())
                        .await; // ignore failure since we are on the way out anyway
                    break;
                }
            }
        });

        Ok(Self {
            peer_id: retid,
            channel: cmd_sender,
        })
    }
}

impl PeerID {
    /// Returns a string representation of the PeerID
    pub fn to_string(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Decodes peer ID from string.
    pub fn from_string(id: &str) -> Option<Self> {
        hex::decode(id)
            .map(|b| {
                if b.len() == 32 {
                    Some(CompressedRistretto::from_slice(&b))
                } else {
                    None
                }
                .map(|r| Self(cybershake::PublicKey::from(r)))
            })
            .unwrap_or(None)
    }
}

impl From<cybershake::PublicKey> for PeerID {
    fn from(pk: cybershake::PublicKey) -> Self {
        PeerID(pk)
    }
}

impl fmt::Display for PeerID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl Hash for PeerID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}
