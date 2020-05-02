//! P2P networking stack.

use futures::future::FutureExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io;
use tokio::task;

use curve25519_dalek::scalar::Scalar;
use p2p::cybershake;
use p2p::{Node, NodeConfig, NodeHandle, NodeNotification, PeerID, PeerInfo};
use rand::thread_rng;

/// Handle to interact with the p2p networking stack.
pub struct P2PHandle {
    node_handle: Option<NodeHandle<Message>>,
    tokio_handle: tokio::runtime::Handle,
}

// Sync API for the P2P state.
impl P2PHandle {
    pub fn peer_id(&self) -> PeerID {
        self.node_handle.as_ref().unwrap().id()
    }

    /// Returns the listening socket address of the node.
    pub fn listen_address(&self) -> SocketAddr {
        self.node_handle.as_ref().unwrap().socket_address()
    }

    pub fn peers(&mut self) -> Vec<PeerInfo> {
        // FIXME: rewrite this into something like handle.block_on(future...)
        let (sender, receiver) = std::sync::mpsc::sync_channel(0);
        let mut node_handle = self
            .node_handle
            .take()
            .expect("node handle should have been returned on the previous call");
        self.tokio_handle.spawn(async move {
            let value = node_handle.list_peers().await;
            sender.send((node_handle, value)).unwrap();
        });
        let (nh, value) = receiver.recv().unwrap();
        self.node_handle = Some(nh);
        value
    }

    pub fn connect(&mut self, addr: String) -> Result<(), String> {
        // FIXME: rewrite this into something like handle.block_on(future...)
        let (sender, receiver) = std::sync::mpsc::sync_channel(0);
        let mut node_handle = self
            .node_handle
            .take()
            .expect("node handle should have been returned on the previous call");
        self.tokio_handle.spawn(async move {
            let value = node_handle.connect_to_peer(addr, None).await;
            sender.send((node_handle, value)).unwrap();
        });
        let (nh, value) = receiver.recv().unwrap();
        self.node_handle = Some(nh);
        value.map_err(|e| format!("Failed to connect. {:?}", e))
    }
}

/// Launches the
pub fn launch_p2p() -> P2PHandle {
    let (sender, receiver) = std::sync::mpsc::sync_channel(0);

    std::thread::spawn(move || {
        // FIXME: provide user-specified privkey here.
        let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

        let config = NodeConfig {
            listen_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            listen_port: 0,
            inbound_limit: 100,
            outbound_limit: 100,
            heartbeat_interval_sec: 3600,
        };

        let mut rt =
            tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
        let local = task::LocalSet::new();
        local.block_on(&mut rt, async move {
            let (node, mut notifications_channel) = Node::spawn(host_privkey, config)
                .await
                .expect("Should bind normally.");

            println!(
                "p2p: Listening on {} with peer ID: {}",
                node.socket_address(),
                node.id()
            );

            let handle = P2PHandle {
                node_handle: Some(node),
                tokio_handle: tokio::runtime::Handle::current(),
            };

            sender.send(handle).unwrap();

            // block the thread until we stop receiving notifications.
            while let Some(notif) = notifications_channel.recv().await {
                match notif {
                    NodeNotification::PeerAdded(pid) => println!("p2p:    Peer connected: {}", pid),
                    NodeNotification::PeerDisconnected(pid) => {
                        println!("p2p: Peer disconnected: {}", pid)
                    }
                    NodeNotification::MessageReceived(pid, msg) => {
                        println!("p2p: Received: `{:?}` from {}", msg, pid)
                    }
                    NodeNotification::InboundConnectionFailure(err) => {
                        println!("p2p: Inbound connection failure: {:?}", err)
                    }
                    NodeNotification::OutboundConnectionFailure(err) => {
                        println!("p2p: Outbound connection failure: {:?}", err)
                    }
                    NodeNotification::Shutdown => {
                        println!("p2p: Node did shutdown.");
                        break;
                    }
                }
            }
        })
    });
    receiver.recv().unwrap()
}

use readerwriter::{Decodable, Encodable, Reader, Writer};
use std::convert::Infallible;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq)]
pub struct Message(pub Vec<u8>);

impl Deref for Message {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encodable for Message {
    type Error = Infallible;

    fn encode(&self, dst: &mut impl Writer) -> Result<(), Self::Error> {
        Ok(dst.write(b"data", self.as_slice()).unwrap())
    }

    fn encoded_length(&self) -> usize {
        self.len()
    }
}

impl Decodable for Message {
    type Error = Infallible;

    fn decode(buf: &mut impl Reader) -> Result<Self, Self::Error> {
        Ok(Self(buf.read_vec(buf.remaining_bytes()).unwrap()))
    }
}
