//! Node manages its own state and the state of its peers, and orchestrates messages between them.
use core::time::Duration;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::future::FutureExt;
use futures::select;
use futures::stream::StreamExt;

use tokio::net;
use tokio::prelude::*;
use tokio::sync;
use tokio::task;
use tokio::time;

use rand::thread_rng;

use crate::cybershake;
use crate::peer::{PeerAddr, PeerID, PeerLink, PeerMessage, PeerNotification};
use crate::priority::{Priority, PriorityTable, HIGH_PRIORITY, LOW_PRIORITY};

type Reply<T> = sync::oneshot::Sender<T>;

/// State of the node.
/// This is a handle that can be copied to send messages to the node from different tasks.
/// When the handle is dropped, the Node is shut down.
#[derive(Clone)]
pub struct NodeHandle {
    peer_id: PeerID,
    socket_address: SocketAddr,
    channel: sync::mpsc::Sender<NodeMessage>,
}

pub struct NodeConfig {
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub inbound_limit: usize,
    pub outbound_limit: usize,
    pub heartbeat_interval_sec: u64,
}

pub struct Node {
    listener: net::TcpListener,
    cybershake_identity: cybershake::PrivateKey,
    peer_notification_channel: sync::mpsc::Sender<PeerNotification>,
    peers: HashMap<PeerID, PeerState>,
    config: NodeConfig,
    inbound_semaphore: sync::Semaphore,
    peer_priorities: PriorityTable<PeerID>, // priorities of peers
    notifications_channel: sync::mpsc::Sender<NodeNotification>,
}

/// Direction of connection
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// State of the peer
struct PeerState {
    link: PeerLink,
    listening_addr: Option<SocketAddr>,
    socket_addr: SocketAddr,
    direction: Direction,
    duplicates: usize,
    peer_addrs: Vec<PeerAddr>, // addresses of all the peers
                               // TODO: add more state
}

#[derive(Debug)]
pub enum NodeNotification {
    PeerAdded(PeerID),
    PeerDisconnected(PeerID),
    MessageReceived(PeerID, Vec<u8>),
    InboundConnectionFailure(cybershake::Error),
    OutboundConnectionFailure(cybershake::Error),
    /// Node has finished running.
    Shutdown,
}

#[derive(Debug)]
pub struct PeerInfo {
    pub id: PeerID,
    pub address: SocketAddr,
    pub public: bool,
    pub priority: Priority,
    pub direction: Direction,
}

/// Internal representation of messages sent by `NodeHandle` to `Node`.
enum NodeMessage {
    ConnectPeer(net::TcpStream, Option<PeerID>),
    RemovePeer(PeerID),
    Broadcast(Vec<u8>),
    CountPeers(Reply<usize>),
    ListPeers(Reply<Vec<PeerInfo>>),
}

impl NodeConfig {
    fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_ip, self.listen_port)
    }
}

impl Node {
    /// Creates a node and returns a handle for communicating with it.
    /// TODO: add the listening loop and avoid doing .accept when we are out of inbound slots.
    pub async fn spawn(
        cybershake_identity: cybershake::PrivateKey,
        config: NodeConfig,
    ) -> Result<(NodeHandle, sync::mpsc::Receiver<NodeNotification>), io::Error> {
        // Prepare listening socket.
        let listener = net::TcpListener::bind(config.listen_addr()).await?;
        let mut local_addr = listener.local_addr()?;
        if local_addr.ip().is_unspecified() {
            local_addr.set_ip(Ipv4Addr::LOCALHOST.into());
        }

        let inbound_semaphore = sync::Semaphore::new(config.inbound_limit);

        let (cmd_sender, mut cmd_receiver) = sync::mpsc::channel::<NodeMessage>(100);
        let (peer_sender, mut peer_receiver) = sync::mpsc::channel::<PeerNotification>(100);
        let (notif_sender, notif_receiver) = sync::mpsc::channel::<NodeNotification>(100);

        let mut node = Node {
            cybershake_identity,
            peer_notification_channel: peer_sender,
            peers: HashMap::new(),
            listener,
            config,
            inbound_semaphore,
            peer_priorities: PriorityTable::new(1000),
            notifications_channel: notif_sender,
        };

        let node_handle = NodeHandle {
            peer_id: node.peer_id(),
            channel: cmd_sender,
            socket_address: local_addr,
        };

        task::spawn_local(async move {
            let mut heartbeat =
                time::interval(Duration::from_secs(node.config.heartbeat_interval_sec));
            loop {
                select! {
                    maybe_cmd = cmd_receiver.next().fuse() => {
                        if let Some(cmd) = maybe_cmd {
                            node.handle_command(cmd).await;
                        } else {
                            // node handle was dropped, shut down the node.
                            break;
                        }
                    },
                    maybe_peer_notif = peer_receiver.next().fuse() => {
                        if let Some(notif) = maybe_peer_notif {
                            node.handle_peer_notification(notif).await;
                        } else {
                            // Never happens until shutdown because Node holds one copy of the sender
                            // for spawning new peers from within.
                        }
                    },
                    _ = heartbeat.tick().fuse() => {
                        node.heartbeat_tick().await
                    },
                    _ = node.try_accept().fuse() => {}
                }
            }
            node.notify(NodeNotification::Shutdown).await
        });

        Ok((node_handle, notif_receiver))
    }
}

impl NodeHandle {
    /// Attempts to open a connection to a peer.
    /// Returns error if cannot establish the connection.
    /// If connection is established, returns Ok(), but can fail later to perform handshake -
    /// in which case you will receive a `NodeNotification::OutboundConnectionFailure` notification.
    ///
    /// TODO: maybe pass `Box<dyn ToSocketAddrs>` to the node, so all errors are handled in one place?
    pub async fn connect_to_peer(
        &mut self,
        addr: impl net::ToSocketAddrs,
        expected_pid: Option<PeerID>,
    ) -> Result<(), io::Error> {
        let stream = net::TcpStream::connect(&addr).await?;
        self.send_internal(NodeMessage::ConnectPeer(stream, expected_pid))
            .await;
        Ok(())
    }

    /// Disconnects from a peer with a given ID.
    pub async fn remove_peer(&mut self, peer_id: PeerID) {
        self.send_internal(NodeMessage::RemovePeer(peer_id)).await
    }

    /// Returns the PeerID of the node.
    pub fn id(&self) -> PeerID {
        self.peer_id
    }

    /// Returns the listening socket address of the node.
    pub fn socket_address(&self) -> SocketAddr {
        self.socket_address
    }

    /// Broadcasts a message to all peers.
    pub async fn broadcast(&mut self, msg: Vec<u8>) {
        self.send_internal(NodeMessage::Broadcast(msg)).await
    }

    pub async fn list_peers(&mut self) -> Vec<PeerInfo> {
        let (tx, rx) = sync::oneshot::channel::<Vec<PeerInfo>>();
        self.send_internal(NodeMessage::ListPeers(tx)).await;
        rx.await
            .expect("should never fail because Node must exist as long as all NodeHandles exist")
    }

    pub async fn count_peers(&mut self) -> usize {
        let (tx, rx) = sync::oneshot::channel::<usize>();
        self.send_internal(NodeMessage::CountPeers(tx)).await;
        rx.await
            .expect("should never fail because Node must exist as long as all NodeHandles exist")
    }

    /// Implements sending a message to a node over a channel
    async fn send_internal(&mut self, msg: NodeMessage) {
        // We intentionally ignore the error because it's only returned if the recipient has disconnected,
        // but even Ok is of no guarantee that the message will be delivered, so we simply ignore the error entirely.
        // Specifically, in this implementation, Node's task does not stop until all senders disappear,
        // so we will never have an error condition here.
        self.channel.send(msg).await.unwrap_or(())
    }
}

impl Node {
    /// Handles the command and returns false if it needs to shutdown.
    async fn handle_command(&mut self, msg: NodeMessage) {
        match msg {
            NodeMessage::ConnectPeer(stream, expected_pid) => {
                self.connect_peer_or_notify(stream, expected_pid, HIGH_PRIORITY)
                    .await
            }
            NodeMessage::RemovePeer(peer_id) => self.remove_peer(&peer_id).await,
            NodeMessage::Broadcast(msg) => self.broadcast(msg).await,
            NodeMessage::CountPeers(reply) => self.count_peers(reply).await,
            NodeMessage::ListPeers(reply) => self.list_peers(reply).await,
        }
    }

    /// Perform periodic update about yourself and your peers.
    async fn heartbeat_tick(&mut self) {
        // Broadcast a list of your peers to everyone.
        // TODO: make this more efficient to avoid copying the list of peers all the time,
        // but instead sending a shared read-only buffer.
        // We can do this by changing how the Peer works from being its own task, to a Stream,
        // and then polling `select_all` of them.
        let listed_peers = self.sorted_peers();
        for (_pid, peerstate) in self.peers.iter_mut() {
            peerstate
                .link
                .send(PeerMessage::Peers(listed_peers.clone()))
                .await
        }
    }

    async fn try_accept(&mut self) {
        let result = async {
            let permit = self.inbound_semaphore.acquire().await;

            let (stream, addr) = self.listener.accept().await?;

            let peer_link = PeerLink::spawn(
                &self.cybershake_identity,
                None,
                self.peer_notification_channel.clone(),
                stream,
                &mut thread_rng(),
            )
            .await?;

            // If the handshake did not fail, forget the semaphore permit,
            // so it's consumed until the peer disconnects. When we get about actually
            // removing the peer, then we'll add a new permit to the semaphore.
            permit.forget();

            self.register_peer(peer_link, addr, Direction::Inbound, LOW_PRIORITY)
                .await;

            Ok(())
        }
        .await;
        self.notify_on_error(result, |e| NodeNotification::InboundConnectionFailure(e))
            .await;
    }

    async fn connect_peer_or_notify(
        &mut self,
        stream: net::TcpStream,
        expected_pid: Option<PeerID>,
        min_priority: Priority,
    ) {
        let result = self.connect_peer(stream, expected_pid, min_priority).await;
        self.notify_on_error(result, |e| NodeNotification::OutboundConnectionFailure(e))
            .await;
    }

    async fn connect_peer(
        &mut self,
        stream: net::TcpStream,
        expected_pid: Option<PeerID>,
        min_priority: Priority,
    ) -> Result<(), cybershake::Error> {
        let addr = stream.peer_addr()?;

        let peer_link = PeerLink::spawn(
            &self.cybershake_identity,
            expected_pid,
            self.peer_notification_channel.clone(),
            stream,
            &mut thread_rng(),
        )
        .await?;

        self.register_peer(peer_link, addr, Direction::Outbound, min_priority)
            .await;

        Ok(())
    }

    async fn connect_to_peer_addr(
        &mut self,
        peer_addr: &PeerAddr,
    ) -> Result<(), cybershake::Error> {
        if peer_addr.addr.ip().is_unspecified() {
            return Err(cybershake::Error::ProtocolError);
        }
        // TODO: add short timeout to avoid hanging for too long waiting to be accepted.
        let stream = net::TcpStream::connect(&peer_addr.addr).await?;

        // We are connecting to some discovered address, so minimum priority is zero,
        // so we don't bump up whatever known priority is there.
        self.connect_peer(stream, Some(peer_addr.id), LOW_PRIORITY)
            .await
    }

    async fn register_peer(
        &mut self,
        peer_link: PeerLink,
        addr: SocketAddr,
        direction: Direction,
        min_priority: Priority,
    ) {
        let id = *peer_link.id();

        self.peer_priorities.insert(id, min_priority);

        if let Some(mut existing_peer) = self.peers.get_mut(&id) {
            // mark the existing peer as having duplicates,
            // so when the current peer is dropped, we don't remove it.
            existing_peer.duplicates += 1;

            // if the duplicate connection is outbound, upgrade the status of the existing one.
            if direction == Direction::Outbound && existing_peer.direction == Direction::Inbound {
                existing_peer.direction = Direction::Outbound;
                existing_peer.listening_addr = Some(addr);
                // restore the semaphore since we have just overriden the direction.
                self.inbound_semaphore.add_permits(1);
            }

            return;
        }

        let peer = PeerState {
            link: peer_link,
            listening_addr: match &direction {
                &Direction::Inbound => None,
                &Direction::Outbound => Some(addr),
            },
            socket_addr: addr,
            direction,
            duplicates: 0,
            peer_addrs: Vec::new(),
        };
        // The peer did not exist - simply add it.
        let _ = self.peers.insert(id, peer);

        self.notify(NodeNotification::PeerAdded(id)).await;

        // If this is an outbound connection, tell our port.
        if direction == Direction::Outbound {
            self.send_to_peer(
                &id,
                PeerMessage::Hello(self.listener.local_addr().unwrap().port()),
            )
            .await
        }

        // Then, tell about our surrounding peers.
        self.send_to_peer(&id, PeerMessage::Peers(self.sorted_peers()))
            .await
    }

    async fn remove_peer(&mut self, peer_id: &PeerID) {
        // First, check if this peer has duplicates - then silently decrement the count
        // and keep it in place.
        if let Some(mut peer) = self.peers.get_mut(&peer_id) {
            if peer.duplicates > 0 {
                peer.duplicates -= 1;
                return;
            }
        }
        if let Some(peer) = self.peers.remove(peer_id) {
            if peer.direction == Direction::Inbound {
                // if that was an inbound peer, restore the permit it consumed.
                self.inbound_semaphore.add_permits(1);
            }
            self.notify(NodeNotification::PeerDisconnected(*peer.link.id()))
                .await;
        }

        self.connect_to_more_peers_if_needed().await;
    }

    fn count_peers_with_direction(&self, direction: Direction) -> usize {
        self.peers
            .iter()
            .filter(|(_pid, peer)| peer.direction == direction)
            .count()
    }

    async fn broadcast(&mut self, msg: Vec<u8>) {
        for (_id, peer_link) in self.peers.iter_mut() {
            peer_link.link.send(PeerMessage::Data(msg.clone())).await;
        }
    }

    async fn count_peers(&mut self, reply: Reply<usize>) {
        reply.send(self.peers.len()).unwrap_or(())
    }

    async fn list_peers(&mut self, reply: Reply<Vec<PeerInfo>>) {
        reply.send(self.peer_infos()).unwrap_or(())
    }

    async fn send_to_peer(&mut self, pid: &PeerID, msg: PeerMessage) {
        if let Some(peer) = self.peers.get_mut(&pid) {
            peer.link.send(msg).await;
        }
    }

    async fn handle_peer_notification(&mut self, notif: PeerNotification) {
        let (id, peermsg) = match notif {
            PeerNotification::Received(id, peermsg) => (id, peermsg),
            PeerNotification::Disconnected(id) => {
                self.remove_peer(&id).await;
                return;
            }
        };

        match peermsg {
            PeerMessage::Hello(port) => {
                if let Some(peer) = self.peers.get_mut(&id) {
                    let mut addr = peer.socket_addr;
                    addr.set_port(port);
                    peer.listening_addr = Some(addr);
                }
            }
            PeerMessage::Data(msg) => {
                self.notify(NodeNotification::MessageReceived(id, msg))
                    .await
            }
            PeerMessage::Peers(mut list) => {
                list.truncate(self.peer_list_limit());
                self.peers.get_mut(&id).map(|peer| {
                    peer.peer_addrs = list;
                });

                self.recompute_priorities();

                self.connect_to_more_peers_if_needed().await;
            }
        }
    }

    async fn connect_to_more_peers_if_needed(&mut self) {
        let outbound_count = self.count_peers_with_direction(Direction::Outbound);
        if outbound_count >= self.config.outbound_limit {
            return;
        }
        let self_pid = self.peer_id();

        // Find all addresses, sorted by priority
        let mut list = self
            .peers
            .iter()
            .flat_map(|(_pid, peer_state)| {
                peer_state
                    .peer_addrs
                    .iter()
                    .filter(|peer_addr| {
                        // ignore all addresses to which we are already connected.
                        self.peers.get(&peer_addr.id).is_none() && peer_addr.id != self_pid
                    })
                    .map(|peer_addr| {
                        let priority = self
                            .peer_priorities
                            .get(&peer_addr.id)
                            .unwrap_or(LOW_PRIORITY);
                        (peer_addr.clone(), priority)
                    })
            })
            .collect::<Vec<_>>();
        // Note: we do not remove duplicates before sorting by priority,
        // because different peers may specify bogus addresses or bogus peer IDs that
        // would erase good entries during deduplication.
        list.sort_by_key(|&(_, priority)| priority);

        let mut slots_available = self.config.outbound_limit - outbound_count;
        for (peer_addr, _) in list.iter() {
            if slots_available == 0 {
                return;
            }

            if self.peers.get(&peer_addr.id).is_some() {
                continue;
            }

            match self.connect_to_peer_addr(&peer_addr).await {
                Ok(_) => {
                    slots_available -= 1;
                }
                Err(_) => {
                    // Probably shouldn't send a noisy notification
                    // that we failed to reach out to some random node.
                    // OTOH, would be good to learn if we are failing on many nodes,
                    // maybe someone is spamming us, or the network is bad.
                    /*  ¯\_(ツ)_/¯ */
                }
            }
        }
    }

    fn recompute_priorities(&mut self) {
        // We will do a naïve version for now.

        // FIXME: there's a problem that we need to fix:
        // If some trusted node temporarily was connected to very small number of their own trusted nodes,
        // some bad inbound nodes might appear high on their list and therefore get high priority on our side.
        // And current implementation is sticky: once a node gets high priority, we don't deprioritize it later,
        // when all high-priority nodes list it in the end.

        // Do at most 5 full cycles - not 100% precise, but won't be too long if we somehow have a large dataset.
        for _ in 0..5 {
            let mut updated = false;

            for (pid, peerstate) in self.peers.iter() {
                self.peer_priorities.batch(|priorities| {
                    let priority = priorities.get(&pid).unwrap_or(LOW_PRIORITY);
                    for (i, paddr) in peerstate.peer_addrs.iter().enumerate() {
                        updated =
                            updated || priorities.insert(paddr.id, priority + (i as Priority) + 1);
                    }
                });
            }

            if !updated {
                return;
            }
        }
    }

    async fn notify_on_error<E>(
        &mut self,
        result: Result<(), E>,
        mapper: impl FnOnce(E) -> NodeNotification,
    ) -> () {
        if let Err(e) = result {
            self.notify(mapper(e)).await;
        }
    }

    async fn notify(&mut self, notif: NodeNotification) {
        let _ = self.notifications_channel.send(notif).await.unwrap_or(());
    }

    fn sorted_peers(&self) -> Vec<PeerAddr> {
        let mut list = self
            .peers
            .iter()
            .filter_map(|(pid, peer)| {
                peer.listening_addr.map(|addr| PeerAddr {
                    id: *pid,
                    addr: addr,
                })
            })
            .map(|pa| {
                let priority = self.peer_priorities.get(&pa.id).unwrap_or(LOW_PRIORITY);
                (pa, priority)
            })
            .collect::<Vec<_>>();

        if list.len() == 0 {
            return Vec::new();
        }

        list.sort_by_key(|&(_, priority)| priority);
        list.into_iter()
            .take(self.peer_list_limit())
            .map(|(peer_addr, _priority)| peer_addr)
            .collect::<Vec<_>>()
    }

    /// Inspectable list of peers for debugging.
    fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .map(|(pid, peerstate)| PeerInfo {
                id: *pid,
                address: peerstate.listening_addr.unwrap_or(peerstate.socket_addr),
                public: peerstate.listening_addr.is_some(),
                direction: peerstate.direction,
                priority: self.peer_priorities.get(pid).unwrap_or(LOW_PRIORITY),
            })
            .collect::<Vec<_>>()
    }

    // Limit amount of peers we send out and receive to the outbound limit.
    fn peer_list_limit(&self) -> usize {
        self.config.outbound_limit
    }

    fn peer_id(&self) -> PeerID {
        PeerID::from(self.cybershake_identity.to_public_key())
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}   priority: {}   public: {}",
            match self.direction {
                Direction::Inbound => " [in]",
                Direction::Outbound => "[out]",
            },
            self.address,
            self.id,
            self.priority,
            self.public
        )
    }
}
