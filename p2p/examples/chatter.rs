use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use std::net::{IpAddr, Ipv4Addr};

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::cybershake;
use p2p::{Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

fn main() {
    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Creating a random private key instead of reading from a file.
            let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

            let config = NodeConfig {
                listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                listen_port: 0,
                inbound_limit: 100,
                outbound_limit: 100,
                heartbeat_interval_sec: 3600,
            };

            let (node, mut notifications_channel) = Node::<Message>::spawn(host_privkey, config)
                .await
                .expect("Should bind normally.");

            println!(
                "Listening on {} with peer ID: {}",
                node.socket_address(),
                node.id()
            );

            // Begin the UI.
            let interactive_loop = Console::spawn(node);

            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    while let Some(notif) = notifications_channel.recv().await {
                        match notif {
                            NodeNotification::PeerAdded(pid) => {
                                println!("\n=>    Peer connected: {}", pid)
                            }
                            NodeNotification::PeerDisconnected(pid) => {
                                println!("\n=> Peer disconnected: {}", pid)
                            }
                            NodeNotification::MessageReceived(pid, msg) => println!(
                                "\n=> Received: `{}` from {}",
                                String::from_utf8_lossy(&msg).into_owned(),
                                pid
                            ),
                            NodeNotification::InboundConnectionFailure(err) => {
                                println!("\n=> Inbound connection failure: {:?}", err)
                            }
                            NodeNotification::OutboundConnectionFailure(err) => {
                                println!("\n=> Outbound connection failure: {:?}", err)
                            }
                            NodeNotification::Shutdown => {
                                println!("\n=> Node did shutdown.");
                                break;
                            }
                        }
                    }
                    Result::<(), String>::Ok(())
                })
            };

            notifications_loop.await.expect("panic on JoinError")?;
            interactive_loop.await.expect("panic on JoinError")
        })
        .unwrap()
}

enum UserCommand {
    Nop,
    Connect(Vec<String>),
    Broadcast(String),
    Disconnect(PeerID), // peer id
    ListPeers,
    Exit,
}

pub struct Console {
    node: NodeHandle<Message>,
}

impl Console {
    pub fn spawn(node: NodeHandle<Message>) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console { node };
            loop {
                let mut line = String::new();
                io::stderr().write_all(">> ".as_ref()).await.unwrap();
                let n = stdin
                    .read_line(&mut line)
                    .await
                    .map_err(|_| "Failed to read UTF-8 line.".to_string())?;
                if n == 0 {
                    // reached EOF
                    break;
                }
                let result = async {
                    let cmd = Console::parse_command(&line)?;
                    console.process_command(cmd).await
                }
                .await;

                match result {
                    Err(e) => {
                        if e == "Command::Exit" {
                            // exit gracefully
                            return Ok(());
                        } else {
                            // print error
                            println!("!> {}", e);
                        }
                    }
                    Ok(_) => {}
                };
            }
            Ok(())
        })
    }

    /// Processes a single command.
    async fn process_command(&mut self, command: UserCommand) -> Result<(), String> {
        match command {
            UserCommand::Nop => {}
            UserCommand::Exit => return Err("Command::Exit".into()),
            UserCommand::Connect(addrs) => {
                for addr in addrs {
                    let _ = self
                        .node
                        .connect_to_peer(&addr, None)
                        .await
                        .map_err(|e| format!("Handshake error with {}. {:?}", addr, e))?;
                }
            }
            UserCommand::Disconnect(peer_id) => {
                self.node.remove_peer(peer_id).await;
            }
            UserCommand::Broadcast(msg) => {
                println!("=> Broadcasting: {:?}", &msg);
                self.node.broadcast(Message(msg.as_bytes().to_vec())).await;
            }
            UserCommand::ListPeers => {
                let peer_infos = self.node.list_peers().await;
                println!("=> {} peers:", peer_infos.len());
                for peer_info in peer_infos.iter() {
                    println!("  {}", peer_info);
                }
            }
        }
        Ok(())
    }

    fn parse_command(line: &str) -> Result<UserCommand, String> {
        let line = line.trim().to_string();
        if line == "" {
            return Ok(UserCommand::Nop);
        }
        let mut head_tail = line.splitn(2, " ");
        let command = head_tail
            .next()
            .ok_or_else(|| {
                "Missing command. Try `connect <addr:port>` or `broadcast <text>`".to_string()
            })?
            .to_lowercase();
        let rest = head_tail.next();

        if command == "connect" {
            let addrs = rest
                .unwrap_or("")
                .to_string()
                .trim()
                .split_whitespace()
                .map(|a| a.to_string())
                .collect::<Vec<_>>();
            if addrs.len() == 0 {
                return Err("Address is not specified. Use `connect <addr:port>`. Multiple addresses are allowed.".into());
            }
            Ok(UserCommand::Connect(addrs))
        } else if command == "broadcast" {
            Ok(UserCommand::Broadcast(rest.unwrap_or("").into()))
        } else if command == "peers" {
            Ok(UserCommand::ListPeers)
        } else if command == "disconnect" {
            let s: String = rest.unwrap_or("").into();
            if let Some(id) = PeerID::from_string(&s) {
                Ok(UserCommand::Disconnect(id))
            } else {
                Err(format!("Invalid peer ID `{}`", s))
            }
        } else if command == "exit" || command == "quit" || command == "q" {
            Ok(UserCommand::Exit)
        } else {
            Err(format!("Unknown command `{}`", command))
        }
    }
}

use readerwriter::{Decodable, Encodable, ReadError, Reader, WriteError, Writer};
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
    fn encode(&self, dst: &mut impl Writer) -> Result<(), WriteError> {
        Ok(dst.write(b"data", self.as_slice()).unwrap())
    }
}

impl Decodable for Message {
    fn decode(buf: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(Self(buf.read_bytes(buf.remaining_bytes()).unwrap()))
    }
}
