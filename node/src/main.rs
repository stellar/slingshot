extern crate actix_web;
extern crate futures as futures_0_1;
extern crate tokio as tokio_0_1;

use std::thread;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

use futures::prelude::*;
use tokio_0_1::sync::mpsc;
use libp2p::{
    PeerId,
    Swarm,
    NetworkBehaviour,
    identity,
    tokio_io::{AsyncRead, AsyncWrite},
    floodsub::{self, Floodsub, FloodsubEvent},
    mdns::{Mdns, MdnsEvent},
    swarm::NetworkBehaviourEventProcess
};



// We create a custom network behaviour that combines floodsub and mDNS.
// In the future, we want to improve libp2p to make this easier to do.
#[derive(NetworkBehaviour)]
struct P2PBehavior<TSubstream: AsyncRead + AsyncWrite> {
    floodsub: Floodsub<TSubstream>,
    mdns: Mdns<TSubstream>,

    #[behaviour(ignore)]
    mystate: Vec<String>,
}

impl<TSubstream: AsyncRead + AsyncWrite> NetworkBehaviourEventProcess<MdnsEvent> for P2PBehavior<TSubstream> {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    println!("mDNS: Connected to {:?}", &peer);
                    self.floodsub.add_node_to_partial_view(peer);
                }
            },
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        println!("mDNS: Disconnected from {:?}", &peer);
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

impl<TSubstream: AsyncRead + AsyncWrite> NetworkBehaviourEventProcess<FloodsubEvent> for P2PBehavior<TSubstream> {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        if let FloodsubEvent::Message(message) = message {
            let msg = String::from_utf8_lossy(&message.data);
            println!("Floodsub: Received: '{:?}' from {:?}", &msg, message.source);
            self.mystate.push(msg.to_string());

            // TODO: send a websocket notification
        }
    }
}

fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

fn publish_action(msg: web::Path<String>, ui_sender: web::Data<mpsc::UnboundedSender<String>>) -> impl Responder {
    let msg: String = msg.to_string();
    let ui_sender = ui_sender.get_ref();
    tokio_0_1::spawn(
        ui_sender
            .clone()
            .send(msg.clone())
            .map(|_| ())
            .map_err(|_| ())
    );

    // Get the channel from the global state and send the value there.
    HttpResponse::Ok().body(format!("Published `{}`", &msg))
}

fn main() {

    // Channel for sending messages from the http UI into the app.
    // Http server holds the sending end, while Tokio p2p loop 
    let (ui_sender, mut ui_receiver) = mpsc::unbounded_channel::<String>();

    // Prepare a background runtime for the p2p communications
    {
        // Create a random PeerId
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("Local peer id: {:?}", local_peer_id);

        // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_tcp_ws_secio_mplex_yamux(local_key);

        // Create a Floodsub topic
        let floodsub_topic = floodsub::TopicBuilder::new("chat").build();

        thread::spawn(move || {
            println!("Launching p2p networking on a separate thread.");


            // Create a Swarm to manage peers and events
            let mut swarm = {
                let mut behaviour = P2PBehavior {
                    floodsub: Floodsub::new(local_peer_id.clone()),
                    mdns: Mdns::new().expect("Failed to create mDNS service"),
                    mystate: Vec::new(),
                };

                behaviour.floodsub.subscribe(floodsub_topic.clone());
                Swarm::new(transport, behaviour, local_peer_id)
            };

            // Listen on all interfaces and whatever port the OS assigns
            Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

            // Kick it off
            let mut listening = false;
            tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
                // Central place to collect messages to our app from the HTTP endpoints.
                loop {
                    match ui_receiver.poll().expect("Error while polling the UI channel") {
                        Async::Ready(Some(msg)) => {
                            // route the message to the app,
                            swarm.mystate.push(msg.clone());
                            // and propagate it to other instance.
                            swarm.floodsub.publish(&floodsub_topic, msg.clone())
                        },
                        Async::Ready(None) => panic!("Stdin closed"),
                        Async::NotReady => break,
                    };
                }
                loop {
                    match swarm.poll().expect("Error while polling swarm") {
                        Async::Ready(Some(_)) => {
                            // Notifications are sent to the impls of `NetworkBehaviourEventProcess`.
                        },
                        Async::Ready(None) | Async::NotReady => {
                            if !listening {
                                if let Some(a) = Swarm::listeners(&swarm).next() {
                                    println!("P2P listening on {:?}", a);
                                    listening = true;
                                }
                            }
                            break
                        }
                    }
                }

                Ok(Async::NotReady)
            }));
        });
    }

    // Prepare a web server UI
    // TODO: try user-provided port instead of a random one.
    // TODO: when integrated into host app, signal the port through FFI to the app so it can show the UI.
    let server = HttpServer::new(move || {
        App::new()
            .data(ui_sender.clone())
            .route("/", web::get().to(index))
            .route("/pub/{msg}", web::get().to(publish_action))
    })
    .bind("127.0.0.1:0")
    .expect("Failed to bind()");

    println!("UI server: localhost:{}", server.addrs()[0].port());

    server.run().expect("Failed to run()");
}
