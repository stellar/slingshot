use futures::{FutureExt, Stream, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::sync::RwLock;

use warp::ws::{Message, WebSocket};

type WSItem = <WebSocket as Stream>::Item;

#[derive(Default)]
pub struct WebsocketPool {
    next_conn_id: AtomicUsize,
    conn_map: RwLock<HashMap<usize, UnboundedSender<WSItem>>>,
}

impl WebsocketPool {
    /// Adds a newly created websocket to the pool and begins processing events to and from it.
    pub async fn add(self: Arc<Self>, socket: WebSocket) {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);

        //eprintln!("WS#{} connected", id);

        // Split the socket into a sender and receive of messages.
        let (ws_tx, mut ws_rx) = socket.split();

        // Use an unbounded channel to handle buffering and flushing of messages
        // to the websocket...
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::task::spawn(rx.forward(ws_tx).map(|result| {
            if let Err(_e) = result {
                //eprintln!("WS send error: {}", e);
            }
        }));

        // Save the sender in our list of connected users.
        self.conn_map.write().await.insert(id, tx);

        // FIXME: in this iteration we simply send every message to all users.
        while let Some(result) = ws_rx.next().await {
            let msg = match result {
                Ok(msg) => msg,
                Err(_e) => {
                    // When the browser tab is closed, we receive this error:
                    // "WebSocket protocol error: Connection reset without closing handshake"
                    //eprintln!("WS#{} error: {}", id, e);
                    break;
                }
            };

            let new_msg = format!("<{}>: {}", id, msg.to_str().unwrap_or("?"));

            // New message from this connection, send it to everyone else (except this id)
            for (&other_id, tx) in self.conn_map.read().await.iter() {
                if id != other_id {
                    if let Err(_disconnected) = tx.send(Ok(Message::text(new_msg.clone()))) {
                        // If we cannot send, it means the connection is dropped and dealt with in its own task.
                    }
                }
            }
        }

        //eprintln!("WS#{} disconnected", id);

        // Connect is closed, so we remove it from the map.
        self.conn_map.write().await.remove(&id);
    }
}
