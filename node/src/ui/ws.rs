use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::default::Default;
use tokio::sync::mpsc;
use futures::{FutureExt, StreamExt};

use warp::ws::{Message, WebSocket};

/// Collection of all open websockets. 
pub type ConnectionMap =
    Arc<tokio::sync::RwLock<HashMap<usize, mpsc::UnboundedSender<Result<Message, warp::Error>>>>>;


static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

/// Prepares the connection
pub async fn add_connection(socket: WebSocket, conn_map: ConnectionMap) {
    // Use a counter to assign a new unique ID for this user.
    let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

    eprintln!("WS#{} connected", id);

    // Split the socket into a sender and receive of messages.
    let (user_ws_tx, mut user_ws_rx) = socket.split();

    // Use an unbounded channel to handle buffering and flushing of messages
    // to the websocket...
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::task::spawn(rx.forward(user_ws_tx).map(|result| {
        if let Err(e) = result {
            eprintln!("WS send error: {}", e);
        }
    }));

    // Save the sender in our list of connected users.
    conn_map.write().await.insert(id, tx);

    // Every time the user sends a message, broadcast it to
    // all other users...
    while let Some(result) = user_ws_rx.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                // When the browser tab is closed, we receive this error:
                // "WebSocket protocol error: Connection reset without closing handshake"
                //eprintln!("WS#{} error: {}", id, e);
                break;
            }
        };

        let new_msg = format!("<{}>: {}", id, msg.to_str().unwrap_or("?"));

        // New message from this connection, send it to everyone else (except this id)
        for (&other_id, tx) in conn_map.read().await.iter() {
            if id != other_id {
                if let Err(_disconnected) = tx.send(Ok(Message::text(new_msg.clone()))) {
                    // If we cannot send, it means the connection is dropped and dealt with in its own task.
                }
            }
        }
    }

    eprintln!("WS#{} disconnected", id);

    // Connect is closed, so we remove it from the map.
    conn_map.write().await.remove(&id);
}