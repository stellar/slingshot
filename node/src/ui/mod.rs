mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::default::Default;
use tokio::sync::mpsc;
use futures::{FutureExt, StreamExt};

use tera::Tera;
use warp::ws::{Message, WebSocket};
use warp::Filter;

/// Launches the UI server.
/// Takes a receiving channel as a parameter that receives 
///
/// /               -> General network stats: chain state, mempool, connected peers, accounts.
/// /blocks         -> List of blocks
/// /blocks/:height -> View into a block
///
/// /ws             -> websocket notifications
pub async fn launch(addr: impl Into<SocketAddr> + 'static) {
    let tera = Tera::new("templates/**/*.html").unwrap();
    let tera_arc = Arc::new(RwLock::new(tera));

    let index = warp::path::end().map(|| {
        let mut dict = HashMap::new();
        dict.insert("greeting", "Hello!");
        ("index.html", dict)
    });

    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    let bye = warp::path!("bye" / String).map(|name| format!("Bye, {}!", name));

    autoreload_templates(tera_arc.clone(), "./templates");
    
    let ws_connections = ws::ConnectionMap::default();
    let ws_route = warp::path("ws")
        .and(warp::any().map(move || ws_connections.clone()))    
        .and(warp::ws())
        .map(|conns, ws: warp::ws::Ws| {
            ws.on_upgrade(move |socket| {
                ws::add_connection(socket, conns)
            })
        });

    // warp::header::headers_cloned()
    let tera = tera_arc.clone();
    let html_routes = index
        .map(move |(template_name, object)| {
            let tera = tera.read().unwrap();
            let ctx =
                tera::Context::from_serialize(object).expect("context should be a JSON object");
            let html = tera
                .render(template_name, &ctx)
                .unwrap_or_else(|e| format!("Tera parse error: {}", e));
            warp::reply::html(html)
        })
        .boxed();
    // Somehow this .boxed() fixes this unintelligible error:
    //
    //     --> node/src/main.rs:37:22
    //     |
    //  37 |     let ui_process = tokio::spawn(async move {
    //     |                      ^^^^^^^^^^^^ one type is more general than the other
    //     |
    //     = note: expected type `std::ops::FnOnce<((&str, &str),)>`
    //                found type `std::ops::FnOnce<((&str, &str),)>`

    let static_route = warp::path("static").and(warp::fs::dir("static"));
    let routes = warp::get().and(
        html_routes
            .or(hello)
            .or(bye)
            .or(ws_route)
            .or(static_route),
    );
    let addr = addr.into();
    eprintln!("UI:  http://{}", &addr);
    warp::serve(routes).run(addr).await;
}

fn autoreload_templates(tera: Arc<RwLock<Tera>>, path: impl AsRef<std::path::Path>) {
    use notify::{watcher, RecursiveMode, Watcher};
    use std::sync::mpsc::{channel, RecvError};
    use std::thread;
    use std::time::Duration;

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(2)).unwrap();
    watcher.watch(path, RecursiveMode::Recursive).unwrap();

    thread::spawn(move || {
        loop {
            match rx.recv() {
                Ok(event) => {
                    //eprintln!("FS event: {:?}", event);
                    let mut tera = tera.write().unwrap();
                    match tera.full_reload() {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Failed to reload tera templates: {}", e);
                        }
                    };
                }
                Err(RecvError) => break, // channel closed
            }
        }
        watcher // make sure the instance lives till the end of the channel
    });
}
