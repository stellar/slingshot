mod ws;

use std::collections::HashMap;
use std::default::Default;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tera::Tera;
use warp::Filter;

use crate::comm::{CommandSender, EventReceiver};

/// Launches the UI server.
/// Takes a receiving channel as a parameter that receives
///
/// /               -> General network stats: chain state, mempool, connected peers, accounts.
/// /blocks         -> List of blocks
/// /blocks/:height -> View into a block
/// /mempool        -> List mempool txs
/// /tx/:id         -> Tx details and status (confirmed, mempool, dropped)
///
/// /ws             -> websocket notifications
pub async fn launch(
    addr: SocketAddr,
    cmd_sender: CommandSender,
    event_receiver: EventReceiver,
) {
    let tera = Tera::new("templates/**/*.html").unwrap();
    let tera_arc = Arc::new(RwLock::new(tera));
    autoreload_templates(tera_arc.clone(), "./templates");

    let index = warp::path::end().map(|| {
        let mut dict = HashMap::new();
        dict.insert("greeting", "Hello!");
        ("index.html", dict)
    });

    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    let bye = warp::path!("bye" / String).map(|name| format!("Bye, {}!", name));

    let ws_pool = Arc::new(ws::WebsocketPool::default());
    let ws_route = warp::path("ws")
        .and(warp::any().map(move || ws_pool.clone()))
        .and(warp::ws())
        .map(|wspool: Arc<ws::WebsocketPool>, ws: warp::ws::Ws| {
            ws.on_upgrade(move |socket| wspool.add(socket))
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
    let routes = warp::get().and(html_routes.or(hello).or(bye).or(ws_route).or(static_route));
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
                Ok(_event) => {
                    eprintln!("FS event: {:?}", _event);
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
