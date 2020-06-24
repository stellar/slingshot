use std::sync::{Arc, RwLock};

use tera::Tera;

/// Provides a Tera engine reference
pub fn init_tera() -> Arc<RwLock<Tera>> {
    let t = Tera::new("templates/**/*.html").unwrap();
    let t = Arc::new(RwLock::new(t));
    autoreload_templates(t.clone(), "./templates");
    t
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
                    //eprintln!("FS event: {:?}", _event);
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
