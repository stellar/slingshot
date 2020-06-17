mod api;
mod bc;
mod ui;

#[tokio::main]
async fn main() {
    // 0. Load config or parse options:
    // - load toml file
    // - override toml name with a CLI option
    // - override individual options with CLI options.

    // 1. Run blockchain state machine loop.

    // 2. Run p2p networking loop.

    // 3. Spawn the API server
    let api_process = tokio::spawn(async move { api::launch(([127, 0, 0, 1], 3001)).await });

    // 4. Spawn the UI server
    let ui_process = tokio::spawn(async move {
        ui::launch(([127, 0, 0, 1], 3000)).await;
    });

    api_process.await.unwrap();
    ui_process.await.unwrap();
}
