mod api;
mod bc;
mod comm;
mod ui;

#[tokio::main]
async fn main() {
    // 0. Load config or parse options:
    /*
    [ui]
    listen = "127.0.0.1:3000"

    [api]
    listen = "127.0.0.1:3001"

    [blockchain]
    listen = "0.0.0.0:0" # port 0 means it is system-assigned.
    priority_peers = ["..."]
    blocked_peers = ["..."]

    */
    // - load toml file
    // - override toml name with a CLI option
    // - override individual options with CLI options.

    let (cmd_sender1, cmd_receiver) = comm::command_channel(1000);
    let cmd_sender2 = cmd_sender1.clone();
    let (event_sender, event_receiver1) = comm::event_channel(1000);
    let event_receiver2 = event_sender.subscribe();

    // 1. Run the blockchain state machine with p2p interface.
    let blockchain_process =
        tokio::spawn(
            async move { bc::launch(([0, 0, 0, 0], 0), cmd_receiver, event_sender).await },
        );

    // 3. Spawn the API server
    let api_process = tokio::spawn(async move {
        api::launch(([127, 0, 0, 1], 3001), cmd_sender1, event_receiver1).await
    });

    // 4. Spawn the UI server
    let ui_process = tokio::spawn(async move {
        ui::launch(([127, 0, 0, 1], 3000), cmd_sender2, event_receiver2).await;
    });

    ui_process.await.unwrap();
    api_process.await.unwrap();
    blockchain_process.await.unwrap();
}
