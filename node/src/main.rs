mod api;
mod bc;
mod comm;
mod ui;
mod config;
mod cli_args;

use config::Config;
use cli_args::RunCommand;

#[tokio::main]
async fn main() {
    match cli_args::parse_args() {
        RunCommand::Empty => print_welcome(),
        RunCommand::Run(config) => run(config).await,
        RunCommand::ShowConfig(config)  => show_config(config),
        RunCommand::Help(config) => help(config),
        RunCommand::Invalid(command_name) => invalid_command(command_name),
    }
}

fn print_welcome() {
    eprintln!("Welcome to the Slingshot node!");
    eprintln!("");
    eprintln!("To run the node, use `run` subcommand.");
    eprintln!("For more details, use `help`.");
}

async fn run(config: Config) {

    let (cmd_sender1, cmd_receiver) = comm::command_channel(1000);
    let cmd_sender2 = cmd_sender1.clone();
    let (event_sender, event_receiver1) = comm::event_channel(1000);
    let event_receiver2 = event_sender.subscribe();

    let config = &config;
    
    // 2. Run the blockchain state machine with p2p interface.
    let bc_process =
        tokio::spawn(
            async move { bc::launch(config.p2p.listen_addr, cmd_receiver, event_sender).await },
        );

    // 3. Spawn the API server
    let api_process = tokio::spawn(async move {
        api::launch(config.api.listen_addr, cmd_sender1, event_receiver1).await
    });

    // 4. Spawn the UI server
    let ui_process = tokio::spawn(async move {
        ui::launch(config.ui.listen_addr, cmd_sender2, event_receiver2).await;
    });

    ui_process.await.unwrap();
    api_process.await.unwrap();
    bc_process.await.unwrap();
}

fn show_config(config: Config) {
    //eprint!()
}

fn help(config: Config) {
    
}

fn invalid_command(name: String) {

}

