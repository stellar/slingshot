mod api;
mod bc;
mod cli_args;
mod comm;
mod config;
mod ui;

use cli_args::RunCommand;
use config::Config;
use std::path::Path;

#[tokio::main]
async fn main() {
    match cli_args::parse_args() {
        Ok(RunCommand::Run(_binpath, (config_path, config))) => run(&config_path, config).await,
        Ok(RunCommand::ShowConfig(_binpath, (config_path, config))) => show_config(&config_path, config),
        Ok(RunCommand::Help(binpath)) => help(&binpath),
        Err(msg) => eprintln!("{}", msg),
    }
}

async fn run(config_path: &Path, config: Config) {
    let (cmd_sender1, cmd_receiver) = comm::command_channel(1000);
    let cmd_sender2 = cmd_sender1.clone();
    let (event_sender, event_receiver1) = comm::event_channel(1000);
    let event_receiver2 = event_sender.subscribe();
    
    let storage_path = config.blockchain.absolute_storage_path(&config_path);

    // 1. Run the blockchain state machine with p2p interface.
    let bc_process = {
        let p2p_cfg = config.p2p.clone();
        let bc_cfg = config.blockchain.clone();
        tokio::spawn(
            async move { bc::launch(&storage_path, p2p_cfg, bc_cfg, cmd_receiver, event_sender).await },
        )
    };

    // 2. Spawn the API server
    let addr = config.api.listen_addr;
    let api_process = if !config.api.disabled {
        Some(tokio::spawn(async move {
            api::launch(addr, cmd_sender1, event_receiver1).await
        }))
    } else {
        None
    };

    // 3. Spawn the UI server
    let addr = config.ui.listen_addr;
    let ui_process = if !config.ui.disabled {
        Some(tokio::spawn(async move {
            ui::launch(addr, cmd_sender2, event_receiver2).await;
        }))
    } else {
        None
    };

    // Join all the tasks.
    if let Some(handle) = ui_process {
        handle.await.unwrap();
    }
    if let Some(handle) = api_process {
        handle.await.unwrap();
    }
    bc_process.await.unwrap();
}

fn show_config(config_path: &Path, config: Config) {
    let toml_string = toml::ser::to_string_pretty(&config).expect("Failed to serialize config as TOML file. Please file a bug with the contents of your config file, so we can fix it.");
    eprintln!("{}", toml_string);
}

fn help(_binpath: &Path) {
    eprintln!(
        r###"
## Running the node

    slingshot run    [options]      # run the node
    slingshot config [options]      # show current configuration
    slingshot help                  # list command line options

## Launch options

    --config <path>           # path to the config file
                                (default is ~/.slingshot/config.toml)

    --override <config line>  # overrides a config setting just for this launch
                                (e.g. --override "ui.listen='127.0.0.1:8000'")

## Slingshot config file with default settings:
{0}
"###,
        Config::description(),
    );
}
