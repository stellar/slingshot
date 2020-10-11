#[macro_use]
extern crate serde_json;

mod api;
mod bc;
mod cli_args;
mod config;
mod errors;
mod json;
mod ui;
mod wallet;
mod wallet_manager;

use bc::Blockchain;
use cli_args::RunCommand;
use config::Config;
use errors::Error;
use std::path::Path;
use ui::UI;
use wallet_manager::WalletManager;

#[tokio::main]
async fn main() {
    match cli_args::parse_args() {
        Ok(RunCommand::Run(_binpath, (config_path, config))) => {
            // Display a proper error message when we fail
            run(&config_path, config).await.unwrap()
        }
        Ok(RunCommand::ShowConfig(_binpath, (config_path, config))) => {
            show_config(&config_path, config)
        }
        Ok(RunCommand::Help(binpath)) => help(&binpath),
        Err(msg) => eprintln!("{}", msg),
    }
}

async fn run(config_path: &Path, config: Config) -> Result<(), Error> {
    let storage_path = config.blockchain.absolute_storage_path(&config_path);

    // 1. Run the blockchain state machine with p2p interface
    let bc_ref =
        Blockchain::launch(storage_path, config.p2p.clone(), config.blockchain.clone()).await;

    // 2. Create a wallet
    let wallet = WalletManager::new(config.wallet.clone(), &config_path)?;

    // 2. Spawn the API server
    let addr = config.api.listen_addr;
    let api_process = if !config.api.disabled {
        let bc = bc_ref.clone();
        let wm = wallet.clone();
        Some(tokio::spawn(async move { api::launch(addr, bc, wm).await }))
    } else {
        None
    };

    // 3. Spawn the UI server
    let addr = config.ui.listen_addr;
    let ui_process = if !config.ui.disabled {
        let bc = bc_ref.clone();
        let wm = wallet.clone();
        Some(tokio::spawn(async move {
            UI::launch(addr, bc, wm).await;
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
    Ok(())
}

fn show_config(config_path: &Path, config: Config) {
    println!("Using {}\n", config_path.display());
    println!("Resolved configuration:\n");
    let toml_string = toml::ser::to_string_pretty(&config).expect("Failed to serialize config as TOML file. Please file a bug with the contents of your config file, so we can fix it.");
    println!("{}", toml_string);
}

fn help(_binpath: &Path) {
    println!(
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
