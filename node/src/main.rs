#[macro_use]
extern crate serde_json;

mod api;
mod bc;
mod config;
mod errors;
mod json;
mod ui;
mod wallet;
mod wallet_manager;

use bc::{Blockchain, BlockchainIdle};
use config::Config;
use errors::Error;
use ui::UI;
use wallet::Wallet;
use wallet_manager::WalletManager;

use accounts::AddressLabel;
use keytree::Xprv;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use zkvm::curve25519_dalek::scalar::Scalar;
use zkvm::ClearValue;

#[tokio::main]
async fn main() {
    if let Err(msg) = launch().await {
        eprintln!("{}", msg);
        std::process::exit(1);
    }
}

async fn launch() -> Result<(), String> {
    use clap::{self, App, Arg, SubCommand};

    let cli_matches = App::new("Slingshot node")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .version("1.0")
        .author("Oleg Andreev <oleganza@gmail.com>")
        .about("An interface to the Slingshot blockchain network and wallet.")
        .arg(
            Arg::with_name("config")
                .long("config")
                .takes_value(true)
                .value_name("FILE")
                .help("Sets a custom config file"),
        )
        .subcommand(SubCommand::with_name("config").about("Displays the current configuration"))
        .subcommand(SubCommand::with_name("run").about("Runs the node"))
        .subcommand(
            SubCommand::with_name("new")
                .about("Creates a new ledger")
                .arg(
                    Arg::with_name("prefix")
                        .long("prefix")
                        .value_name("ADDRESS_PREFIX")
                        .takes_value(true)
                        .required(true)
                        .help("Prefix for addresses (1-83 alphanumeric lowercase characters)"),
                ),
        )
        .subcommand(
            SubCommand::with_name("connect").about("Connects to an existing ledger"), //.arg(Arg::with_name(""))
        )
        .subcommand(
            SubCommand::with_name("wallet")
                .about("Performs wallet operations")
                .subcommand(SubCommand::with_name("new").about("Creates a new wallet")),
        )
        .get_matches();
    let config_path = cli_matches.value_of("config").map(|s| PathBuf::from(s));

    let mut config = Config::load(config_path.clone())
        .map_err(|e| format!("Cannot read the config file: {:?}", e))?;

    match cli_matches.subcommand() {
        ("config", Some(_)) => {
            show_config(&config);
        }
        ("new", Some(sm)) => {
            let prefix = sm
                .value_of("prefix")
                .expect("This is a required argument")
                .to_string();
            let addr_label = AddressLabel::new(prefix).ok_or(
                "Address prefix must be 1-83 alphanumeric characters long, US-ASCII lowercase."
                    .to_string(),
            )?;
            create_new_blockchain(config, addr_label)
                .await
                .map_err(|e| format!("Failed to create a new blockchain {:?}", e))?;
        }
        ("wallet", Some(wallet)) => {}
        ("run", Some(sm)) => {
            run(config)
                .await
                .map_err(|e| format!("Failed to launch node: {:?}", e))?;
            println!("TBD: run");
        }

        (other, _) => {
            eprintln!("Sorry, subcommand `{}` is not enabled yet.", other);
        }
    }

    Ok(())
}

async fn create_new_blockchain(
    config: Config,
    addr_label: AddressLabel,
) -> Result<BlockchainIdle, Error> {
    let xprv = Xprv::random(rand::thread_rng());
    let xpub = xprv.to_xpub();
    let wallet = Wallet::new(addr_label, xpub);
    let wallet_manager = WalletManager::new(config.clone())?;
    wallet_manager.read().await.save_xprv(xprv)?;
    wallet_manager.write().await.initialize_wallet(wallet)?;

    // Initialize blockchain.
    let bc_state = wallet_manager.write().await.update_wallet(|wallet| {
        let state = wallet.seed_blockchain(
            current_timestamp_ms(),
            vec![ClearValue {
                qty: 1000,
                flv: Scalar::zero(),
            }],
        );
        Ok(state)
    })?;

    // Save the blockchain state.
    let bc = Blockchain::new(config)?.init(bc_state)?;
    Ok(bc)
}

async fn run(config: Config) -> Result<(), Error> {
    // 1. Run the blockchain state machine with p2p interface
    let bc_ref = Blockchain::new(config.clone())?.launch().await?;

    // 2. Create a wallet
    let wallet = WalletManager::new(config.clone())?;

    // 2. Spawn the API server
    let addr = config.data.api.listen;
    let api_process = if !config.data.api.disabled {
        let bc = bc_ref.clone();
        let wm = wallet.clone();
        Some(tokio::spawn(async move { api::launch(addr, bc, wm).await }))
    } else {
        None
    };

    // 3. Spawn the UI server
    let addr = config.data.ui.listen;
    let ui_process = if !config.data.ui.disabled {
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

    // Shut down blockchain stack
    bc_ref.as_ref().read().await.stop().await;
    Ok(())
}

fn show_config(config: &Config) {
    println!("Using {}\n", config.path.display());
    println!("Resolved configuration:\n");
    let toml_string = toml::ser::to_string_pretty(&config.data).expect("Failed to serialize config as TOML file. Please file a bug with the contents of your config file, so we can fix it.");
    println!("{}", toml_string);
}

/// Returns the current system time.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime should work")
        .as_millis() as u64
}
