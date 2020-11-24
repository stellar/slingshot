use crate::config::Config;
use std::env;
use std::path::PathBuf;

pub enum RunCommand {
    /// executable path, config path, config
    Run(PathBuf, (PathBuf, Config)),
    /// executable path, config path, config
    ShowConfig(PathBuf, (PathBuf, Config)),
    /// executable path
    Help(PathBuf),
}

/// Parses command like args and returns the path to the executable and the type of subcommand.
pub fn parse_args() -> Result<RunCommand, String> {
    let mut args = std::env::args();
    let exec_path = args
        .next()
        .ok_or_else(|| "Unexpected missing executable path in the env::args list.".to_string())?;

    let subcommand = args.next().ok_or_else(|| {
        r##"
Please use one of the following subcommands:

    slingshot run      # run the node
    slingshot config   # show the current configuration
    slingshot init     # initialize the blockchain state and wallet
    slingshot help     # list command line options
"##
    })?;

    let exec_path = PathBuf::from(exec_path);

    match subcommand.as_str() {
        "help" => Ok(RunCommand::Help(exec_path)),
        "--help" => Ok(RunCommand::Help(exec_path)),
        "-h" => Ok(RunCommand::Help(exec_path)),
        "run" => Ok(RunCommand::Run(exec_path, parse_config_opts(args)?)),
        "config" => Ok(RunCommand::ShowConfig(exec_path, parse_config_opts(args)?)),
        x => Err(format!(
            "Unknown subcommand: `{}`. Use `help` to see a list of available options.",
            x
        )),
    }
}

fn parse_config_opts(args: env::Args) -> Result<(PathBuf, Config), String> {
    // TODO: load Config from ~/.slingshot/config.toml
    // or via --config <path/to/config.toml>
    let default_path = PathBuf::from("~/.slingshot/config.toml");

    Ok((default_path, Config::default()))
}
