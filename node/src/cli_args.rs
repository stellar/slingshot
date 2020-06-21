use crate::config::Config;
use std::env;
use std::path::PathBuf;

pub enum RunCommand {
    Run(PathBuf, Config),
    ShowConfig(PathBuf, Config),
    Help(PathBuf),
}

/// Parses command like args and returns the path to the executable and the type of subcommand.
pub fn parse_args() -> Result<RunCommand, String> {
    let mut args = std::env::args();
    let exec_path = args
        .next()
        .ok_or_else(|| "Unexpected missing executable path in the env::args list.".to_string())?;

    let subcommand = args.next().ok_or_else(|| {
        format!(
            "\
        {0} run      # run the node\n\
        {0} config   # show current configuration\n\
        {0} help     # list command line options\n\
        ",
            &exec_path
        )
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

fn parse_config_opts(args: env::Args) -> Result<Config, String> {
    // TODO: load Config from ~/.slingshot/config.toml
    // or via --config <path/to/config.toml>
    Ok(Config::default())
}
