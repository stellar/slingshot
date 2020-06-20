use crate::config::Config;

pub enum RunCommand {
    Empty,
    Run(Config),
    ShowConfig(Config),
    Help(Config),
    Invalid(String)
}

    //
    // First comes the command: 
    //    "run", "help" (also "-h" and "--help" works) or "config"
    // 2. Then come the --config <path to config>  # default path is ~/.slingshot/config.toml
    // 

    // - load toml file
    // - override toml name with a CLI option
    // - override individual options with CLI options.

    
/// Parses command like args and returns the type of command and a config file.
pub fn parse_args() -> RunCommand {
    RunCommand::Empty
}

