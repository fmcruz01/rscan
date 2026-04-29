use crate::errors::{Error, ErrorType};

pub enum Mode {
    TUI,
    PASSIVE,
    ACTIVE,
    VERSION,
    HELP,
}

pub struct Config {
    pub mode: Mode,
    pub verbose: bool,
}

impl Config {
    fn default() -> Self {
        Self {
            mode: Mode::TUI,
            verbose: false,
        }
    }

    fn set_mode(&mut self, mode_set: &mut bool, new_mode: Mode) -> Result<(), Error> {
        if *mode_set {
            return Err(Error::err(
                ErrorType::ArgParseError,
                "Multiple modes specified, only one is supported".to_string(),
            ));
        }
        self.mode = new_mode;
        *mode_set = true;
        Ok(())
    }
}

pub enum Cli {
    Config(Config),
    Help,
    Version,
}

impl Cli {
    pub fn parse() -> Result<Self, Error> {
        let mut config = Config::default();
        let mut mode_set = false;
        let args = std::env::args().skip(1);
        for arg in args {
            if arg.starts_with("--") {
                match arg.as_str() {
                    "--version" => return Ok(Cli::Version),
                    "--help" => return Ok(Cli::Help),
                    "--tui" => config.set_mode(&mut mode_set, Mode::TUI)?,
                    "--passive" => config.set_mode(&mut mode_set, Mode::PASSIVE)?,
                    "--active" => config.set_mode(&mut mode_set, Mode::ACTIVE)?,
                    "--verbose" => config.verbose = true,
                    _ => {
                        return Err(Error::err(
                            ErrorType::ArgParseError,
                            "Unknown argument.".to_string(),
                        ));
                    }
                }
            } else if arg.starts_with("-") {
                for ch in arg.chars().skip(1) {
                    match ch {
                        'V' => return Ok(Cli::Version),
                        'h' => return Ok(Cli::Help),
                        't' => config.set_mode(&mut mode_set, Mode::TUI)?,
                        'p' => config.set_mode(&mut mode_set, Mode::PASSIVE)?,
                        'a' => config.set_mode(&mut mode_set, Mode::ACTIVE)?,
                        'v' => config.verbose = true,
                        _ => {
                            return Err(Error::err(
                                ErrorType::ArgParseError,
                                "Unknown argument.".to_string(),
                            ));
                        }
                    }
                }
            } else {
            }
        }
        Ok(Cli::Config(config))
    }
}

pub fn usage_display() {
    println!(
        "usage: rscan [MODE] [OPTIONS]

        Arguments:
        -t, --tui           Terminal User Interface mode. (Default mode).
        -p, --passive       Passive mode. (Displaying packets metadata).
        -a, --active        Active mode (Host/port discovery).


        Options:
        -v, --verbose       Verbose output logging.
        -h, --help          Print help.
        -V, --version       Print version.

        Notes:
        If no mode is specified, --tui is assumed.\n"
    );
}

pub fn help() {
    version();
    usage_display();
}

pub fn version() {
    println!("RSCAN {} — Network Recon CLI\n", env!("CARGO_PKG_VERSION"));
}

pub fn intro_banner() {
    let banner = r#"
 ____  ____   ____    _    _   _
|  _ \/ ___| / ___|  / \  | \ | |
| |_) \___ \| |     / _ \ |  \| |
|  _ < ___) | |___ / ___ \| |\  |
|_| \_\____/ \____/_/   \_\_| \_|
"#;
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char); // clear terminal and position cursor at 1,1
    println!("\x1b[36m{}\x1b[0m", banner); // cyan
    println!("RSCAN {} — Network Recon CLI\n", env!("CARGO_PKG_VERSION"));
}

