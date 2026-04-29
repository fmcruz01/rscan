use core::config::{Cli, help, usage_display, version};
use std::process::exit;

fn main() {
    match Cli::parse() {
        Ok(Cli::Help) => {
            help();
            exit(0);
        }
        Ok(Cli::Version) => {
            version();
            exit(0);
        }
        Ok(Cli::Config(_)) => { todo!() }
        Err(err) => {
            eprintln!("{}", err);
            usage_display();
            exit(1);
        }
    }
}
