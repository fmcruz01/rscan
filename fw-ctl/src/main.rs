// CLI entry point
//
// Parse user commands
// Dispatch subcommands
// Handle errors cleanly

use std::env::args;
use std::process::exit;

fn main() {
    let mut args = args().skip(1);
    match args.next().as_deref() {
        Some("sniff") => {
            let verbose = true;
            println!("Starting capture...");
            if let Err(e) = fw_user::runtime::start_capture(verbose) {
                eprintln!("error: {e:?}");
                exit(1);
            }
        }
        _ => {
            help();
            exit(0);
        }
    }
}

fn help() {
    println!(
        "usage:
fw-ctl sniff [ -v ]
    Start firewall. Use -v for verbose mode.
"
    );
}
