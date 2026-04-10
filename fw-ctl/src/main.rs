// CLI entry point
//
// Parse user commands
// Dispatch subcommands
// Handle errors cleanly

use std::env::args;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() -> Result<(), ()> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nShutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting SIGINT handler.");

    let mut args = args().skip(1);
    match args.next().as_deref() {
        Some("sniff") => {
            let verbose = true;
            println!("Starting capture...");
            if let Err(e) = fw_user::runtime::start_capture(verbose, running) {
                eprintln!("error: {e:?}");
                exit(1);
            }
        }
        _ => {
            help();
        }
    }
    Ok(())
}

fn help() {
    println!(
        "usage:
fw-ctl sniff [ -v ]
    Start firewall. Use -v for verbose mode.
"
    );
}
