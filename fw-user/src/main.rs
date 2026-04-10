mod runtime;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool};
use std::process::exit;

fn main() {
    println!("Starting firewall...");
    if let Err(e) = runtime::start_capture(true, Arc::new(AtomicBool::new(true))) {
        eprintln!("error: {e:?}");
        exit(1);
    }
}
