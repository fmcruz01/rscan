mod runtime;

use std::process::exit;

fn main() {
    println!("Starting firewall...");
    if let Err(e) = runtime::start_capture(true) {
        eprintln!("error: {e:?}");
        exit(1);
    }
}
