use clap::Parser;
use ed25519::signature::{Signer};

#[derive(Parser, Debug)]
struct Props{
    path: std::path::PathBuf,
}

fn main() {
    let args = Props::parse();
    let bytes = std::fs::read(&args.path);

    match bytes {
        Ok(data) => {
            println!("Bytes: {:?}", data);
        }
        Err(e) => {
            eprintln!("Error reading file: {}", e);
        }
    }
}
