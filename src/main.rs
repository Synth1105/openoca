use clap::{Parser, Subcommand};
use openoca::{OCA, Key};
use std::process;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Encrypt {
        #[arg(short, long)]
        value: String,
        #[arg(short, long)]
        key:String,
    },
    Decrypt {
        #[arg(short, long)]
        value: String,
        #[arg(short, long)]
        key: String,
    },
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Command::Encrypt { value, key } => {
            let k = Key::new(key).unwrap_or_else( | _e | {eprintln!("Invalid Key"); process::exit(1)} );
            let encrypted = OCA::new(k);
            let result = encrypted.crypt(&value);
            println!("{}", result);
        },
        Command::Decrypt { value, key } => {
            let k = Key::new(key).unwrap_or_else(|_e| {eprintln!("Invalid Key");process::exit(1)});
            let decrypted = OCA::new(k);
            let result = decrypted.decrypt(&value).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1)
            });
            println!("{}", result);
        },
    };
}
