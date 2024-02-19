use emv_tlv_parser::parse_tlv;
use clap::Parser;

fn read_date_from_stdin() -> String {
    use std::io::{stdin,stdout,Write};
    let mut data_raw = String::new();
    print!("Please enter a message to parse: ");
    let _=stdout().flush();
    stdin().read_line(&mut data_raw).expect("Did not enter a correct string");
    if let Some('\n')=data_raw.chars().next_back() {
        data_raw.pop();
    }
    if let Some('\r')=data_raw.chars().next_back() {
        data_raw.pop();
    }
    data_raw
}

/// Arguments
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// message to get
    #[arg(short, long, required = false)]
    message: Option<String>,
}

fn main() {
    // Get command-line arguments
    let args = Args::parse();

    // Check if message argument is provided unless read data from stdin
    let data_raw = match args.message {
        Some(m) => m,
        None => read_date_from_stdin(), 
    };

    let data_trimmed = data_raw.replace(" ", "");
    println!("Data Trimmed: {}", data_trimmed);
    match parse_tlv(data_trimmed) { 
        Ok(tags) => tags.iter().for_each(|tag| println!("{}", tag)), 
        Err(e) => eprintln!("Error parsing TLV: {}", e) 
    }
}

