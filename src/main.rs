
use emv_tlv_parser::parse_tlv;

fn hex_string_to_bytes(input: &str) -> Vec<u8> {
    match hex::decode(input) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Handle decoding error
            panic!("Invalid hex string: {}", input);
        }
    }
}

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

fn main() {
    let  data_raw = read_date_from_stdin();
    let data = hex_string_to_bytes(&data_raw); 

    match parse_tlv(&data) { 
        Ok(tags) => tags.iter().for_each(|tag| println!("{}", tag)), 
        Err(e) => eprintln!("Error parsing TLV: {}", e) 
    }
}

