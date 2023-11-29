use emv_tlv_parser::parse_tlv;

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

    match parse_tlv(data_raw) { 
        Ok(tags) => tags.iter().for_each(|tag| println!("{}", tag)), 
        Err(e) => eprintln!("Error parsing TLV: {}", e) 
    }
}

