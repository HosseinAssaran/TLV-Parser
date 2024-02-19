# TLV Parser
![Crates.io](https://img.shields.io/crates/v/emv_tlv_parser?style=flat-square)
![Crates.io](https://img.shields.io/crates/d/emv_tlv_parser?style=flat-square)
![build workflow](https://github.com/HosseinAssaran/TLV-Parser/actions/workflows/rust.yml/badge.svg)
![release workflow](https://github.com/HosseinAssaran/TLV-Parser/actions/workflows/release.yml/badge.svg)

This is a TLV (Tag-Length-Value) parser implemented in Rust and PHP. The parser can decode TLV-encoded data and represents each tag as a struct called `Tag`. The `Tag` struct has the following fields:

- `id`: Vector of bytes representing the tag identifier.
- `length`: Length of the value field.
- `value`: Vector of bytes representing the value.

Additionally, the `Tag` struct has a method `is_constructed` to check if the tag is constructed.

## Run it as a PHP Web Server With Precompiled Rust Program
1. Download the source code and go to the root directory of your source code
2. Run below command inside **PowerShell**:
   ```
    .\tlv_parser_downloader.bat
   ```
3. Run PHP Web Server using below command:
   ```
   php -S localhost:12345
   ```
4. Open your browser and go to the link below:
   ```
   localhost:12345
   ```
**Important Note:** As the PHP Web server uses a rust program to parse the message, you will need it. You can achieve this program by building release of the rust written program from the source or you can downlaod the executable file with **tlv_parser_downloader** as it mentioned above.

## How to use as library
```
    use emv_tlv_parser::parse_tlv;
    let data_raw = "6F1A840E315041592E5359532E4444463031A5088801025F2D02656E";

    match parse_tlv(data_raw.to_string()) { 
        Ok(tags) => tags.iter().for_each(|tag| println!("{}", tag)), 
        Err(e) => eprintln!("Error parsing TLV: {}", e) 
    }
```
## Run The Sample And Tests
To run the program, use the following command:
`cargo run`

To run the tests, use the following command:
`cargo test`

