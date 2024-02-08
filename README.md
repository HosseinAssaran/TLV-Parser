# TLV Parser
![Crates.io](https://img.shields.io/crates/v/emv_tlv_parser?style=flat-square)
![Crates.io](https://img.shields.io/crates/d/emv_tlv_parser?style=flat-square)
![build workflow](https://github.com/HosseinAssaran/TLV-Parser/actions/workflows/rust.yml/badge.svg)

This is a TLV (Tag-Length-Value) parser implemented in Rust. The parser can decode TLV-encoded data and represents each tag as a struct called `Tag`. The `Tag` struct has the following fields:

- `id`: Vector of bytes representing the tag identifier.
- `length`: Length of the value field.
- `value`: Vector of bytes representing the value.

Additionally, the `Tag` struct has a method `is_constructed` to check if the tag is constructed.

## How to use

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
