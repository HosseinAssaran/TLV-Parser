# TLV Parser

This is a TLV (Tag-Length-Value) parser implemented in Rust. The parser can decode TLV-encoded data and represents each tag as a struct called `Tag`. The `Tag` struct has the following fields:

- `id`: Vector of bytes representing the tag identifier.
- `length`: Length of the value field.
- `value`: Vector of bytes representing the value.

Additionally, the `Tag` struct has a method `is_constructed` to check if the tag is constructed.

## Usage

To run the program, use the following command:
`cargo run`

To run the tests, use the following command:
`cargo test`
