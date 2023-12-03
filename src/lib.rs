//! # EMV TLV Parser
//! 
//! This library is collection of utilities to decode a tlv message.

use std::fmt;

#[derive(Debug, Clone)]
pub struct Tag {
    pub id: Vec<u8>,
    pub length: usize,
    pub value: Vec<u8>,
    pub nest_level: usize,
}

impl Tag {
    fn is_constructed(&self) -> bool {
        // Check if the least significant bit of the first byte of the tag is set
        (self.id[0] & 0x20) == 0x20
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex: Vec<String> = self.id.iter().map(|byte| format!("{:02X}", byte)).collect();
        let value_hex: Vec<String> = self.value.iter().map(|byte| format!("{:02X}", byte)).collect();
        write!(f,"{}", std::iter::repeat('\t').take(self.nest_level).collect::<String>())?;
        write!(
            f,
            "\ttag_id: {:5} | length: {:3} | value: {}",
            id_hex.join(" "),
            self.length,
            value_hex.join(" ")
        )
    }
}

/// Parse tlv messsages from vector
/// 
/// # Examples 
/// 
/// ```
///     use emv_tlv_parser::parse_tlv_vec;
///     let data = vec![
///     0x6F, 0x1A, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44,
///     0x44, 0x46, 0x30, 0x31, 0xA5, 0x08, 0x88, 0x01, 0x02, 0x5F, 0x2D, 0x02, 0x65, 0x6E,
///     ];
///     
///     match parse_tlv_vec(&data) {
///         Ok(tags) => {
///             assert_eq!(tags.len(), 5); // Assuming three tags in the provided data
///             // Add more assertions based on your expected results
///         }
///         Err(e) => panic!("Error parsing TLV: {}", e),
///     }
///``` 
pub fn parse_tlv_vec(data: &[u8]) -> Result<Vec<Tag>, &'static str> {
    let mut tags = Vec::new();
    let mut index = 0;

    while index < data.len() {
        let mut tag_id = Vec::new();
        tag_id.push(data[index]);
        index += 1;

        if index >= data.len() {
            return Err("Unexpected end of data");
        }

        if tag_id[0] & 0x1F == 0x1F {
            tag_id.push(data[index]);
            index += 1;
        }

        if index >= data.len() {
            return Err("Unexpected end of data");
        }

        let length_byte = data[index];
        index += 1;

        let length = if length_byte & 0x80 == 0 {
            length_byte as usize
        } else {
            let length_bytes_count = length_byte & 0x7F;
            if index + length_bytes_count as usize > data.len() {
                return Err("Unexpected end of data");
            }

            let mut length_value = 0;
            for _ in 0..length_bytes_count {
                length_value <<= 8;
                length_value |= data[index] as usize;
                index += 1;
            }

            length_value
        };

        if index + length > data.len() {
            return Err("Unexpected end of data");
        }

        let value = data[index..(index + length)].to_vec();
        index += length;

        let tag = Tag { id: tag_id.clone(), length, value, nest_level: 0 };
        tags.push(tag.clone());

        if tag.is_constructed()  {
            // Recursively parse the TLV-encoded object within the value
            let nested_tags = parse_tlv_vec(&tag.value)?;
            
            //Do something with the parsed nested_tags if needed
            for mut nested_tag in nested_tags {
                nested_tag.nest_level += 1;
                tags.push(nested_tag);
            }
        }

    }

    Ok(tags)
}

/// Parse tlv messsages from hex string
/// 
/// # Examples 
/// 
/// ```
///     use emv_tlv_parser::parse_tlv;
///     let data_raw = "6F1A840E315041592E5359532E4444463031A5088801025F2D02656E";
///     
///     match parse_tlv(data_raw.to_string()) {
///         Ok(tags) => {
///             assert_eq!(tags.len(), 5); // Assuming three tags in the provided data
///             // Add more assertions based on your expected results
///         }
///         Err(e) => panic!("Error parsing TLV: {}", e),
///     }
///``` 
pub fn parse_tlv(data_raw: String) -> Result<Vec<Tag>, &'static str>
{
    let data = hex::decode(data_raw).expect("Invalid hex string:");
    parse_tlv_vec(&data)
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nested_parse_tlv() {
        let data = vec![
            0x6F, 0x1A, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44,
            0x44, 0x46, 0x30, 0x31, 0xA5, 0x08, 0x88, 0x01, 0x02, 0x5F, 0x2D, 0x02, 0x65, 0x6E,
        ];

        match parse_tlv_vec(&data) {
            Ok(tags) => {
                assert_eq!(tags.len(), 5); // Assuming three tags in the provided data
                assert_eq!(tags[0].id, vec![0x6F]);
                assert_eq!(tags[1].id, vec![0x84]);
                assert_eq!(tags[2].id, vec![0xA5]);
                assert_eq!(tags[3].id, vec![0x88]);
                assert_eq!(tags[4].id, vec![0x5f, 0x2D]);

                // Add more assertions based on your expected results
            }
            Err(e) => panic!("Error parsing TLV: {}", e),
        }
    }

    #[test]
    fn test_parse_tlv_data() {
        let data = vec![
            0x5F, 0x2A, 0x02, 0x03, 0x64, 0x82, 0x02, 0x08, 0x00, 0x95, 0x05, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x9A, 0x03, 0x23, 0x11, 0x25, 0x9C, 0x01, 0x00, 0x9F, 0x02, 0x06, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x9F, 0x10, 0x20, 0x0F, 0xA5, 0x00, 0xA0, 0x83, 0x09, 0xC0, 0x00, 0xF4,
            0x56, 0xB8, 0x28, 0x60, 0x06, 0x4C, 0x95, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9F, 0x1A, 0x02, 0x03, 0x64, 0x9F, 0x26,
            0x08, 0xD5, 0x47, 0x07, 0x94, 0x27, 0xA4, 0x20, 0xB7, 0x9F, 0x27, 0x01, 0x80, 0x9F, 0x36,
            0x02, 0x00, 0xFC, 0x9F, 0x37, 0x04, 0x20, 0x47, 0x5A, 0x30, 0x9F, 0x6E, 0x04, 0x10, 0x30,
            0x00, 0x00, 0x9F, 0x08, 0x02, 0x00, 0x01,
        ];

        match parse_tlv_vec(&data) {
            Ok(tags) => {
                assert_eq!(tags.len(), 14); // Assuming 15 tags in the provided data
                assert_eq!(tags[0].id, vec![0x5F, 0x2A]);
                assert_eq!(tags[1].id, vec![0x82]);
                assert_eq!(tags[2].id, vec![0x95]);
                assert_eq!(tags[3].id, vec![0x9A]);
                assert_eq!(tags[4].id, vec![0x9C]);
                assert_eq!(tags[5].id, vec![0x9F, 0x02]);
                assert_eq!(tags[6].id, vec![0x9F, 0x10]);
                assert_eq!(tags[7].id, vec![0x9F, 0x1A]);
                assert_eq!(tags[8].id, vec![0x9F, 0x26]);
                assert_eq!(tags[9].id, vec![0x9F, 0x27]);
                assert_eq!(tags[10].id, vec![0x9F, 0x36]);
                assert_eq!(tags[11].id, vec![0x9F, 0x37]);
                assert_eq!(tags[12].id, vec![0x9F, 0x6E]);
                assert_eq!(tags[13].id, vec![0x9F, 0x08]);
                // Add assertions for other fields if needed
            }
            Err(e) => panic!("Error parsing TLV: {}", e),
        }
    }

    #[test]
    fn test_parse_tlv_data_raw() {
        let data_raw = "6F1A840E315041592E5359532E4444463031A5088801025F2D02656E";

        match parse_tlv(data_raw.to_string()) {            Ok(tags) => {
                assert_eq!(tags.len(), 5); // Assuming three tags in the provided data
                assert_eq!(tags[0].id, vec![0x6F]);
                assert_eq!(tags[1].id, vec![0x84]);
                assert_eq!(tags[2].id, vec![0xA5]);
                assert_eq!(tags[3].id, vec![0x88]);
                assert_eq!(tags[4].id, vec![0x5f, 0x2D]);

                // Add more assertions based on your expected results
            }
            Err(e) => panic!("Error parsing TLV: {}", e),
        }
    }
    // Add more tests as needed
}