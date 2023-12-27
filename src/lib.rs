//! # EMV TLV Parser
//! 
//! This library is collection of utilities to decode a tlv message.

use std::fmt;

#[derive(Debug, Clone)]
pub struct Tag {
    pub id: Vec<u8>,
    pub name: &'static str,
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
        write!(f,"{}", std::iter::repeat("  ").take(self.nest_level).collect::<String>())?;
        write!(
            f,
            "  Id: {:5} | {} | Len: {:3} | Val: {}",
            id_hex.join(" "),
            self.name,
            self.length,
            value_hex.join(" ")
        )
    }
}

pub struct TagDefinition {
    pub id: &'static [u8],
    pub name: &'static str,
}

impl TagDefinition {
    pub const fn new(id: &'static [u8], name: &'static str) -> TagDefinition {
        TagDefinition {
            id: id,
            name,
        }
    }
}

fn get_name_by_id(id: Vec<u8>) -> &'static str {
    TAGS_LIST
        .iter()
        .find(|&def| def.id == id)
        .map_or("unknown", |def| def.name)
}

static TAGS_LIST: [TagDefinition; 120] = [
    TagDefinition::new(&[0x9F,0x01], "Acquirer Identifier"),
    TagDefinition::new(&[0x9F,0x40], "Additional Terminal Capabilities"),
    TagDefinition::new(&[0x81], "Amount, Authorised (Binary)"),
    TagDefinition::new(&[0x9F,0x02], "Amount, Authorised (Numeric)"),
    TagDefinition::new(&[0x9F,0x04], "Amount, Other (Binary)"),
    TagDefinition::new(&[0x9F,0x03], "Amount, Other (Numeric)"),
    TagDefinition::new(&[0x9F,0x3A], "Amount, Reference Currency"),
    TagDefinition::new(&[0x9F,0x26], "Application Cryptogram"),
    TagDefinition::new(&[0x9F,0x42], "Application Currency Code"),
    TagDefinition::new(&[0x9F,0x44], "Application Currency Exponent"),
    TagDefinition::new(&[0x9F,0x05], "Application Discretionary Data"),
    TagDefinition::new(&[0x5F,0x25], "Application Effective Date"),
    TagDefinition::new(&[0x5F,0x24], "Application Expiration Date"),
    TagDefinition::new(&[0x94], "Application File Locator (AFL)"),
    TagDefinition::new(&[0x4F], "Application Identifier (AID) - card"),
    TagDefinition::new(&[0x9F,0x06], "Application Identifier (AID) - terminal"),
    TagDefinition::new(&[0x82], "Application Interchange Profile"),
    TagDefinition::new(&[0x50], "Application Label"),
    TagDefinition::new(&[0x9F,0x12], "Application Preferred Name"),
    TagDefinition::new(&[0x5A], "Application Primary Account Number (PAN)"),
    TagDefinition::new(&[0x5F,0x34], "Application Primary Account Number (PAN) Sequence Number"),
    TagDefinition::new(&[0x87], "Application Priority Indicator"),
    TagDefinition::new(&[0x9F,0x3B], "Application Reference Currency"),
    TagDefinition::new(&[0x9F,0x43], "Application Reference Currency Exponent"),
    TagDefinition::new(&[0x61], "Application Template"),
    TagDefinition::new(&[0x9F,0x36], "Application Transaction Counter (ATC)"),
    TagDefinition::new(&[0x9F,0x07], "Application Usage Control"),
    TagDefinition::new(&[0x9F,0x08], "Application Version Number"),
    TagDefinition::new(&[0x9F,0x09], "Application Version Number"),
    TagDefinition::new(&[0x89], "Authorisation Code"),
    TagDefinition::new(&[0x8A], "Authorisation Response Code"),
    TagDefinition::new(&[0x5F,0x54], "Bank Identifier Code (BIC)"),
    TagDefinition::new(&[0x8C], "Card Risk Management Data Object List 1 (CDOL1)"),
    TagDefinition::new(&[0x8D], "Card Risk Management Data Object List 2 (CDOL2)"),
    TagDefinition::new(&[0x5F,0x20], "Cardholder Name"),
    TagDefinition::new(&[0x9F,0x0B], "Cardholder Name Extended"),
    TagDefinition::new(&[0x8E], "Cardholder Verification Method (CVM) List"),
    TagDefinition::new(&[0x9F,0x34], "Cardholder Verification Method (CVM) Results"),
    TagDefinition::new(&[0x8F], "Certification Authority Public Key Index"),
    TagDefinition::new(&[0x9F,0x22], "Certification Authority Public Key Index"),
    TagDefinition::new(&[0x83], "Command Template"),
    TagDefinition::new(&[0x9F,0x27], "Cryptogram Information Data"),
    TagDefinition::new(&[0x9F,0x45], "Data Authentication Code"),
    TagDefinition::new(&[0x84], "Dedicated File (DF) Name"),
    TagDefinition::new(&[0x9D], "Directory Definition File (DDF) Name"),
    TagDefinition::new(&[0x73], "Directory Discretionary Template"),
    TagDefinition::new(&[0x9F,0x49], "Dynamic Data Authentication Data Object List (DDOL)"),
    TagDefinition::new(&[0x70], "EMV Proprietary Template"),
    TagDefinition::new(&[0xBF,0x0C], "File Control Information (FCI) Issuer Discretionary Data"),
    TagDefinition::new(&[0xA5], "File Control Information (FCI) Proprietary Template"),
    TagDefinition::new(&[0x6F], "File Control Information (FCI) Template"),
    TagDefinition::new(&[0x9F,0x4C], "ICC Dynamic Number"),
    TagDefinition::new(&[0x9F,0x2D], "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate"),
    TagDefinition::new(&[0x9F,0x2E], "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent"),
    TagDefinition::new(&[0x9F,0x2F], "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder"),
    TagDefinition::new(&[0x9F,0x46], "Integrated Circuit Card (ICC) Public Key Certificate"),
    TagDefinition::new(&[0x9F,0x47], "Integrated Circuit Card (ICC) Public Key Exponent"),
    TagDefinition::new(&[0x9F,0x48], "Integrated Circuit Card (ICC) Public Key Remainder"),
    TagDefinition::new(&[0x9F,0x1E], "Interface Device (IFD) Serial Number"),
    TagDefinition::new(&[0x5F,0x53], "International Bank Account Number (IBAN)"),
    TagDefinition::new(&[0x9F,0x0D], "Issuer Action Code - Default"),
    TagDefinition::new(&[0x9F,0x0E], "Issuer Action Code - Denial"),
    TagDefinition::new(&[0x9F,0x0F], "Issuer Action Code - Online"),
    TagDefinition::new(&[0x9F,0x10], "Issuer Application Data"),
    TagDefinition::new(&[0x91], "Issuer Authentication Data"),
    TagDefinition::new(&[0x9F,0x11], "Issuer Code Table Index"),
    TagDefinition::new(&[0x5F,0x28], "Issuer Country Code"),
    TagDefinition::new(&[0x5F,0x55], "Issuer Country Code (alpha2 format)"),
    TagDefinition::new(&[0x5F,0x56], "Issuer Country Code (alpha3 format)"),
    TagDefinition::new(&[0x42], "Issuer Identification Number (IIN)"),
    TagDefinition::new(&[0x90], "Issuer Public Key Certificate"),
    TagDefinition::new(&[0x9F,0x32], "Issuer Public Key Exponent"),
    TagDefinition::new(&[0x92], "Issuer Public Key Remainder"),
    TagDefinition::new(&[0x86], "Issuer Script Command"),
    TagDefinition::new(&[0x9F,0x18], "Issuer Script Identifier"),
    TagDefinition::new(&[0x71], "Issuer Script Template 1"),
    TagDefinition::new(&[0x72], "Issuer Script Template 2"),
    TagDefinition::new(&[0x5F,0x50], "Issuer URL"),
    TagDefinition::new(&[0x5F,0x2D], "Language Preference"),
    TagDefinition::new(&[0x9F,0x13], "Last Online Application Transaction Counter (ATC) Register"),
    TagDefinition::new(&[0x9F,0x4D], "Log Entry"),
    TagDefinition::new(&[0x9F,0x4F], "Log Format"),
    TagDefinition::new(&[0x9F,0x14], "Lower Consecutive Offline Limit"),
    TagDefinition::new(&[0x9F,0x15], "Merchant Category Code"),
    TagDefinition::new(&[0x9F,0x16], "Merchant Identifier"),
    TagDefinition::new(&[0x9F,0x4E], "Merchant Name and Location"),
    TagDefinition::new(&[0x9F,0x17], "Personal Identification Number (PIN) Try Counter"),
    TagDefinition::new(&[0x9F,0x39], "Point-of-Service (POS) Entry Mode"),
    TagDefinition::new(&[0x9F,0x38], "Processing Options Data Object List (PDOL)"),
    TagDefinition::new(&[0x80], "Response Message Template Format 1"),
    TagDefinition::new(&[0x77], "Response Message Template Format 2"),
    TagDefinition::new(&[0x5F,0x30], "Service Code"),
    TagDefinition::new(&[0x88], "Short File Identifier (SFI)"),
    TagDefinition::new(&[0x9F,0x4B], "Signed Dynamic Application Data"),
    TagDefinition::new(&[0x93], "Signed Static Application Data"),
    TagDefinition::new(&[0x9F,0x4A], "Static Data Authentication Tag List"),
    TagDefinition::new(&[0x9F,0x33], "Terminal Capabilities"),
    TagDefinition::new(&[0x9F,0x1A], "Terminal Country Code"),
    TagDefinition::new(&[0x9F,0x1B], "Terminal Floor Limit"),
    TagDefinition::new(&[0x9F,0x1C], "Terminal Identification"),
    TagDefinition::new(&[0x9F,0x1D], "Terminal Risk Management Data"),
    TagDefinition::new(&[0x9F,0x35], "Terminal Type"),
    TagDefinition::new(&[0x95], "Terminal Verification Results"),
    TagDefinition::new(&[0x9F,0x1F], "Track 1 Discretionary Data"),
    TagDefinition::new(&[0x9F,0x20], "Track 2 Discretionary Data"),
    TagDefinition::new(&[0x57], "Track 2 Equivalent Data"),
    TagDefinition::new(&[0x98], "Transaction Certificate (TC) Hash Value"),
    TagDefinition::new(&[0x97], "Transaction Certificate Data Object List (TDOL)"),
    TagDefinition::new(&[0x5F,0x2A], "Transaction Currency Code"),
    TagDefinition::new(&[0x5F,0x36], "Transaction Currency Exponent"),
    TagDefinition::new(&[0x9A], "Transaction Date"),
    TagDefinition::new(&[0x99], "Transaction Personal Identification Number (PIN) Data"),
    TagDefinition::new(&[0x9F,0x3C], "Transaction Reference Currency Code"),
    TagDefinition::new(&[0x9F,0x3D], "Transaction Reference Currency Exponent"),
    TagDefinition::new(&[0x9F,0x41], "Transaction Sequence Counter"),
    TagDefinition::new(&[0x9B], "Transaction Status Information"),
    TagDefinition::new(&[0x9F,0x21], "Transaction Time"),
    TagDefinition::new(&[0x9C], "Transaction Type"),
    TagDefinition::new(&[0x9F,0x37], "Unpredictable Number"),
    TagDefinition::new(&[0x9F,0x23], "Upper Consecutive Offline Limit"),   
];

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

        let tag = Tag { id: tag_id.clone(), name: get_name_by_id(tag_id), length, value, nest_level: 0 };
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